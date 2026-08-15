// Read side of the prebuilt index.
//
// Mirror of etl/lookup.py -- the SQL here is the SQL there. If you change a
// query in one, change it in the other, because lookup.py is how the index gets
// exercised without launching a debugger.
//
// Everything the panel displays was rendered to HTML at build time, so nothing
// in this file parses JSON, YAML or Markdown. A lookup is an indexed SELECT and
// a string copy.

#pragma once

#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "normalize.h"

struct sqlite3;

namespace malapi {

// Schema this build understands. Written to meta.schema_version by the ETL; a
// mismatch means the index and the plugin came from different releases.
//
// v2 interned the document text into a `text` table and compressed it against a
// shared dictionary, which took the index from 115 MB to 46 MB. A v1 index has
// doc_html columns this build no longer reads, so opening one is refused rather
// than silently returning empty documentation.
constexpr const char* kExpectedSchemaVersion = "3";

struct Param {
    std::string name;
    std::string desc_html;
};

// MalAPI's malicious-use layer. Absent for most of the corpus -- only 369 of
// 44,527 APIs have one, and that scarcity is itself informative.
struct Intent {
    bool present = false;
    std::string description;

    // The spelling MalAPI wrote the entry against, which is often not the
    // spelling under the cursor: 122 entries exist only in their ANSI form while
    // a modern disassembly shows the wide one. The panel discloses the
    // difference rather than implying MalAPI documented what you selected.
    std::string documented_as;

    std::string source_url;
    std::vector<std::string> attacks;
};

struct ApiEntry {
    long long id = 0;
    std::string name;
    std::string name_norm;
    std::string dll;
    std::string header;
    std::string syntax;

    // Whose signature `syntax` actually is. Usually this row's own name, but
    // most rows have none of their own -- Microsoft generates prototypes from
    // win32metadata rather than storing them in the markdown -- so a charset
    // sibling's is borrowed. CreateProcessA's and CreateProcessW's differ
    // (LPCSTR against LPCWSTR), so the panel labels a borrowed one.
    std::string syntax_from;

    std::string doc_html;
    std::string return_html;
    std::string doc_url;
    std::string source;  // malapi | sdk-api | driver-ddi
    std::vector<Param> params;
    Intent intent;
};

// A capa combination the selected API takes part in.
//
// The panel's primary capability view. Rather than asserting a verdict about the
// binary, it shows the whole combination and marks which parts are present --
// more useful at a breakpoint, and impossible to overstate.
struct Combination {
    std::string name;
    std::string name_space;   // capa's namespace, e.g. host-interaction/process
    std::vector<std::string> attck;
    std::vector<std::string> mbc;

    std::vector<std::string> present;  // members already in the target
    std::vector<std::string> absent;   // members not seen

    // Leaves capa would test that an import table cannot answer -- strings,
    // constants, byte patterns. Zero means APIs decide the rule outright.
    int unknown_leaves = 0;

    bool high_confidence() const { return unknown_leaves == 0; }

    // Fraction of the combination already present. Drives ordering: a rule with
    // three of four members is far more interesting than one with one of nine.
    double completeness() const {
        const size_t total = present.size() + absent.size();
        return total ? static_cast<double>(present.size()) / static_cast<double>(total)
                     : 0.0;
    }
};

// One capability the target's API set satisfies.
struct Capability {
    std::string name;
    std::string name_space;
    std::string description;
    std::vector<std::string> attck;
    std::vector<std::string> mbc;

    // The rule's APIs that the target actually has. What the match rests on.
    std::vector<std::string> matched;

    int unknown_leaves = 0;
    bool high_confidence() const { return unknown_leaves == 0; }
};

// The result of matching, with the denominator attached.
//
// The counts are not decoration. A short list can mean "this sample does little"
// or "most of what capa checks is invisible to us", and those are opposite
// conclusions. Reporting capabilities without saying how many rules could not be
// evaluated invites the wrong one.
struct CapabilityReport {
    std::vector<Capability> capabilities;
    int rules_evaluated = 0;   // reportable rules APIs can decide
    int rules_invisible = 0;   // rules testing only features we cannot observe
    int partial_hidden = 0;    // matches held back by the confidence filter
    size_t api_count = 0;      // size of the API set this was matched against
};

struct SearchHit {
    std::string name;
    std::string dll;
    std::string excerpt;
};

class Index {
public:
    Index() = default;
    ~Index();

    Index(const Index&) = delete;
    Index& operator=(const Index&) = delete;

    // Opens read-only. `error` is filled on failure and is safe to show a user.
    bool open(const std::string& path, std::string& error);
    void close();
    bool is_open() const { return db_ != nullptr; }

    // Two stages, in this order: every exact spelling against api.name, then the
    // case-folded key against api.name_norm. Exact-first is what keeps
    // CreateProcessA landing on the ANSI entry directly rather than arriving
    // there via the base name.
    bool lookup(const Symbol& symbol, ApiEntry& out);

    std::vector<SearchHit> search(const std::string& query, int limit = 20);

    // Combinations `api_name` participates in, most complete first.
    //
    // `present` is the target's API set, used only to mark which members are
    // already there; pass an empty set to describe combinations in the abstract,
    // which is what the panel shows with no debuggee loaded.
    //
    // Library rules are excluded, and so are rules whose APIs are not
    // load-bearing (fires_empty) -- those are satisfied by an empty binary and
    // say nothing about a target.
    std::vector<Combination> combinations_for(const std::string& api_name,
                                              const std::set<std::string>& present,
                                              int limit = 12);

    // Every capability the API set supports, best-supported first.
    //
    // `high_confidence_only` is the difference between 19 accurate capabilities
    // for notepad.exe and 152 that include "bypass UAC" -- the permissive tier
    // fires on rules discriminated by registry strings we cannot see. It
    // defaults to the narrow tier for that reason.
    CapabilityReport capabilities(const std::set<std::string>& present,
                                  bool high_confidence_only = true);

    // meta.attribution.* joined for the About view. We redistribute CC BY 4.0
    // documentation, so this is an obligation, not a nicety.
    std::string attribution();

    const std::string& schema_version() const { return schema_version_; }
    const std::string& path() const { return path_; }

private:
    void load_params(ApiEntry& out);
    void load_syntax(ApiEntry& out);
    void load_intent(ApiEntry& out);
    std::string meta(const char* key);
    long long scalar(const char* sql);

    // Inflate one interned string. Returns empty for a NULL reference, which is
    // how the schema spells "absent".
    std::string text(long long text_id);

    sqlite3* db_ = nullptr;
    std::string path_;
    std::string schema_version_;

    // The shared deflate dictionary, read once at open. Without it every blob in
    // the index is undecodable, so it travels inside the file rather than being
    // compiled in where a version skew would corrupt output silently.
    std::string dictionary_;

    // x64dbg gives no promise about which thread a callback arrives on, and the
    // handle is shared with the menu-driven search. One connection, one lock.
    std::mutex lock_;
};

// Turn what a user typed into a valid FTS5 expression. FTS5 matches whole
// tokens, so passing input through verbatim finds nothing for "keylog" even
// though thirteen entries describe keylogging; the trailing term has to become a
// prefix query. Returns false when there is nothing searchable.
bool prepare_fts_query(const std::string& query, std::string& out);

}  // namespace malapi
