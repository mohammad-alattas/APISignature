#include "index.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <utility>

#include <unordered_map>

#include "capa_eval.h"
#include "sqlite3.h"
#include "zlib.h"

namespace malapi {
namespace {

const char* const kApiColumns =
    "id, name, name_norm, dll, header, syntax, doc_id, return_id, doc_url, source";

// Z_SOLO builds omit zlib's default allocator, so it has to come from here.
voidpf zlib_alloc(voidpf, uInt items, uInt size) {
    return std::malloc(static_cast<size_t>(items) * static_cast<size_t>(size));
}

void zlib_free(voidpf, voidpf address) {
    std::free(address);
}

// Inflate a raw-deflate blob that was compressed against `dictionary`.
//
// Raw deflate (windowBits -15) carries no header, so there is no dictionary id
// and inflate never returns Z_NEED_DICT -- the dictionary has to be installed
// immediately after init instead. `expected` is the uncompressed length the ETL
// recorded, so this allocates exactly once.
bool inflate_raw(const void* data, size_t size, const std::string& dictionary,
                 size_t expected, std::string& out) {
    z_stream stream{};
    stream.zalloc = zlib_alloc;
    stream.zfree = zlib_free;
    if (inflateInit2(&stream, -15) != Z_OK) {
        return false;
    }

    bool ok = false;
    if (dictionary.empty() ||
        inflateSetDictionary(
            &stream, reinterpret_cast<const Bytef*>(dictionary.data()),
            static_cast<uInt>(dictionary.size())) == Z_OK) {
        out.resize(expected);

        stream.next_in = static_cast<z_const Bytef*>(const_cast<void*>(data));
        stream.avail_in = static_cast<uInt>(size);
        stream.next_out = reinterpret_cast<Bytef*>(&out[0]);
        stream.avail_out = static_cast<uInt>(expected);

        const int result = inflate(&stream, Z_FINISH);
        // Z_STREAM_END with nothing left over is the only acceptable outcome: a
        // short or overlong result means the recorded size disagrees with the
        // data, and half a document is worse than none.
        ok = result == Z_STREAM_END && stream.avail_out == 0;
    }

    inflateEnd(&stream);
    if (!ok) {
        out.clear();
    }
    return ok;
}

// sqlite3_finalize is easy to miss on an early return, and a leaked statement
// holds a read transaction open for the life of the process.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        ok_ = sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) == SQLITE_OK;
    }
    ~Stmt() { sqlite3_finalize(stmt_); }

    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    bool ok() const { return ok_ && stmt_ != nullptr; }
    sqlite3_stmt* get() { return stmt_; }

    void bind(int index, const std::string& value) {
        sqlite3_bind_text(stmt_, index, value.c_str(),
                          static_cast<int>(value.size()), SQLITE_TRANSIENT);
    }
    void bind(int index, long long value) { sqlite3_bind_int64(stmt_, index, value); }

    bool step() { return sqlite3_step(stmt_) == SQLITE_ROW; }

    std::string text(int column) const {
        const auto* raw = sqlite3_column_text(stmt_, column);
        if (!raw) {
            return std::string();
        }
        return std::string(reinterpret_cast<const char*>(raw),
                           static_cast<size_t>(sqlite3_column_bytes(stmt_, column)));
    }
    long long integer(int column) const { return sqlite3_column_int64(stmt_, column); }

private:
    sqlite3_stmt* stmt_ = nullptr;
    bool ok_ = false;
};

// Text ids are 1-based, so 0 doubles as "NULL" without a separate null check.
void read_api_row(const Stmt& row, ApiEntry& out, long long& doc_id,
                  long long& return_id) {
    out.id        = row.integer(0);
    out.name      = row.text(1);
    out.name_norm = row.text(2);
    out.dll       = row.text(3);
    out.header    = row.text(4);
    out.syntax    = row.text(5);
    doc_id        = row.integer(6);
    return_id     = row.integer(7);
    out.doc_url   = row.text(8);
    out.source    = row.text(9);
}

// Pull the "id" and "text" fields out of an ATT&CK/MBC array.
//
// Deliberately not a JSON parser. The shape is fixed and written by our own ETL
// -- [{"id":"T1055.002","text":"Defense Evasion::Process Injection"}] -- so a
// scanner for the two fields we display keeps a parser out of a DLL that loads
// inside a debugger. Anything unexpected yields fewer labels, never a crash.
std::vector<std::string> extract_labels(const std::string& json) {
    std::vector<std::string> labels;
    if (json.empty()) {
        return labels;
    }

    const auto field = [&json](const char* key, size_t from, std::string& out) -> size_t {
        const std::string needle = std::string("\"") + key + "\":\"";
        const size_t start = json.find(needle, from);
        if (start == std::string::npos) {
            return std::string::npos;
        }
        size_t at = start + needle.size();
        out.clear();
        while (at < json.size() && json[at] != '"') {
            if (json[at] == '\\' && at + 1 < json.size()) {
                ++at;  // keep the escaped character verbatim
            }
            out.push_back(json[at++]);
        }
        return at;
    };

    size_t offset = 0;
    for (;;) {
        std::string id;
        const size_t after_id = field("id", offset, id);
        if (after_id == std::string::npos) {
            break;
        }
        std::string text;
        const size_t after_text = field("text", after_id, text);

        labels.push_back(text.empty() ? id : id + "  " + text);
        offset = (after_text == std::string::npos) ? after_id : after_text;
    }
    return labels;
}

bool is_token_char(char c) {
    const auto uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) != 0 || c == '_';
}

}  // namespace

Index::~Index() {
    close();
}

bool Index::open(const std::string& path, std::string& error) {
    close();

    // FULLMUTEX because callbacks and the search box can both reach this handle
    // and x64dbg documents no thread affinity for either.
    const int flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.c_str(), &db_, flags, nullptr) != SQLITE_OK) {
        error = db_ ? sqlite3_errmsg(db_) : "could not open index";
        close();
        return false;
    }

    path_ = path;
    schema_version_ = meta("schema_version");

    if (schema_version_.empty()) {
        error = "'" + path + "' is not an APISignature index (no schema_version in meta)";
        close();
        return false;
    }
    if (schema_version_ != kExpectedSchemaVersion) {
        // Refuse rather than half-work: a schema change means columns this build
        // reads may be absent or mean something else.
        error = "index schema v" + schema_version_ + ", but this build expects v" +
                kExpectedSchemaVersion + " -- rebuild the index or update the plugin";
        close();
        return false;
    }

    {
        Stmt row(db_, "SELECT data FROM text_dict WHERE id = 1");
        if (row.ok() && row.step()) {
            const auto* blob =
                static_cast<const char*>(sqlite3_column_blob(row.get(), 0));
            const auto size = static_cast<size_t>(sqlite3_column_bytes(row.get(), 0));
            if (blob && size) {
                dictionary_.assign(blob, size);
            }
        }
    }
    if (dictionary_.empty()) {
        error = "index has no compression dictionary; every document would be "
                "unreadable -- rebuild it with etl/build_index.py";
        close();
        return false;
    }

    return true;
}

void Index::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    path_.clear();
    schema_version_.clear();
    dictionary_.clear();
}

bool Index::lookup(const Symbol& symbol, ApiEntry& out) {
    if (!db_ || !symbol.resolvable()) {
        return false;
    }

    std::lock_guard<std::mutex> guard(lock_);

    // Stage 1: exact, case-preserving spellings, most specific first. Querying
    // one key at a time in order is equivalent to lookup.py's `IN (...) ORDER BY
    // CASE name` and avoids building SQL by concatenation.
    {
        const std::string sql =
            std::string("SELECT ") + kApiColumns + " FROM api WHERE name = ? LIMIT 1";
        for (const std::string& key : symbol.lookup_keys) {
            Stmt row(db_, sql.c_str());
            if (!row.ok()) {
                return false;
            }
            row.bind(1, key);
            if (row.step()) {
                long long doc_id = 0, return_id = 0;
                read_api_row(row, out, doc_id, return_id);
                out.doc_html = text(doc_id);
                out.return_html = text(return_id);
                load_params(out);
                load_syntax(out);
                load_intent(out);
                return true;
            }
        }
    }

    // Stage 2: the case-folded key. Prefer a row carrying MalAPI intent -- once
    // sdk-api contributes CreateProcessW alongside MalAPI's CreateProcessA, both
    // share a canonical key and only one of them has the write-up.
    const std::string sql = std::string("SELECT a.") + "id, a.name, a.name_norm, a.dll," +
                            " a.header, a.syntax, a.doc_html, a.return_html, a.doc_url," +
                            " a.source FROM api a" +
                            " LEFT JOIN malapi m ON m.api_id = a.id" +
                            " WHERE a.name_norm = ?" +
                            " ORDER BY (m.api_id IS NOT NULL) DESC, a.name LIMIT 1";

    Stmt row(db_, sql.c_str());
    if (!row.ok()) {
        return false;
    }
    row.bind(1, symbol.canonical_key);
    if (!row.step()) {
        return false;
    }

    long long doc_id = 0, return_id = 0;
    read_api_row(row, out, doc_id, return_id);
    out.doc_html = text(doc_id);
    out.return_html = text(return_id);
    load_params(out);
    load_syntax(out);
    load_intent(out);
    return true;
}

std::string Index::text(long long text_id) {
    if (!db_ || text_id <= 0) {
        return std::string();
    }

    Stmt row(db_, "SELECT size, data FROM text WHERE id = ?");
    if (!row.ok()) {
        return std::string();
    }
    row.bind(1, text_id);
    if (!row.step()) {
        return std::string();
    }

    const auto expected = static_cast<size_t>(row.integer(0));
    const void* blob = sqlite3_column_blob(row.get(), 1);
    const auto size = static_cast<size_t>(sqlite3_column_bytes(row.get(), 1));

    std::string out;
    inflate_raw(blob, size, dictionary_, expected, out);
    return out;
}

void Index::load_params(ApiEntry& out) {
    out.params.clear();

    std::vector<std::pair<std::string, long long>> rows;
    {
        Stmt row(db_,
                 "SELECT name, desc_id FROM api_param WHERE api_id = ? ORDER BY ord");
        if (!row.ok()) {
            return;
        }
        row.bind(1, out.id);
        while (row.step()) {
            rows.emplace_back(row.text(0), row.integer(1));
        }
    }

    // Collected first, then inflated: text() prepares its own statement, and
    // stepping a second query while this one is still open would leave both
    // live against the same connection for no reason.
    for (auto& entry : rows) {
        Param param;
        param.name = std::move(entry.first);
        param.desc_html = text(entry.second);
        out.params.push_back(std::move(param));
    }
}

void Index::load_syntax(ApiEntry& out) {
    if (!out.syntax.empty()) {
        out.syntax_from = out.name;
        return;
    }

    // Same charset-sibling join as load_intent, for the same reason: the row the
    // analyst selected is often not the row that carries the content.
    Stmt row(db_,
             "SELECT syntax, name FROM api"
             " WHERE name_norm = ? AND syntax IS NOT NULL AND syntax != ''"
             " ORDER BY (name = ?) DESC, name LIMIT 1");
    if (!row.ok()) {
        return;
    }
    row.bind(1, out.name_norm);
    row.bind(2, out.name);
    if (row.step()) {
        out.syntax = row.text(0);
        out.syntax_from = row.text(1);
    }
}

void Index::load_intent(ApiEntry& out) {
    out.intent = Intent();

    // Joined on name_norm rather than api_id deliberately. CreateProcessW has its
    // own row with Microsoft's docs, but MalAPI only ever wrote up
    // CreateProcessA; an id-keyed lookup would show the reference documentation
    // and silently drop the intent layer, which is the whole point of the tool.
    {
        Stmt row(db_,
                 "SELECT m.description, m.source_url, a.name FROM malapi m"
                 " JOIN api a ON a.id = m.api_id"
                 " WHERE a.name_norm = ?"
                 " ORDER BY (a.name = ?) DESC, a.name LIMIT 1");
        if (row.ok()) {
            row.bind(1, out.name_norm);
            row.bind(2, out.name);
            if (row.step()) {
                out.intent.present = true;
                out.intent.description = row.text(0);
                out.intent.source_url = row.text(1);
                out.intent.documented_as = row.text(2);
            }
        }
    }

    Stmt row(db_,
             "SELECT DISTINCT t.name FROM api a"
             " JOIN api_attack aa ON aa.api_id = a.id"
             " JOIN attack t ON t.id = aa.attack_id"
             " WHERE a.name_norm = ? ORDER BY t.name");
    if (!row.ok()) {
        return;
    }
    row.bind(1, out.name_norm);
    while (row.step()) {
        out.intent.attacks.push_back(row.text(0));
    }
}

std::vector<SearchHit> Index::search(const std::string& query, int limit) {
    std::vector<SearchHit> hits;
    if (!db_) {
        return hits;
    }

    std::string expression;
    if (!prepare_fts_query(query, expression)) {
        return hits;
    }

    std::lock_guard<std::mutex> guard(lock_);

    const char* sql =
        "SELECT a.name, a.dll, snippet(api_fts, 1, '', '', '\xE2\x80\xA6', 12)"
        " FROM api_fts f JOIN api a ON a.id = f.rowid"
        " WHERE api_fts MATCH ? ORDER BY rank LIMIT ?";

    for (int attempt = 0; attempt < 2; ++attempt) {
        Stmt row(db_, sql);
        if (!row.ok()) {
            return hits;
        }
        row.bind(1, expression);
        row.bind(2, static_cast<long long>(limit));

        while (row.step()) {
            SearchHit hit;
            hit.name = row.text(0);
            hit.dll = row.text(1);
            hit.excerpt = row.text(2);
            hits.push_back(std::move(hit));
        }
        if (!hits.empty() || attempt == 1) {
            return hits;
        }

        // Malformed explicit syntax: retry the whole input as a literal phrase
        // rather than reporting a query error at someone who just typed a name.
        expression.assign("\"");
        for (char c : query) {
            if (c != '"') {
                expression.push_back(c);
            }
        }
        expression.push_back('"');
    }

    return hits;
}

std::vector<Combination> Index::combinations_for(const std::string& api_name,
                                                 const std::set<std::string>& present,
                                                 int limit) {
    std::vector<Combination> results;
    if (!db_) {
        return results;
    }

    const std::string key = canonical(api_name);

    // The target's API set, canonicalized once so membership tests below compare
    // like with like -- capa_api.name_norm holds canonical keys too.
    std::set<std::string> present_norm;
    for (const std::string& name : present) {
        present_norm.insert(canonical(name));
    }

    std::lock_guard<std::mutex> guard(lock_);

    // fires_empty = 0 is the load-bearing test: a rule satisfied without any APIs
    // would be reported for every binary. 43 rules name APIs only inside
    // `optional:` blocks and would otherwise slip through a "mentions an API"
    // filter. Precomputed by the ETL; see the schema.
    std::vector<std::pair<long long, Combination>> rules;
    {
        Stmt row(db_,
                 "SELECT r.id, r.name, r.namespace, r.attck_json, r.mbc_json,"
                 "       r.unknown_leaves"
                 " FROM capa_rule r"
                 " JOIN capa_rule_api ra ON ra.rule_id = r.id"
                 " JOIN capa_api ca ON ca.id = ra.capa_api_id"
                 " WHERE ca.name_norm = ? AND r.is_lib = 0 AND r.fires_empty = 0");
        if (!row.ok()) {
            return results;
        }
        row.bind(1, key);
        while (row.step()) {
            Combination combination;
            combination.name = row.text(1);
            combination.name_space = row.text(2);
            combination.attck = extract_labels(row.text(3));
            combination.mbc = extract_labels(row.text(4));
            combination.unknown_leaves = static_cast<int>(row.integer(5));
            rules.emplace_back(row.integer(0), std::move(combination));
        }
    }

    for (auto& entry : rules) {
        Stmt member(db_,
                    "SELECT ca.name_norm FROM capa_rule_api ra"
                    " JOIN capa_api ca ON ca.id = ra.capa_api_id"
                    " WHERE ra.rule_id = ? ORDER BY ca.name_norm");
        if (!member.ok()) {
            continue;
        }
        member.bind(1, entry.first);
        while (member.step()) {
            const std::string api = member.text(0);
            // The selected API counts as present by definition -- it is what the
            // analyst is looking at, whether or not a target is loaded.
            if (api == key || present_norm.count(api)) {
                entry.second.present.push_back(api);
            } else {
                entry.second.absent.push_back(api);
            }
        }
        results.push_back(std::move(entry.second));
    }

    std::sort(results.begin(), results.end(),
              [](const Combination& a, const Combination& b) {
                  if (a.completeness() != b.completeness()) {
                      return a.completeness() > b.completeness();
                  }
                  if (a.absent.size() != b.absent.size()) {
                      return a.absent.size() < b.absent.size();
                  }
                  return a.name < b.name;
              });

    if (limit > 0 && results.size() > static_cast<size_t>(limit)) {
        results.resize(static_cast<size_t>(limit));
    }
    return results;
}

CapabilityReport Index::capabilities(const std::set<std::string>& present,
                                     bool high_confidence_only) {
    CapabilityReport report;
    report.api_count = present.size();
    if (!db_) {
        return report;
    }

    // capa_api.name_norm holds canonical keys, so the caller's names have to be
    // folded the same way before they can be compared. Doing it here rather than
    // trusting callers: the plugin already passes canonical names, but a raw set
    // would silently match nothing, which reads as "this sample is clean".
    std::set<std::string> present_norm;
    for (const std::string& name : present) {
        present_norm.insert(canonical(name));
    }

    std::lock_guard<std::mutex> guard(lock_);

    // capa_api is a few thousand rows, so one scan beats building an IN clause
    // with a thousand bound parameters -- and it keeps the id map around for
    // naming the matched APIs afterwards.
    std::unordered_set<uint32_t> present_ids;
    std::unordered_map<uint32_t, std::string> id_to_name;
    {
        Stmt row(db_, "SELECT id, name_norm FROM capa_api");
        if (!row.ok()) {
            return report;
        }
        while (row.step()) {
            const auto id = static_cast<uint32_t>(row.integer(0));
            std::string name = row.text(1);
            if (present_norm.count(name)) {
                present_ids.insert(id);
            }
            id_to_name.emplace(id, std::move(name));
        }
    }

    report.rules_invisible = static_cast<int>(scalar(
        "SELECT COUNT(*) FROM capa_rule WHERE is_lib = 0 AND evidence = 'no-api'"));

    // Every reportable rule is evaluated, not only those naming a present API.
    // A rule containing `not:` can be satisfied by an API's *absence*, so
    // pre-filtering on the reverse index would silently drop it.
    //
    // fires_empty = 0 excludes rules already true with no APIs at all; those
    // would match every binary and say nothing about this one.
    struct Matched {
        long long id;
        Capability capability;
    };
    std::vector<Matched> matches;
    {
        Stmt row(db_,
                 "SELECT id, name, namespace, description, attck_json, mbc_json,"
                 "       program, unknown_leaves"
                 " FROM capa_rule WHERE is_lib = 0 AND fires_empty = 0");
        if (!row.ok()) {
            return report;
        }
        while (row.step()) {
            ++report.rules_evaluated;

            const auto* program =
                static_cast<const uint8_t*>(sqlite3_column_blob(row.get(), 6));
            const auto size = static_cast<size_t>(sqlite3_column_bytes(row.get(), 6));

            // Unknowns are treated as satisfied: we cannot check them, and a
            // rule with none is unaffected either way. The unknown count is what
            // separates the tiers, not a second evaluation.
            if (!capa_evaluate(program, size, present_ids, true)) {
                continue;
            }

            const int unknown = static_cast<int>(row.integer(7));
            if (high_confidence_only && unknown != 0) {
                ++report.partial_hidden;
                continue;
            }

            Capability capability;
            capability.name = row.text(1);
            capability.name_space = row.text(2);
            capability.description = row.text(3);
            capability.attck = extract_labels(row.text(4));
            capability.mbc = extract_labels(row.text(5));
            capability.unknown_leaves = unknown;
            matches.push_back({row.integer(0), std::move(capability)});
        }
    }

    for (Matched& match : matches) {
        Stmt member(db_,
                    "SELECT capa_api_id FROM capa_rule_api WHERE rule_id = ?");
        if (member.ok()) {
            member.bind(1, match.id);
            while (member.step()) {
                const auto id = static_cast<uint32_t>(member.integer(0));
                if (present_ids.count(id)) {
                    match.capability.matched.push_back(id_to_name[id]);
                }
            }
        }
        std::sort(match.capability.matched.begin(), match.capability.matched.end());
        report.capabilities.push_back(std::move(match.capability));
    }

    // Most evidence first; a capability resting on six present APIs is a firmer
    // claim than one resting on two.
    std::sort(report.capabilities.begin(), report.capabilities.end(),
              [](const Capability& a, const Capability& b) {
                  if (a.high_confidence() != b.high_confidence()) {
                      return a.high_confidence();
                  }
                  if (a.matched.size() != b.matched.size()) {
                      return a.matched.size() > b.matched.size();
                  }
                  return a.name < b.name;
              });

    return report;
}

long long Index::scalar(const char* sql) {
    Stmt row(db_, sql);
    return (row.ok() && row.step()) ? row.integer(0) : 0;
}

std::string Index::meta(const char* key) {
    if (!db_) {
        return std::string();
    }
    Stmt row(db_, "SELECT value FROM meta WHERE key = ?");
    if (!row.ok()) {
        return std::string();
    }
    row.bind(1, std::string(key));
    return row.step() ? row.text(0) : std::string();
}

std::string Index::attribution() {
    if (!db_) {
        return std::string();
    }
    std::lock_guard<std::mutex> guard(lock_);

    Stmt row(db_,
             "SELECT value FROM meta WHERE key LIKE 'attribution.%' ORDER BY key");
    if (!row.ok()) {
        return std::string();
    }

    std::string out;
    while (row.step()) {
        if (!out.empty()) {
            out += "\n\n";
        }
        out += row.text(0);
    }
    return out;
}

bool prepare_fts_query(const std::string& query, std::string& out) {
    const auto first = query.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return false;
    }
    const auto last = query.find_last_not_of(" \t\r\n");
    const std::string trimmed = query.substr(first, last - first + 1);

    // Explicit FTS5 syntax passes through untouched, so phrase and boolean
    // queries keep working for anyone who knows them.
    if (trimmed.find_first_of("\"*():") != std::string::npos) {
        out = trimmed;
        return true;
    }

    std::vector<std::string> tokens;
    for (size_t i = 0; i < trimmed.size();) {
        if (!is_token_char(trimmed[i])) {
            ++i;
            continue;
        }
        const size_t start = i;
        while (i < trimmed.size() && is_token_char(trimmed[i])) {
            ++i;
        }
        tokens.push_back(trimmed.substr(start, i - start));
    }
    if (tokens.empty()) {
        return false;
    }

    for (const std::string& token : tokens) {
        if (token == "AND" || token == "OR" || token == "NOT" || token == "NEAR") {
            out = trimmed;
            return true;
        }
    }

    // Quote every token to neutralise FTS5 metacharacters, then make the last a
    // prefix so partial words match as the user types.
    out.clear();
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i) {
            out += ' ';
        }
        out += '"';
        out += tokens[i];
        out += '"';
        if (i + 1 == tokens.size()) {
            out += '*';
        }
    }
    return true;
}

}  // namespace malapi

