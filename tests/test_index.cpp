// Asserts the C++ index reader against the real dist/apisignature.db.
//
// src/index.cpp and etl/lookup.py run the same SQL against the same file, and
// this test pins the cases where that is easy to get subtly wrong -- charset
// folding, Nt/Zw equivalence, case-folded Winsock names, and the join that
// carries MalAPI's intent across spellings. Each expectation below was taken
// from etl/lookup.py's output, so a disagreement means the two implementations
// have drifted.
//
// Skips rather than fails when the index is absent: the index is a 109 MB build
// artifact and is not in the repository.

#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

#include "index.h"
#include "normalize.h"
#include "render.h"

namespace {

int g_failures = 0;

void fail(const std::string& label, const std::string& expected,
          const std::string& actual) {
    std::printf("  FAIL %s\n       expected: %s\n       actual:   %s\n",
                label.c_str(), expected.c_str(), actual.c_str());
    ++g_failures;
}

void expect_eq(const std::string& label, const std::string& expected,
               const std::string& actual) {
    if (expected != actual) {
        fail(label, "\"" + expected + "\"", "\"" + actual + "\"");
    }
}

void expect_true(const std::string& label, bool value) {
    if (!value) {
        fail(label, "true", "false");
    }
}

bool contains(const std::vector<std::string>& values, const std::string& wanted) {
    for (const std::string& value : values) {
        if (value == wanted) {
            return true;
        }
    }
    return false;
}

bool lookup(malapi::Index& index, const char* raw, malapi::ApiEntry& out) {
    return index.lookup(malapi::parse_symbol(raw), out);
}

void check_charset_folding(malapi::Index& index) {
    std::printf("charset folding\n");

    // MalAPI only ever wrote up CreateProcessA, but a modern disassembly shows
    // the wide spelling. Microsoft's W page must resolve AND still carry the
    // intent -- an api_id-keyed join would drop it silently.
    malapi::ApiEntry entry;
    if (!lookup(index, "kernel32.CreateProcessW", entry)) {
        fail("lookup kernel32.CreateProcessW", "resolved", "no row");
        return;
    }

    expect_eq("CreateProcessW.name", "CreateProcessW", entry.name);
    expect_eq("CreateProcessW.dll", "kernel32", entry.dll);
    expect_true("CreateProcessW has MalAPI intent", entry.intent.present);
    expect_eq("CreateProcessW documented as", "CreateProcessA",
              entry.intent.documented_as);
    expect_true("CreateProcessW tagged Injection",
                contains(entry.intent.attacks, "Injection"));
    expect_true("CreateProcessW has parameters", !entry.params.empty());

    // Microsoft stores no prototype for CreateProcessW in the markdown, so the
    // signature is borrowed from the ANSI sibling and must be labelled as such.
    expect_true("CreateProcessW has syntax", !entry.syntax.empty());
    expect_eq("CreateProcessW syntax borrowed from", "CreateProcessA",
              entry.syntax_from);

    // The sdk-api merge exists to repair MalAPI's truncated scrape. If an
    // ellipsis survives here, that merge regressed.
    for (const malapi::Param& param : entry.params) {
        const std::string& text = param.desc_html;
        if (text.size() >= 3 && text.compare(text.size() - 3, 3, "\xE2\x80\xA6") == 0) {
            fail("parameter " + param.name + " is truncated", "full text",
                 "ends with an ellipsis");
        }
    }

    // The panel must disclose that the write-up was authored against a different
    // spelling rather than implying MalAPI documented what is on screen.
    const std::string html = malapi::render_entry(entry, {}, false);
    expect_true("panel discloses the documented spelling",
                html.find("MalAPI documents this as CreateProcessA") != std::string::npos);
    expect_true("panel labels the borrowed signature",
                html.find("signature shown is CreateProcessA's") != std::string::npos);
}

void check_case_folding(malapi::Index& index) {
    std::printf("case folding\n");

    // MalAPI title-cases the Winsock family; the real exports are lowercase.
    // Before this was fixed the entire Internet attack category was unreachable.
    malapi::ApiEntry entry;
    if (!lookup(index, "ws2_32.socket", entry)) {
        fail("lookup ws2_32.socket", "resolved", "no row");
        return;
    }

    expect_eq("socket.name", "socket", entry.name);
    expect_true("socket has MalAPI intent", entry.intent.present);
    expect_eq("socket documented as", "Socket", entry.intent.documented_as);
    expect_true("socket tagged Internet", contains(entry.intent.attacks, "Internet"));
}

void check_native_and_decoration(malapi::Index& index) {
    std::printf("native aliases and decoration\n");

    // ntdll exports NtX and ZwX at one address; MalAPI only uses the Nt form.
    malapi::ApiEntry zw;
    if (lookup(index, "ZwOpenProcess", zw)) {
        expect_eq("ZwOpenProcess.name", "ZwOpenProcess", zw.name);
        expect_true("ZwOpenProcess has MalAPI intent", zw.intent.present);
        expect_eq("ZwOpenProcess documented as", "NtOpenProcess",
                  zw.intent.documented_as);
    } else {
        fail("lookup ZwOpenProcess", "resolved", "no row");
    }

    // Import thunks are what actually appear on an IAT call site.
    malapi::ApiEntry thunk;
    if (lookup(index, "__imp_VirtualAllocEx", thunk)) {
        expect_eq("__imp_VirtualAllocEx.name", "VirtualAllocEx", thunk.name);
        expect_true("VirtualAllocEx has MalAPI intent", thunk.intent.present);
        expect_true("VirtualAllocEx tagged Injection",
                    contains(thunk.intent.attacks, "Injection"));
    } else {
        fail("lookup __imp_VirtualAllocEx", "resolved", "no row");
    }

    malapi::ApiEntry missing;
    expect_true("an invented name resolves to nothing",
                !lookup(index, "kernel32.ThisApiDoesNotExist", missing));
}

void check_search(malapi::Index& index) {
    std::printf("search\n");

    // FTS5 matches whole tokens, so "keylog" finds nothing unless the trailing
    // term is turned into a prefix query.
    const std::vector<malapi::SearchHit> hits = index.search("keylog");
    expect_true("partial word 'keylog' matches", !hits.empty());

    expect_true("empty query returns nothing", index.search("   ").empty());

    // Malformed FTS5 syntax must degrade to a literal phrase, not surface an
    // error at someone who typed a stray bracket.
    index.search("process (injection");
}

void check_combinations(malapi::Index& index) {
    std::printf("capa combinations\n");

    // With no target loaded, only the selected API counts as present.
    const auto abstract = index.combinations_for("VirtualAllocEx", {});
    expect_true("VirtualAllocEx participates in combinations", !abstract.empty());

    // The classic injection chain. Given the rest of it, a rule naming these
    // should come back complete and rank first.
    const std::set<std::string> injection = {
        "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "GetProcAddress", "LoadLibraryA",
    };
    const auto matched = index.combinations_for("VirtualAllocEx", injection);
    expect_true("injection chain yields combinations", !matched.empty());

    if (!matched.empty()) {
        // Sorted most-complete first, so the head must be at least as complete
        // as anything after it -- that ordering is what makes the view usable.
        for (size_t i = 1; i < matched.size(); ++i) {
            if (matched[i].completeness() > matched[0].completeness()) {
                fail("combinations are ordered by completeness", "descending",
                     "out of order");
                break;
            }
        }
        expect_true("the best match is more complete with the chain present",
                    matched[0].completeness() >= abstract[0].completeness());

        // Every member is either present or absent, never dropped.
        for (const malapi::Combination& c : matched) {
            if (c.present.empty()) {
                fail("combination " + c.name, "at least one present member",
                     "none -- the selected API should always count");
            }
        }
    }

    // A rule whose APIs are not load-bearing would match anything; the ETL marks
    // those fires_empty and the query excludes them.
    const auto nothing = index.combinations_for("ThisApiDoesNotExist", {});
    expect_true("an unknown API yields no combinations", nothing.empty());

    // The three sources must stay in this order and stay fenced off from each
    // other: what malware does with the call, then the vendor's reference, then
    // the community's combination rules. Reading them as one wall of text loses
    // track of which claim came from where.
    malapi::ApiEntry entry;
    if (lookup(index, "kernel32.VirtualAllocEx", entry)) {
        const auto rules = index.combinations_for(entry.name, {});
        const std::string html = malapi::render_entry(entry, rules, false);

        const size_t malapi_at = html.find("MALICIOUS USE");
        const size_t microsoft_at = html.find("DOCUMENTATION");
        const size_t capa_at = html.find("API COMBINATIONS");

        expect_true("the MalAPI group is present", malapi_at != std::string::npos);
        expect_true("the Microsoft group is present", microsoft_at != std::string::npos);
        expect_true("the capa group is present", capa_at != std::string::npos);
        expect_true("MalAPI comes before Microsoft", malapi_at < microsoft_at);
        expect_true("Microsoft comes before capa", microsoft_at < capa_at);

        // Each group names where it came from, which is also how the CC BY 4.0
        // attribution reaches the reader.
        expect_true("the groups name their sources",
                    html.find("malapi.io") != std::string::npos &&
                        html.find("CC BY 4.0") != std::string::npos &&
                        html.find("capa-rules") != std::string::npos);
    } else {
        fail("lookup VirtualAllocEx for layout", "resolved", "no row");
    }
}

void check_capabilities(malapi::Index& index) {
    std::printf("whole-target capabilities\n");

    const std::set<std::string> injection = {
        "OpenProcess",       "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "GetProcAddress", "LoadLibraryA",
        "CloseHandle",       "Sleep",
    };
    const malapi::CapabilityReport report = index.capabilities(injection);

    expect_true("the injection chain yields capabilities",
                !report.capabilities.empty());
    expect_true("rules were actually evaluated", report.rules_evaluated > 0);
    expect_true("the invisible-rule denominator is reported",
                report.rules_invisible > 0);

    for (const malapi::Capability& capability : report.capabilities) {
        // Every reported capability must rest on APIs we actually have,
        // otherwise it is not evidence about this target.
        if (capability.matched.empty()) {
            fail("capability " + capability.name, "at least one matched API",
                 "none");
        }
        if (!capability.high_confidence()) {
            fail("default tier is high-confidence only", "no unknown leaves",
                 std::to_string(capability.unknown_leaves));
        }
    }
    for (size_t i = 0; i < report.capabilities.size() && i < 8; ++i) {
        std::printf("       - %s (%zu APIs)\n", report.capabilities[i].name.c_str(),
                    report.capabilities[i].matched.size());
    }

    // The measurement that drove the whole confidence model: a benign-looking
    // set must not produce alarming claims.
    const std::set<std::string> benign = {
        "GetCommandLineA", "TerminateProcess", "CloseHandle", "Sleep",
    };
    const malapi::CapabilityReport quiet = index.capabilities(benign);
    for (const malapi::Capability& capability : quiet.capabilities) {
        if (capability.name.find("inject") != std::string::npos) {
            fail("benign set stays quiet", "no injection capability",
                 capability.name);
        }
    }

    // The permissive tier is what reports "bypass UAC" for notepad.exe. It must
    // be strictly larger, and must not be the default.
    const malapi::CapabilityReport permissive = index.capabilities(injection, false);
    expect_true("the permissive tier reports at least as much",
                permissive.capabilities.size() >= report.capabilities.size());
    expect_true("the default tier says how much it held back",
                report.partial_hidden > 0);

    // The injection rules themselves are `mixed`: capa pairs the APIs with
    // constants such as PAGE_EXECUTE_READWRITE, which an import table cannot
    // supply. So they belong to the permissive tier and must NOT appear in the
    // default one -- that separation is the entire confidence model, and it is
    // why the default view stays quiet on notepad.exe.
    const auto names_an_injection = [](const malapi::CapabilityReport& r) {
        for (const malapi::Capability& c : r.capabilities) {
            if (c.name.find("inject") != std::string::npos) {
                return true;
            }
        }
        return false;
    };
    expect_true("injection shows up once unseen features are assumed",
                names_an_injection(permissive));
    expect_true("injection is withheld from the high-confidence tier",
                !names_an_injection(report));

    std::printf("       %zu high-confidence, %d partial hidden, %d evaluated,"
                " %d invisible\n",
                report.capabilities.size(), report.partial_hidden,
                report.rules_evaluated, report.rules_invisible);
}

}  // namespace

int main() {
    const char* db = MALAPI_TEST_DB;

    // Skipping is only legitimate when the index has not been built. If the file
    // is there and will not open, that is a failure -- a schema bump the C++ side
    // did not follow shipped a plugin that silently refused its own index, and a
    // green "SKIP" is exactly why nobody noticed.
    std::FILE* handle = std::fopen(db, "rb");
    const bool exists = handle != nullptr;
    if (handle) {
        std::fclose(handle);
    }

    malapi::Index index;
    std::string error;
    if (!index.open(db, error)) {
        if (!exists) {
            std::printf("SKIP: no index at %s\n", db);
            std::printf("Build it with: python etl/build_index.py\n");
            return 0;
        }
        std::printf("FAIL: the index exists but would not open\n       %s\n",
                    error.c_str());
        return 1;
    }

    std::printf("index: %s (schema v%s)\n\n", db, index.schema_version().c_str());

    check_charset_folding(index);
    check_case_folding(index);
    check_native_and_decoration(index);
    check_search(index);
    check_combinations(index);
    check_capabilities(index);

    if (g_failures) {
        std::printf("\n%d assertion(s) failed\n", g_failures);
        return 1;
    }
    std::printf("\nall assertions passed\n");
    return 0;
}
