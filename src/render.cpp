#include "render.h"

namespace malapi {
namespace {

void append_section(std::string& out, const char* title) {
    out += "<div class=\"section\">";
    out += title;
    out += "</div>";
}

// A top-level group: one source of truth, clearly fenced off from the others.
//
// The three groups say very different kinds of thing -- a curated claim about
// how attackers abuse a call, a vendor's reference text, and a community rule
// about co-occurring APIs -- and an analyst weighing them needs to know which is
// which. So each group names its source rather than presenting one seamless
// wall of text.
//
// The rule is an <hr> rather than a CSS border: QTextBrowser supports only a
// subset of CSS 2.1 and is inconsistent about borders on block elements, but it
// always renders <hr>.
void append_group(std::string& out, const char* title, const char* source) {
    out += "<hr>";
    out += "<div class=\"group\">";
    out += title;
    out += "</div>";
    out += "<div class=\"source\">";
    out += source;
    out += "</div>";
}

// MalAPI's eight categories, coloured by how much each one narrows the question
// "is this sample doing something hostile". Injection and Ransomware are close
// to a verdict on their own; Helper covers calls that appear in every second
// benign program. Flattening them to one colour would imply they carry equal
// weight, which is the opposite of the truth.
const char* attack_class(const std::string& attack) {
    if (attack == "Injection" || attack == "Ransomware") {
        return "chip severe";
    }
    if (attack == "Evasion" || attack == "Anti-Debugging" || attack == "Spying") {
        return "chip notable";
    }
    return "chip";  // Helper, Enumeration, Internet
}

}  // namespace

std::string escape_html(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default:  out += c; break;
        }
    }
    return out;
}

std::string style_sheet() {
    // Deliberately theme-agnostic: no background colours anywhere, and every
    // foreground colour is a mid tone that stays legible on both a dark and a
    // light panel.
    //
    // The obvious approach -- read QPalette and branch on dark vs light -- does
    // not work here. x64dbg themes itself with a stylesheet rather than a
    // palette, so QPalette::Base still reports the default light colour while
    // the panel renders dark. Trusting it painted a near-white block behind
    // every <pre> and every inline <code> in Microsoft's prose. Since the host
    // background cannot be detected reliably, the fix is to never paint one:
    // code is distinguished by its monospace face, not by a filled box.
    const char* muted = "#8a8f94";   // ~4:1 on both black and white
    const char* rule  = "#7f7f7f";
    const char* severe  = "#e06c62";
    const char* notable = "#c99a2e";

    std::string css;
    css += "h2 { font-size: 13pt; margin: 2px 0 6px 0; }";

    // Qt's default link colour is pure blue, which is close to unreadable on
    // x64dbg's charcoal. This mid blue works against either.
    css += "a { color: #4a90d9; }";

    css += ".section { font-weight: bold; font-size: 8pt;";
    css += " color: "; css += muted; css += ";";
    css += " border-bottom: 1px solid "; css += rule; css += ";";
    css += " margin: 14px 0 4px 0; }";

    css += ".muted { color: "; css += muted; css += "; }";
    css += ".small { font-size: 8pt; }";

    // Group heading sits a clear step above the section headings inside it, so
    // the hierarchy reads at a glance: which source, then which part of it.
    css += ".group { font-size: 11pt; font-weight: bold; margin: 12px 0 0 0; }";
    css += ".source { font-size: 8pt; font-style: italic;";
    css += " color: "; css += muted; css += "; margin: 0 0 8px 0; }";

    css += "pre, code { font-family: Consolas, 'Courier New', monospace; }";
    css += "pre { margin: 4px 0; }";

    css += ".intent { margin: 4px 0; }";
    css += ".chip { font-size: 8pt; font-weight: bold; }";
    css += ".severe { color: "; css += severe; css += "; }";
    css += ".notable { color: "; css += notable; css += "; }";

    css += ".param { margin-top: 6px; }";
    css += ".pname { font-family: Consolas, 'Courier New', monospace; font-weight: bold; }";

    return css;
}

std::string api_link(const std::string& name, const std::string& label) {
    const std::string text = label.empty() ? name : label;
    return "<a href=\"api:" + escape_html(name) + "\">" + escape_html(text) + "</a>";
}

// The capability section.
//
// This deliberately does not render a verdict. capa's static scope wants these
// APIs in the *same function*, while an import set only proves they exist
// somewhere in the binary -- so the honest presentation is the combination
// itself with each member marked, letting the analyst judge. Saying "this binary
// performs process injection" from an import table would be overclaiming.
std::string render_combinations(const std::vector<Combination>& combinations,
                                bool target_loaded) {
    if (combinations.empty()) {
        return std::string();
    }

    std::string out;
    out += "<div class=\"muted small\">Known malicious combinations this call "
           "takes part in.</div>";

    for (const Combination& combination : combinations) {
        out += "<div class=\"param\"><span class=\"pname\">";
        out += escape_html(combination.name);
        out += "</span>";
        if (!combination.high_confidence()) {
            // Say what cannot be checked rather than presenting a partial match
            // as an equal. These rules also test strings or constants that an
            // import table cannot see.
            out += " <span class=\"muted small\">(+";
            out += std::to_string(combination.unknown_leaves);
            out += " unverifiable)</span>";
        }
        out += "</div>";

        if (!combination.name_space.empty()) {
            out += "<div class=\"muted small\">" +
                   escape_html(combination.name_space) + "</div>";
        }

        out += "<div class=\"small\">";
        for (size_t i = 0; i < combination.present.size(); ++i) {
            if (i) {
                out += "<span class=\"muted\"> + </span>";
            }
            out += "<span class=\"severe\">" + api_link(combination.present[i]) +
                   "</span>";
        }
        for (const std::string& api : combination.absent) {
            out += "<span class=\"muted\"> + " + api_link(api) + "</span>";
        }
        out += "</div>";

        if (!combination.absent.empty()) {
            out += "<div class=\"muted small\">";
            out += target_loaded
                       ? "greyed members are not in the target's imports"
                       : "greyed members not checked -- no target loaded";
            out += "</div>";
        }

        for (const std::string& label : combination.attck) {
            out += "<div class=\"small muted\">ATT&amp;CK " + escape_html(label) +
                   "</div>";
        }
    }

    // The caveat belongs next to the claim, not in a README nobody reads.
    out += "<div class=\"muted small\" style=\"margin-top:8px\">"
           "capa matches these within a single function; an import set only "
           "proves the calls exist somewhere in the binary.</div>";
    return out;
}

std::string render_entry(const ApiEntry& entry,
                         const std::vector<Combination>& combinations,
                         bool target_loaded) {
    std::string out;

    out += "<h2>";
    if (!entry.dll.empty()) {
        out += "<span class=\"muted\">" + escape_html(entry.dll) + "!</span>";
    }
    out += escape_html(entry.name);
    out += "</h2>";

    // --- 1. MalAPI -----------------------------------------------------------
    //
    // First because it is the reason this plugin exists, it is short, and it is
    // present for only 369 of 44,527 APIs -- burying it under Microsoft's prose
    // would waste the one section the analyst came for.
    append_group(out, "MALICIOUS USE", "malapi.io");

    if (entry.intent.present) {
        out += "<div class=\"intent\">" + escape_html(entry.intent.description) + "</div>";

        if (entry.intent.documented_as != entry.name) {
            // The MSDN page and the MalAPI entry are different charset variants
            // of the same call. Say so rather than silently attributing one
            // spelling's write-up to the other.
            out += "<div class=\"muted small\">MalAPI documents this as ";
            out += escape_html(entry.intent.documented_as);
            out += "</div>";
        }

        if (!entry.intent.attacks.empty()) {
            out += "<div style=\"margin-top:6px\">";
            for (size_t i = 0; i < entry.intent.attacks.size(); ++i) {
                const std::string& attack = entry.intent.attacks[i];
                if (i) {
                    out += "<span class=\"muted\"> &middot; </span>";
                }
                out += "<span class=\"";
                out += attack_class(attack);
                out += "\">";
                out += escape_html(attack);
                out += "</span>";
            }
            out += "</div>";
        }
    } else {
        // Absence is information: it means this call is not among the 369 MalAPI
        // catalogues, not that the lookup failed. Worth one quiet line.
        out += "<div class=\"muted\">";
        out += "Not in MalAPI's catalogue of commonly abused calls.";
        out += "</div>";
    }

    // --- 2. Microsoft --------------------------------------------------------
    const bool has_reference =
        !entry.doc_html.empty() || !entry.syntax.empty() || !entry.params.empty() ||
        !entry.return_html.empty() || !entry.header.empty() || !entry.doc_url.empty();

    if (has_reference) {
        append_group(out, "DOCUMENTATION",
                     "Microsoft, via sdk-api &mdash; CC BY 4.0");
    }

    if (!entry.doc_html.empty()) {
        append_section(out, "DESCRIPTION");
        out += entry.doc_html;
    }

    if (!entry.syntax.empty()) {
        append_section(out, "SYNTAX");
        if (!entry.syntax_from.empty() && entry.syntax_from != entry.name) {
            // Borrowed from a charset sibling. The parameter order matches but
            // the string types do not (LPCSTR against LPCWSTR), so label it
            // rather than let it read as this function's own prototype.
            out += "<div class=\"muted small\">signature shown is ";
            out += escape_html(entry.syntax_from);
            out += "'s</div>";
        }
        out += "<pre>" + escape_html(entry.syntax) + "</pre>";
    }

    if (!entry.params.empty()) {
        append_section(out, "PARAMETERS");
        for (const Param& param : entry.params) {
            out += "<div class=\"param\"><span class=\"pname\">";
            out += escape_html(param.name);
            out += "</span></div>";
            if (!param.desc_html.empty()) {
                out += param.desc_html;
            }
        }
    }

    if (!entry.return_html.empty()) {
        append_section(out, "RETURN VALUE");
        out += entry.return_html;
    }

    if (!entry.header.empty() || !entry.doc_url.empty() || !entry.intent.source_url.empty()) {
        append_section(out, "REFERENCE");
        out += "<div class=\"small\">";
        if (!entry.header.empty()) {
            out += "<div>Header: <code>" + escape_html(entry.header) + "</code></div>";
        }
        if (!entry.doc_url.empty()) {
            const std::string url = escape_html(entry.doc_url);
            out += "<div><a href=\"" + url + "\">Microsoft documentation</a></div>";
        }
        if (!entry.intent.source_url.empty()) {
            const std::string url = escape_html(entry.intent.source_url);
            out += "<div><a href=\"" + url + "\">malapi.io entry</a></div>";
        }
        out += "</div>";
    }

    // --- 3. capa -------------------------------------------------------------
    //
    // Last because it is the longest and the least often present. Unlike the
    // MalAPI group there is no "none found" line: most of the 44,527 APIs take
    // part in no combination, so saying so every time would be noise rather
    // than information.
    if (!combinations.empty()) {
        append_group(out, "API COMBINATIONS", "mandiant/capa-rules &mdash; Apache 2.0");
        out += render_combinations(combinations, target_loaded);
    }

    return out;
}

std::string render_not_found(const Symbol& symbol) {
    std::string out;
    out += "<h2>" + escape_html(symbol.function) + "</h2>";
    out += "<div class=\"muted\">Not in the index.</div>";

    // A miss is nearly always a normalization problem, so show the keys that were
    // tried. It turns "the panel is blank" into a reproducible bug report.
    out += "<div class=\"section\">TRIED</div><div class=\"small\">";
    for (const std::string& key : symbol.lookup_keys) {
        out += "<div><code>" + escape_html(key) + "</code></div>";
    }
    out += "<div class=\"muted\">canonical: <code>" +
           escape_html(symbol.canonical_key) + "</code></div>";
    out += "</div>";
    return out;
}

std::string render_capabilities(const CapabilityReport& report,
                                const std::set<std::string>& fresh) {
    std::string out = "<h2>Capabilities</h2>";

    if (report.api_count == 0) {
        out += "<div class=\"muted\">No target loaded, or no imports could be "
               "read. Start the debuggee and try again.</div>";
        return out;
    }

    out += "<div class=\"muted small\">matched against " +
           std::to_string(report.api_count) + " APIs imported by the loaded "
           "modules</div>";

    if (report.capabilities.empty()) {
        out += "<div class=\"section\">NOTHING MATCHED</div>";
    } else {
        out += "<div class=\"section\">" +
               std::to_string(report.capabilities.size()) + " CAPABILITIES</div>";
    }

    for (const Capability& capability : report.capabilities) {
        out += "<div class=\"param\"><span class=\"pname\">";
        out += escape_html(capability.name);
        out += "</span>";
        if (fresh.count(capability.name)) {
            // The point of re-running: what the sample has just gained.
            out += " <span class=\"severe small\">NEW</span>";
        }
        if (!capability.high_confidence()) {
            out += " <span class=\"muted small\">(+" +
                   std::to_string(capability.unknown_leaves) +
                   " unverifiable)</span>";
        }
        out += "</div>";

        if (!capability.name_space.empty()) {
            out += "<div class=\"muted small\">" +
                   escape_html(capability.name_space) + "</div>";
        }

        out += "<div class=\"small\">";
        for (size_t i = 0; i < capability.matched.size(); ++i) {
            if (i) {
                out += "<span class=\"muted\"> + </span>";
            }
            out += api_link(capability.matched[i]);
        }
        out += "</div>";

        for (const std::string& label : capability.attck) {
            out += "<div class=\"small muted\">ATT&amp;CK " + escape_html(label) +
                   "</div>";
        }
    }

    // The denominator, on screen rather than in a README. A short list can mean
    // "this sample does little" or "most of what capa checks is invisible from an
    // import table", and those are opposite conclusions.
    out += "<div class=\"section\">COVERAGE</div><div class=\"small muted\">";
    out += "Evaluated " + std::to_string(report.rules_evaluated) +
           " rules that APIs can decide.";
    if (report.partial_hidden) {
        out += " " + std::to_string(report.partial_hidden) +
               " further rules matched on APIs but also test strings or "
               "constants we cannot see, and are not shown.";
    }
    if (report.rules_invisible) {
        out += " " + std::to_string(report.rules_invisible) +
               " rules test no APIs at all and are invisible from an import "
               "table.";
    }
    out += " capa matches within a single function; an import set only proves "
           "the calls exist somewhere in the loaded modules.";
    out += "</div>";
    return out;
}

std::string render_placeholder() {
    return "<h2>APISignature</h2>"
           "<div class=\"muted\">Select an API call in the disassembly.</div>";
}

std::string render_error(const std::string& title, const std::string& detail) {
    std::string out;
    out += "<h2>" + escape_html(title) + "</h2>";
    out += "<div class=\"muted\">" + escape_html(detail) + "</div>";
    return out;
}

std::string render_about(const std::string& attribution, const std::string& index_path,
                         size_t api_count) {
    std::string out;
    out += "<h2>APISignature</h2>";

    out += "<div class=\"small\">";
    out += "<div>Index: <code>" + escape_html(index_path) + "</code></div>";
    if (api_count) {
        out += "<div>" + std::to_string(api_count) + " documented APIs</div>";
    }
    out += "</div>";

    // Not decoration: the index redistributes CC BY 4.0 documentation, and the
    // licence requires the attribution to travel with it.
    append_section(out, "ATTRIBUTION");
    out += "<div class=\"small\">";
    size_t start = 0;
    while (start < attribution.size()) {
        size_t end = attribution.find("\n\n", start);
        if (end == std::string::npos) {
            end = attribution.size();
        }
        out += "<p>" + escape_html(attribution.substr(start, end - start)) + "</p>";
        start = end + 2;
    }
    out += "</div>";
    return out;
}

}  // namespace malapi
