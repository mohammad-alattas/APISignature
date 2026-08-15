// Assembles panel HTML from index rows.
//
// The document fields (doc_html, return_html, desc_html) were rendered to HTML
// by the ETL and are inserted verbatim; everything this file adds around them is
// escaped. QTextBrowser understands a subset of HTML 4 and CSS 2.1, so the
// markup stays plain and the styling lives in one stylesheet applied to the
// document rather than in inline attributes.

#pragma once

#include <string>

#include "index.h"
#include "normalize.h"

namespace malapi {

// Escapes text for insertion into markup. Applied to everything that came from
// a symbol name or a database text column that is not already HTML.
std::string escape_html(const std::string& text);

// The document stylesheet. Sets no background colours and only mid-tone
// foregrounds, so it reads on a dark or a light panel without needing to know
// which it is -- x64dbg themes via stylesheet, so QPalette cannot tell us.
std::string style_sheet();

// `target_loaded` says whether the absent members mean "not in this binary" or
// merely "we have no binary to check against". The wording changes accordingly:
// claiming an API is missing when nothing is loaded would be a lie.
std::string render_entry(const ApiEntry& entry,
                         const std::vector<Combination>& combinations,
                         bool target_loaded);

// Internal navigation. Links use an `api:` scheme so the panel can tell its own
// links from the http(s) ones that belong in a browser.
std::string api_link(const std::string& name, const std::string& label = "");

// Shown when the symbol resolved but no index row matched. Names the keys that
// were tried, since a miss is usually a normalization problem and that is the
// first thing worth seeing.
std::string render_not_found(const Symbol& symbol);

// The whole-target capability view.
//
// `fresh` names capabilities that were not in the previous report, so re-running
// after a sample unpacks shows what it just gained rather than an identical list.
std::string render_capabilities(const CapabilityReport& report,
                                const std::set<std::string>& fresh);

std::string render_placeholder();
std::string render_error(const std::string& title, const std::string& detail);
std::string render_about(const std::string& attribution, const std::string& index_path,
                         size_t api_count);

}  // namespace malapi
