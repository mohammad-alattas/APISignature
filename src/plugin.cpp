// APISignature -- x64dbg plugin entry points.
//
// Two rules hold for every function x64dbg can call:
//
//   1. No exception crosses the plugin boundary. A throw unwinding into
//      x64dbg's callback dispatcher kills the debugger mid-analysis, and an
//      analyst loses the process they were halfway through understanding. Every
//      entry point is wrapped.
//   2. Widgets are touched only on the thread that owns them. CB_SELCHANGED does
//      arrive on the GUI thread today, but that is x64dbg's implementation
//      detail rather than a documented promise, so work is posted, not called.

#include <windows.h>

#include <atomic>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <QDesktopServices>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QMetaObject>
#include <QString>
#include <QTextBrowser>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include "_plugins.h"
#include "bridgemain.h"
#include "imports.h"
#include "index.h"
#include "normalize.h"
#include "render.h"

#define PLUGIN_NAME    "APISignature"
#define PLUGIN_VERSION 1

// Long enough that arrowing through a function does not trigger a lookup per
// row, short enough to feel immediate when you stop on one.
#define SELECTION_DEBOUNCE_MS 150

namespace {

HINSTANCE g_instance = nullptr;

int g_pluginHandle = 0;
int g_hMenu = 0;

enum MenuEntry {
    kMenuPin = 0,
    kMenuSearch = 1,
    kMenuAbout = 2,
};

// Owned by us: GuiAddQWidgetTab does not take ownership. g_tab is the container
// handed to x64dbg; the search box and the browser are its children, so deleting
// it in plugstop takes the whole tree with it.
QWidget* g_tab = nullptr;
QTextBrowser* g_panel = nullptr;
QLineEdit* g_search = nullptr;
QPushButton* g_searchButton = nullptr;
QPushButton* g_capaButton = nullptr;
QTimer* g_debounce = nullptr;

// Capability names from the previous run, so a re-run can mark what is new.
// That difference is the whole reason to press the button twice: a packed
// sample gains capabilities as it unpacks and resolves imports.
std::set<std::string> g_lastCapabilities;

malapi::Index g_index;
std::atomic<duint> g_pendingVa{0};
std::atomic<bool> g_pinned{false};

// The debuggee's imports, refreshed when a process starts. Cached because the
// import table does not change under us, and re-reading it for every selection
// would mean hundreds of DbgMemRead calls per arrow key.
std::set<std::string> g_imports;
std::atomic<bool> g_haveTarget{false};

// Declared up front because callbacks defined above the definition use it.
// Every x64dbg-facing function funnels through it, so rule 1 is enforced in one
// place instead of being remembered at each call site.
template <typename Fn>
void guarded(const char* what, Fn&& fn);

// --- index location ---------------------------------------------------------

std::string to_utf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                         static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        &out[0], size, nullptr, nullptr);
    return out;
}

// The index sits beside the plugin, not beside x64dbg.exe: plugins are the thing
// that gets copied around, and an index that does not travel with its reader is
// an index that goes missing.
std::wstring plugin_directory() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD written =
            GetModuleFileNameW(g_instance, &path[0], static_cast<DWORD>(path.size()));
        if (written == 0) {
            return std::wstring();
        }
        if (written < path.size()) {
            path.resize(written);
            break;
        }
        path.resize(path.size() * 2);  // ERROR_INSUFFICIENT_BUFFER
    }

    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

bool open_index(std::string& error) {
    const std::wstring directory = plugin_directory();
    if (directory.empty()) {
        error = "could not determine the plugin directory";
        return false;
    }

    const std::wstring candidates[] = {
        directory + L"\\apisignature.db",
        directory + L"\\" PLUGIN_NAME L"\\apisignature.db",
    };

    for (const std::wstring& candidate : candidates) {
        if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES) {
            continue;
        }
        if (g_index.open(to_utf8(candidate), error)) {
            return true;
        }
        return false;  // Found it but could not use it -- report that, not "missing".
    }

    error = "no apisignature.db beside the plugin (" + to_utf8(directory) + ")";
    return false;
}

// --- panel ------------------------------------------------------------------

void set_html(const std::string& html) {
    if (!g_panel) {
        return;
    }
    const QString text = QString::fromStdString(html);
    QMetaObject::invokeMethod(
        g_panel, [text]() { g_panel->setHtml(text); }, Qt::QueuedConnection);
}

// What x64dbg shows at an address, if anything. A direct label wins; otherwise,
// if the instruction branches, the label at the branch target is what the
// analyst means by "this call" -- which is what catches `call kernel32.Sleep`.
std::string symbol_at(duint va) {
    char label[MAX_LABEL_SIZE] = "";

    if (DbgGetLabelAt(va, SEG_DEFAULT, label) && label[0]) {
        return label;
    }

    const duint destination = DbgGetBranchDestination(va);
    if (destination && destination != va &&
        DbgGetLabelAt(destination, SEG_DEFAULT, label) && label[0]) {
        char module[MAX_MODULE_SIZE] = "";
        if (DbgGetModuleAt(destination, module) && module[0]) {
            return std::string(module) + "." + label;
        }
        return label;
    }

    return std::string();
}

// Render one API by name -- the path shared by selection changes and by clicking
// a link inside the panel.
void show_api(const std::string& raw) {
    const malapi::Symbol symbol = malapi::parse_symbol(raw);
    if (!symbol.resolvable()) {
        return;
    }

    malapi::ApiEntry entry;
    if (!g_index.lookup(symbol, entry)) {
        set_html(malapi::render_not_found(symbol));
        return;
    }

    const std::vector<malapi::Combination> combinations =
        g_index.combinations_for(entry.name, g_imports);
    set_html(malapi::render_entry(entry, combinations, g_haveTarget.load()));
}

void refresh(duint va) {
    const std::string raw = symbol_at(va);
    if (raw.empty()) {
        return;  // Leave the last useful result up rather than blanking.
    }
    show_api(raw);
}

// Re-read the debuggee's imports across every loaded module.
//
// Called on process start and again whenever capabilities are requested: the
// main module's table is fixed at load, but a packed sample loads more DLLs as
// it unpacks, and each brings its own imports. Re-scanning is what lets the
// answer change.
void refresh_imports() {
    g_imports = malapi::all_imported_apis();
    g_haveTarget.store(!g_imports.empty());

    if (!g_imports.empty()) {
        _plugin_logprintf("[" PLUGIN_NAME "] %zu imported APIs from the target\n",
                          g_imports.size());
    }
}

void run_query(const std::string& query);

// --- callbacks --------------------------------------------------------------

void cbSelChanged(CBTYPE, void* info) {
    auto* selection = static_cast<PLUG_CB_SELCHANGED*>(info);
    if (!selection || selection->hWindow != GUI_DISASSEMBLY) {
        return;
    }
    if (g_pinned.load() || !g_index.is_open() || !g_debounce) {
        return;
    }

    g_pendingVa.store(selection->VA);

    // start() must run on the timer's own thread, so post it rather than calling.
    QMetaObject::invokeMethod(
        g_debounce, []() { g_debounce->start(SELECTION_DEBOUNCE_MS); },
        Qt::QueuedConnection);
}

void show_about() {
    size_t api_count = 0;
    const std::string attribution = g_index.attribution();
    set_html(malapi::render_about(attribution, g_index.path(), api_count));
    GuiShowQWidgetTab(g_tab);
}

// A process starting or stopping changes which imports exist, and therefore
// which combination members count as present.
void cbCreateProcess(CBTYPE, void*) {
    guarded("imports", refresh_imports);
}

void cbStopDebug(CBTYPE, void*) {
    g_imports.clear();
    g_haveTarget.store(false);
    // A new process starts from a clean slate; otherwise its first capability
    // report would be diffed against the previous sample's.
    g_lastCapabilities.clear();
}

void run_query(const std::string& query) {
    // Without this the panel reports "NO MATCHES" when the real problem is that
    // no index is loaded -- which reads as "this API is not documented" and sent
    // the last round of debugging in the wrong direction entirely.
    if (!g_index.is_open()) {
        set_html(malapi::render_error(
            "No index loaded",
            "Searching is unavailable. See the Log tab for why the index was "
            "refused, then reinstall with build.ps1 -Install."));
        return;
    }

    if (query.empty()) {
        set_html(malapi::render_placeholder());
        return;
    }

    // An exact API name is what people usually type, and jumping straight to the
    // entry beats showing a one-row result list they then have to click.
    {
        const malapi::Symbol symbol = malapi::parse_symbol(query);
        malapi::ApiEntry entry;
        if (symbol.resolvable() && g_index.lookup(symbol, entry)) {
            const std::vector<malapi::Combination> combinations =
                g_index.combinations_for(entry.name, g_imports);
            set_html(malapi::render_entry(entry, combinations, g_haveTarget.load()));
            return;
        }
    }

    const std::vector<malapi::SearchHit> hits = g_index.search(query);
    _plugin_logprintf("[" PLUGIN_NAME "] search '%s' -> %zu hits\n", query.c_str(),
                      hits.size());

    std::string html = "<div class=\"section\">";
    html += hits.empty() ? "NO MATCHES"
                         : std::to_string(hits.size()) + " MATCHES";
    html += "</div>";

    for (const malapi::SearchHit& hit : hits) {
        html += "<div class=\"param\"><span class=\"pname\">";
        if (!hit.dll.empty()) {
            html += "<span class=\"muted\">" + malapi::escape_html(hit.dll) + "!</span>";
        }
        // Clickable: the whole point of a result list is getting to the entry.
        html += malapi::api_link(hit.name) + "</span></div>";
        if (!hit.excerpt.empty()) {
            html += "<div class=\"small\">" + malapi::escape_html(hit.excerpt) + "</div>";
        }
    }

    set_html(html);
}

// What the target is capable of, from the APIs currently visible to us.
void show_capabilities() {
    if (!g_index.is_open()) {
        set_html(malapi::render_error(
            "No index loaded",
            "See the Log tab for why the index was refused, then reinstall with "
            "build.ps1 -Install."));
        return;
    }

    // Re-scan first: pressing this after a sample unpacks is the point.
    refresh_imports();

    const malapi::CapabilityReport report = g_index.capabilities(g_imports);

    std::set<std::string> fresh;
    std::set<std::string> current;
    for (const malapi::Capability& capability : report.capabilities) {
        current.insert(capability.name);
        if (!g_lastCapabilities.empty() && !g_lastCapabilities.count(capability.name)) {
            fresh.insert(capability.name);
        }
    }
    g_lastCapabilities = std::move(current);

    _plugin_logprintf("[" PLUGIN_NAME "] %zu capabilities from %zu APIs (%d new)\n",
                      report.capabilities.size(), report.api_count,
                      static_cast<int>(fresh.size()));

    set_html(malapi::render_capabilities(report, fresh));
}

// Ctrl+Shift+A now focuses the search box rather than opening a modal, so the
// results stay on screen and are clickable.
void focus_search() {
    if (!g_search) {
        return;
    }
    GuiShowQWidgetTab(g_tab);
    QMetaObject::invokeMethod(
        g_search,
        []() {
            g_search->setFocus(Qt::ShortcutFocusReason);
            g_search->selectAll();
            _plugin_logputs("[" PLUGIN_NAME "] search box focused");
        },
        Qt::QueuedConnection);
}

void toggle_pin() {
    const bool pinned = !g_pinned.load();
    g_pinned.store(pinned);
    _plugin_menuentrysetchecked(g_pluginHandle, kMenuPin, pinned);
    _plugin_logprintf("[" PLUGIN_NAME "] %s\n",
                      pinned ? "pinned; selection changes ignored"
                             : "following the disassembly selection");
}

template <typename Fn>
void guarded(const char* what, Fn&& fn) {
    try {
        fn();
    } catch (const std::exception& e) {
        _plugin_logprintf("[" PLUGIN_NAME "] %s failed: %s\n", what, e.what());
    } catch (...) {
        _plugin_logprintf("[" PLUGIN_NAME "] %s failed\n", what);
    }
}

void cbMenuEntry(CBTYPE, void* info) {
    auto* entry = static_cast<PLUG_CB_MENUENTRY*>(info);
    if (!entry) {
        return;
    }

    switch (entry->hEntry) {
        case kMenuPin:    guarded("pin", toggle_pin); break;
        case kMenuSearch: guarded("search", focus_search); break;
        case kMenuAbout:  guarded("about", show_about); break;
        default: break;
    }
}

}  // namespace

// --- x64dbg entry points ----------------------------------------------------

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;

    guarded("init", [] {
        _plugin_registercallback(g_pluginHandle, CB_SELCHANGED, cbSelChanged);
        _plugin_registercallback(g_pluginHandle, CB_MENUENTRY, cbMenuEntry);
        _plugin_registercallback(g_pluginHandle, CB_CREATEPROCESS, cbCreateProcess);
        _plugin_registercallback(g_pluginHandle, CB_STOPDEBUG, cbStopDebug);
    });

    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    g_hMenu = setupStruct->hMenu;

    guarded("setup", [] {
        _plugin_menuaddentry(g_hMenu, kMenuPin, "&Pin (stop following selection)");
        _plugin_menuaddentry(g_hMenu, kMenuSearch, "&Search documentation...");
        _plugin_menuaddseparator(g_hMenu);
        _plugin_menuaddentry(g_hMenu, kMenuAbout, "&About / attribution");
        _plugin_menuentrysethotkey(g_pluginHandle, kMenuSearch, "Ctrl+Shift+A");

        g_tab = new QWidget();
        g_tab->setObjectName("APISignatureTab");
        g_tab->setWindowTitle("APISignature");  // becomes the tab title

        g_search = new QLineEdit(g_tab);
        g_search->setPlaceholderText("API name, or words to search for");
        g_search->setClearButtonEnabled(true);
        g_search->setMinimumHeight(24);

        g_searchButton = new QPushButton("Search", g_tab);
        g_searchButton->setMinimumHeight(24);
        g_searchButton->setDefault(true);

        g_capaButton = new QPushButton("Capabilities", g_tab);
        g_capaButton->setMinimumHeight(24);
        g_capaButton->setToolTip(
            "What the loaded modules' imports say this target can do.\n"
            "Press again after it unpacks to see what it gained.");

        g_panel = new QTextBrowser(g_tab);
        g_panel->setObjectName("APISignaturePanel");

        // We handle every click ourselves: `api:` links navigate inside the
        // panel, everything else goes to a browser. Leaving openLinks on would
        // make QTextBrowser try to load `api:CreateProcessW` as a document and
        // blank the view.
        g_panel->setOpenLinks(false);
        g_panel->setOpenExternalLinks(false);
        QObject::connect(
            g_panel, &QTextBrowser::anchorClicked, g_panel, [](const QUrl& url) {
                guarded("link", [&url] {
                    if (url.scheme() == "http" || url.scheme() == "https") {
                        QDesktopServices::openUrl(url);
                        return;
                    }

                    // Depending on how Qt parses an opaque URL, the name can
                    // land in path(), in the scheme-specific part, or come back
                    // whole. Take whichever is non-empty rather than betting on
                    // one and silently doing nothing.
                    QString target = url.path();
                    if (target.isEmpty()) {
                        target = url.toString();
                    }
                    if (target.startsWith("api:", Qt::CaseInsensitive)) {
                        target.remove(0, 4);
                    }

                    _plugin_logprintf("[" PLUGIN_NAME "] link '%s' -> '%s'\n",
                                      url.toString().toUtf8().constData(),
                                      target.toUtf8().constData());
                    if (!target.isEmpty()) {
                        show_api(target.toStdString());
                    }
                });
            });

        auto* row = new QHBoxLayout();
        row->setContentsMargins(4, 4, 4, 4);
        row->setSpacing(4);
        row->addWidget(g_search, 1);
        row->addWidget(g_searchButton, 0);
        row->addWidget(g_capaButton, 0);

        auto* layout = new QVBoxLayout(g_tab);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(0);
        layout->addLayout(row);
        layout->addWidget(g_panel, 1);

        g_panel->document()->setDefaultStyleSheet(
            QString::fromStdString(malapi::style_sheet()));

        g_debounce = new QTimer(g_tab);
        g_debounce->setSingleShot(true);
        QObject::connect(g_debounce, &QTimer::timeout, g_panel,
                         []() { guarded("refresh", [] { refresh(g_pendingVa.load()); }); });

        // Search on an explicit trigger -- the button or Enter -- rather than as
        // you type. A partial name searched mid-keystroke replaces whatever you
        // were reading, which is worse than pressing a key to ask for it.
        const auto search_now = []() {
            guarded("search", [] { run_query(g_search->text().trimmed().toStdString()); });
        };
        QObject::connect(g_searchButton, &QPushButton::clicked, g_searchButton,
                         [search_now](bool) { search_now(); });
        QObject::connect(g_search, &QLineEdit::returnPressed, g_search, search_now);
        QObject::connect(g_capaButton, &QPushButton::clicked, g_capaButton,
                         [](bool) { guarded("capabilities", show_capabilities); });

        std::string error;
        if (open_index(error)) {
            g_panel->setHtml(QString::fromStdString(malapi::render_placeholder()));
            _plugin_logprintf("[" PLUGIN_NAME "] loaded; index %s\n",
                              g_index.path().c_str());
        } else {
            // A missing index is a setup problem, not a crash. Say so in the
            // panel as well as the log, because the panel is where someone will
            // be looking when nothing appears.
            g_panel->setHtml(QString::fromStdString(malapi::render_error(
                "No index loaded", error + ". Build it with etl/build_index.py and "
                                           "place apisignature.db beside the plugin.")));
            _plugin_logprintf("[" PLUGIN_NAME "] %s\n", error.c_str());
        }

        GuiAddQWidgetTab(g_tab);
    });
}

extern "C" __declspec(dllexport) bool plugstop() {
    guarded("stop", [] {
        _plugin_unregistercallback(g_pluginHandle, CB_SELCHANGED);
        _plugin_unregistercallback(g_pluginHandle, CB_MENUENTRY);
        _plugin_unregistercallback(g_pluginHandle, CB_CREATEPROCESS);
        _plugin_unregistercallback(g_pluginHandle, CB_STOPDEBUG);
        _plugin_menuclear(g_hMenu);

        if (g_tab) {
            GuiCloseQWidgetTab(g_tab);
            delete g_tab;  // takes the search box, browser and timers with it
            g_tab = nullptr;
            g_panel = nullptr;
            g_search = nullptr;
            g_searchButton = nullptr;
            g_capaButton = nullptr;
            g_debounce = nullptr;
        }

        g_index.close();
    });

    return true;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = instance;
    }
    return TRUE;
}
