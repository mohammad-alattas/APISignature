# The plugin proper: a DLL renamed .dp32/.dp64, linked against the x64dbg SDK
# and against the SAME Qt that x64dbg itself ships.

if(NOT X64DBG_ROOT)
    message(FATAL_ERROR
        "X64DBG_ROOT is not set. Point it at the x64dbg install (the directory "
        "containing pluginsdk/ and release/), or configure with "
        "-DMALAPI_BUILD_PLUGIN=OFF to build only the host-side tests.")
endif()

set(MALAPI_SDK "${X64DBG_ROOT}/pluginsdk")
if(NOT EXISTS "${MALAPI_SDK}/_plugins.h")
    message(FATAL_ERROR "No plugin SDK at ${MALAPI_SDK}")
endif()

# --- Qt ---------------------------------------------------------------------
#
# GuiAddQWidgetTab hands a QWidget across the DLL boundary into x64dbg's own Qt,
# which then calls virtual functions on it. There is no version negotiation and
# no error path: if our Qt and x64dbg's Qt disagree about vtable or struct
# layout, the debugger corrupts memory instead of failing to link. So the
# version is pinned, and a mismatch is a hard error rather than a warning.

set(MALAPI_EXPECTED_QT "5.12.12" CACHE STRING
    "Qt version x64dbg ships; check (Get-Item release/x64/Qt5Core.dll).VersionInfo")

find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets)

if(NOT Qt5Core_VERSION VERSION_EQUAL MALAPI_EXPECTED_QT)
    message(FATAL_ERROR
        "Qt ${Qt5Core_VERSION} found, but x64dbg ships ${MALAPI_EXPECTED_QT}.\n"
        "Loading a plugin built against a different Qt crashes the debugger. "
        "Point CMAKE_PREFIX_PATH at the matching kit, or override "
        "MALAPI_EXPECTED_QT if you have verified the shipped version yourself.")
endif()

set(CMAKE_AUTOMOC ON)

# --- Toolset ----------------------------------------------------------------
#
# Qt 5.12 (2018) uses stdext::checked_array_iterator, an MSVC extension that the
# STL deprecated and then removed -- it is gone in 14.51, the toolset VS 2026
# installs by default. The failure is 10 screens of template errors from inside
# qlist.h and qvector.h with nothing pointing at the real cause, so check for it
# directly and say what to do about it.
#
# This is a compile check rather than a version comparison so it keeps telling
# the truth if the STL restores the extension or Qt is patched.

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
    #include <iterator>
    int main() { int a[4]; auto it = stdext::make_checked_array_iterator(a, 4); (void)it; }
" MALAPI_STL_HAS_STDEXT_ARRAY_ITERATORS)

if(NOT MALAPI_STL_HAS_STDEXT_ARRAY_ITERATORS)
    message(FATAL_ERROR
        "This MSVC (${CMAKE_CXX_COMPILER_VERSION}) removed "
        "stdext::checked_array_iterator, which Qt ${Qt5Core_VERSION} requires.\n"
        "Build with the older toolset instead -- from a developer prompt:\n"
        "    vcvarsall.bat x64 -vcvars_ver=14.44\n"
        "then configure with -G Ninja. build.ps1 does this for you.\n"
        "Note that -T version=... does NOT work here: CMake's VS 2026 generator "
        "rejects a 14.44 tools version under the v145 toolset.")
endif()

# --- Target -----------------------------------------------------------------

add_library(APISignature SHARED
    plugin.cpp
    imports.cpp
)

target_link_libraries(APISignature PRIVATE
    malapi_index
    Qt5::Core Qt5::Gui Qt5::Widgets
    "${MALAPI_SDK}/${MALAPI_DBG_LIB}.lib"
    "${MALAPI_SDK}/${MALAPI_BRIDGE_LIB}.lib"
)

target_include_directories(APISignature PRIVATE "${MALAPI_SDK}")

# x64dbg discovers plugins by extension, and the extension is how it decides
# which architecture a plugin is for. A .dp64 in the x32 plugins directory is
# silently ignored.
set_target_properties(APISignature PROPERTIES
    PREFIX  ""
    SUFFIX  "${MALAPI_SUFFIX}"
)

# Qt 5.12 predates the compilers that can now build it. Its headers trip
# warnings we cannot fix and do not own, so quiet them at the boundary rather
# than dropping /W4 for our own code.
target_compile_options(APISignature PRIVATE /wd4127 /wd4251)

# Optional convenience: drop the built plugin straight into x64dbg so a rebuild
# is immediately loadable. Off by default -- writing into another application's
# install directory should be something you ask for.
option(MALAPI_INSTALL_TO_X64DBG "Copy the built plugin into x64dbg's plugins directory" OFF)

# The plugin looks for its index beside itself (see open_index in plugin.cpp), so
# installing the DLL alone produces a plugin that loads and then reports "No
# index loaded" -- which looks like a bug and is really a missing file. Whatever
# copies the DLL copies the index too.
set(MALAPI_INDEX "${CMAKE_SOURCE_DIR}/dist/apisignature.db" CACHE FILEPATH
    "Prebuilt index to install beside the plugin")

if(MALAPI_INSTALL_TO_X64DBG)
    set(MALAPI_PLUGIN_DIR "${X64DBG_ROOT}/release/${MALAPI_ARCH}/plugins")

    add_custom_command(TARGET APISignature POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${MALAPI_PLUGIN_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:APISignature>"
                "${MALAPI_PLUGIN_DIR}/"
        COMMENT "Installing $<TARGET_FILE_NAME:APISignature> into x64dbg")

    if(EXISTS "${MALAPI_INDEX}")
        add_custom_command(TARGET APISignature POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${MALAPI_INDEX}" "${MALAPI_PLUGIN_DIR}/apisignature.db"
            COMMENT "Installing apisignature.db beside the plugin")
    else()
        # A warning rather than an error: building the plugin without an index is
        # a legitimate thing to do, and the plugin says so itself at runtime.
        message(WARNING
            "No index at ${MALAPI_INDEX}, so only the DLL will be installed and "
            "the panel will report 'No index loaded'.\n"
            "Download apisignature.db from the releases page and place it there, build "
            "it with `python etl/build_index.py`, or point -DMALAPI_INDEX at it.")
    endif()
endif()
