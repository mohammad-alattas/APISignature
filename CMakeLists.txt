cmake_minimum_required(VERSION 3.21)
project(APISignature VERSION 0.1.0 LANGUAGES C CXX)

# x64dbg plugins are plain DLLs with an architecture-specific extension. One
# configure/build per architecture: x64 produces .dp64, x86 produces .dp32.
#
#   cmake -B build64 -A x64 -DX64DBG_ROOT="D:/Malware Analysis/x64_86dbg" ^
#         -DCMAKE_PREFIX_PATH="D:/Malware Analysis/x64_86dbg/Qt/qt5.12.12-msvc2017_64"
#   cmake --build build64 --config Release
#
# The Qt build MUST match the Qt that x64dbg itself ships, because
# GuiAddQWidgetTab hands a widget across the DLL boundary into x64dbg's own Qt.
# Verified for this checkout: release/x64/Qt5Core.dll and release/x32/Qt5Core.dll
# are both 5.12.12.0, matching Qt/qt5.12.12-msvc2017_64. MSVC v141 and v143 are
# binary compatible, so building with VS2022 against an msvc2017 Qt is fine.
#
# Pass -DMALAPI_BUILD_PLUGIN=OFF to build and run only the host-side tests, which
# need neither x64dbg nor Qt.

option(MALAPI_BUILD_PLUGIN "Build the x64dbg plugin (needs x64dbg SDK and Qt)" ON)
option(MALAPI_BUILD_TESTS "Build the unit tests" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    message(FATAL_ERROR "x64dbg plugins require MSVC")
endif()

add_compile_options(/W4 /permissive- /utf-8)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MALAPI_ARCH       x64)
    set(MALAPI_SUFFIX     .dp64)
    set(MALAPI_DBG_LIB    x64dbg)
    set(MALAPI_BRIDGE_LIB x64bridge)
else()
    set(MALAPI_ARCH       x32)
    set(MALAPI_SUFFIX     .dp32)
    set(MALAPI_DBG_LIB    x32dbg)
    set(MALAPI_BRIDGE_LIB x32bridge)
endif()

# Portable half of the plugin: no x64dbg, no Qt, no I/O. Kept separate so it can
# be unit-tested on the host, which is the only way the Python/C++ contract in
# etl/tests/normalize_cases.json stays honest.
add_library(malapi_core STATIC
    src/normalize.cpp
)
target_include_directories(malapi_core PUBLIC src)

# SQLite, built from the amalgamation. Its own target so the project's /W4
# does not bury our warnings under thousands from code we do not maintain.
#
# FTS5 is required, not optional: the index carries an api_fts table and the
# search uses snippet(). Loadable extensions are compiled out -- this process is
# a debugger attached to malware, and an index file that could pull in a DLL is
# an attack surface we have no reason to offer.
add_library(sqlite3 STATIC third_party/sqlite3.c)
target_include_directories(sqlite3 PUBLIC third_party)
target_compile_definitions(sqlite3 PUBLIC
    SQLITE_ENABLE_FTS5
    SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_DQS=0                  # reject double-quoted string literals
    SQLITE_LIKE_DOESNT_MATCH_BLOBS
    SQLITE_MAX_EXPR_DEPTH=0
)
target_compile_options(sqlite3 PRIVATE /W0)

# zlib, inflate side only. The plugin never compresses -- that happens in the
# Python ETL -- so deflate.c, trees.c, compress.c, gzip and the rest are simply
# not vendored. Six .c files instead of fifteen, and no code we cannot reach.
add_library(zlibinflate STATIC
    third_party/zlib/adler32.c
    third_party/zlib/crc32.c
    third_party/zlib/inffast.c
    third_party/zlib/inflate.c
    third_party/zlib/inftrees.c
    third_party/zlib/zutil.c
)
target_include_directories(zlibinflate PUBLIC third_party/zlib)
target_compile_options(zlibinflate PRIVATE /W0)

# Z_SOLO drops the gzip file API, which is the only reason zutil.c wants
# gzguts.h and stdio. PUBLIC because zlib.h itself changes shape under it, so
# the library and its callers must agree. The trade is that zlib no longer
# provides a default allocator -- see zlib_alloc in src/index.cpp.
target_compile_definitions(zlibinflate PUBLIC Z_SOLO)

# Index reader and panel rendering. Needs neither x64dbg nor Qt, so it is
# testable on the host against a real dist/apisignature.db.
add_library(malapi_index STATIC
    src/index.cpp
    src/render.cpp
)
target_link_libraries(malapi_index PUBLIC malapi_core sqlite3 zlibinflate)

if(MALAPI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(MALAPI_BUILD_PLUGIN)
    add_subdirectory(src)
endif()
