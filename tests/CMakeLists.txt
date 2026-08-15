# Host-side tests. These need neither x64dbg nor Qt, so the Python/C++ contract
# can be checked on any machine with a compiler.

# Regenerate the fixture header from the shared JSON contract at configure time,
# so a change to normalize_cases.json cannot be forgotten on the C++ side.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    execute_process(
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/etl/gen_cpp_fixtures.py"
        RESULT_VARIABLE gen_result
        OUTPUT_VARIABLE gen_output
        ERROR_VARIABLE  gen_output
    )
    if(NOT gen_result EQUAL 0)
        message(WARNING "Could not regenerate fixtures: ${gen_output}")
    else()
        message(STATUS "Fixtures: ${gen_output}")
    endif()
else()
    message(WARNING
        "Python not found; tests/normalize_cases.inc will not be regenerated "
        "and may be stale relative to etl/tests/normalize_cases.json")
endif()

add_executable(test_normalize test_normalize.cpp)
target_link_libraries(test_normalize PRIVATE malapi_core)
target_include_directories(test_normalize PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

add_test(NAME normalize COMMAND test_normalize)

# Runs against the real dist/apisignature.db. Skips itself when the index has not been
# built, so a fresh checkout still passes `ctest`.
add_executable(test_index test_index.cpp)
target_link_libraries(test_index PRIVATE malapi_index)
target_compile_definitions(test_index PRIVATE
    MALAPI_TEST_DB="${CMAKE_SOURCE_DIR}/dist/apisignature.db")

add_test(NAME index COMMAND test_index)
