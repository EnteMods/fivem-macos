cmake_minimum_required(VERSION 3.20)
project(CfxCoreLoaderFixture LANGUAGES C CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(../windows-core core EXCLUDE_FROM_ALL)
set(test_sources "${CMAKE_CURRENT_SOURCE_DIR}/../windows-tests")

add_executable(corert_loader_probe "${test_sources}/core_loader_probe.cpp")

set(manifest "${CMAKE_CURRENT_BINARY_DIR}/fixture-auto.json")
set(resource "${CMAKE_CURRENT_BINARY_DIR}/fixture-auto.rc")
file(WRITE "${manifest}"
  "{\"name\":\"windows:fixture\",\"version\":\"1.2.3.0\",\"provides\":[],\"dependencies\":[],\"shouldAutoInstance\":true}")
file(WRITE "${resource}" "FXCOMPONENT 115 \"${manifest}\"\n")
add_library(windows_fixture_auto SHARED "${test_sources}/core_dll_fixture.cpp" "${resource}")
target_link_libraries(windows_fixture_auto PRIVATE Shared)
set_target_properties(windows_fixture_auto PROPERTIES PREFIX "" OUTPUT_NAME "windows-fixture"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/auto-fixture"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/auto-fixture"
  PDB_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/auto-fixture")
