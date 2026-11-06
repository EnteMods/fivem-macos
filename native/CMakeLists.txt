cmake_minimum_required(VERSION 3.20)
project(CfxNativeFoundation LANGUAGES C CXX)

if(NOT APPLE)
  message(FATAL_ERROR "This port target currently requires macOS.")
endif()
set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Native port architecture")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CFX_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../port/fivem" CACHE PATH "Isolated FiveM source worktree")
get_filename_component(CFX_SOURCE_DIR "${CFX_SOURCE_DIR}" ABSOLUTE)
string(REPLACE "[" "[[]" CFX_GLOB_ROOT "${CFX_SOURCE_DIR}")
option(CFX_NATIVE_GAME_TARGET "Attempt full GTA_FIVE CoreRT compilation; game/platform boundaries remain unresolved" OFF)

foreach(required vendor/fmtlib/CMakeLists.txt vendor/tbb/CMakeLists.txt vendor/rapidjson/include/rapidjson/document.h vendor/utfcpp/source/utf8.h)
  if(NOT EXISTS "${CFX_SOURCE_DIR}/${required}")
    message(FATAL_ERROR "Missing pinned source dependency: ${required}; run native bootstrap first.")
  endif()
endforeach()
set(FMT_TEST OFF CACHE BOOL "" FORCE)
set(FMT_DOC OFF CACHE BOOL "" FORCE)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory("${CFX_SOURCE_DIR}/vendor/fmtlib" dependencies/fmt)
set(TBB_TEST OFF CACHE BOOL "" FORCE)
set(TBB_EXAMPLES OFF CACHE BOOL "" FORCE)
set(TBB_STRICT OFF CACHE BOOL "" FORCE)
# Upstream's absolute glob treats brackets in a workspace path as a pattern.
# Load its utility macros explicitly without changing the pinned dependency.
include("${CFX_SOURCE_DIR}/vendor/tbb/cmake/utils.cmake")
include("${CFX_SOURCE_DIR}/vendor/tbb/cmake/config_generation.cmake")
include("${CFX_SOURCE_DIR}/vendor/tbb/cmake/vars_utils.cmake")
set(TBBMALLOC_BUILD OFF CACHE BOOL "" FORCE)
set(TBB_ENABLE_IPO OFF CACHE BOOL "" FORCE)
add_subdirectory("${CFX_SOURCE_DIR}/vendor/tbb" dependencies/tbb)

file(GLOB boostRoots "${CFX_GLOB_ROOT}/vendor/boost-submodules/*/include")
add_library(cfx_native_options INTERFACE)
target_include_directories(cfx_native_options INTERFACE
  "${CFX_SOURCE_DIR}/code/client/shared"
  "${CFX_SOURCE_DIR}/code/client/citicore"
  "${CFX_SOURCE_DIR}/code/shared"
  "${CFX_SOURCE_DIR}/vendor/rapidjson/include"
  "${CFX_SOURCE_DIR}/vendor/utfcpp/source"
  ${boostRoots})
target_compile_definitions(cfx_native_options INTERFACE BOOST_ALL_NO_LIB CFX_NATIVE_FOUNDATION=1)
target_compile_options(cfx_native_options INTERFACE -Wno-deprecated-declarations -Wno-deprecated-copy -Wno-deprecated-literal-operator -Wno-character-conversion)

# The source selection follows Shared's upstream non-Windows rules.
file(GLOB sharedSources CONFIGURE_DEPENDS
  "${CFX_GLOB_ROOT}/code/client/shared/*.cpp"
  "${CFX_GLOB_ROOT}/code/shared/*.cpp")
list(FILTER sharedSources EXCLUDE REGEX "\\.Win32\\.cpp$")
list(FILTER sharedSources EXCLUDE REGEX "/Hooking\\..*\\.cpp$")
list(FILTER sharedSources EXCLUDE REGEX "/Hooking\\.cpp$")
add_library(Shared STATIC ${sharedSources})
target_link_libraries(Shared PUBLIC cfx_native_options fmt::fmt)
target_compile_definitions(Shared PRIVATE COMPILING_SHARED)

# All public CitiCore C++ translation units are included, except upstream Win32-only units.
file(GLOB_RECURSE coreSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/client/citicore/*.cpp")
list(FILTER coreSources EXCLUDE REGEX "\\.Win32\\.cpp$")
list(APPEND coreSources "${CFX_SOURCE_DIR}/code/client/common/Error.cpp" "${CFX_SOURCE_DIR}/code/client/common/StdInc.cpp")
add_library(CoreRT SHARED ${coreSources})
target_link_libraries(CoreRT PUBLIC Shared TBB::tbb)
target_compile_definitions(CoreRT PRIVATE COMPILING_CORE)
set_target_properties(CoreRT PROPERTIES OUTPUT_NAME CoreRT)
if(CFX_NATIVE_GAME_TARGET)
  target_compile_definitions(cfx_native_options INTERFACE GTA_FIVE "GAME_BUILDS=(1604)(3258)(3889)")
else()
  target_compile_definitions(cfx_native_options INTERFACE "GAME_BUILDS=(0)")
endif()

# Full public non-Windows vfs-core, including ZIP and RPF readers.
find_package(ZLIB REQUIRED)
add_library(cfx_minizip STATIC
  "${CFX_SOURCE_DIR}/vendor/minizip/mz_strm.c"
  "${CFX_SOURCE_DIR}/vendor/minizip/mz_strm_mem.c"
  "${CFX_SOURCE_DIR}/vendor/minizip/mz_strm_crc32.c"
  "${CFX_SOURCE_DIR}/vendor/minizip/mz_strm_zlib.c"
  "${CFX_SOURCE_DIR}/vendor/minizip/mz_zip.c"
  "${CFX_SOURCE_DIR}/vendor/minizip/mz_zip_rw.c")
target_include_directories(cfx_minizip PUBLIC "${CFX_SOURCE_DIR}/vendor/minizip")
target_compile_definitions(cfx_minizip PRIVATE HAVE_ZLIB)
target_link_libraries(cfx_minizip PUBLIC ZLIB::ZLIB)
file(GLOB vfsSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/components/vfs-core/src/*.cpp")
list(FILTER vfsSources EXCLUDE REGEX "\\.Win32\\.cpp$")
add_library(VFSCore SHARED ${vfsSources})
target_include_directories(VFSCore PUBLIC "${CFX_SOURCE_DIR}/code/components/vfs-core/include")
target_compile_definitions(VFSCore PRIVATE COMPILING_VFS_CORE)
target_link_libraries(VFSCore PUBLIC CoreRT cfx_minizip)
set_target_properties(VFSCore PROPERTIES OUTPUT_NAME vfs-core)

# Reuse the existing POSIX device/manager implementation, with no server build define.
file(GLOB fsSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/components/vfs-impl-server/src/*.cpp")
list(FILTER fsSources EXCLUDE REGEX "\\.Win32\\.cpp$")
add_library(NativeFS SHARED ${fsSources})
target_include_directories(NativeFS PUBLIC "${CFX_SOURCE_DIR}/code/components/vfs-impl-server/include")
target_link_libraries(NativeFS PUBLIC VFSCore)
set_target_properties(NativeFS PROPERTIES OUTPUT_NAME cfx-native-filesystem)

include(CTest)
if(BUILD_TESTING)
  target_sources(CoreRT PRIVATE tests/core_test_entry.cpp)
  add_library(native_fixture MODULE tests/native_fixture.cpp)
  target_link_libraries(native_fixture PRIVATE CoreRT)
  set_target_properties(native_fixture PROPERTIES OUTPUT_NAME native-fixture SUFFIX ".dylib")
  file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/libnative-fixture.json" CONTENT
    "{\"name\":\"native:fixture\",\"version\":\"1.0.0.0\",\"dependencies\":[],\"provides\":[],\"shouldAutoInstance\":false}\n")
  add_executable(tests_native_core tests/native_core.cpp)
  add_executable(tests_native_vfs tests/native_vfs.cpp)
  target_link_libraries(tests_native_vfs PRIVATE NativeFS)
  add_test(NAME native_vfs_io COMMAND tests_native_vfs)
  add_test(NAME native_vfs_invalid_handles COMMAND tests_native_vfs --invalid-handle-probe)
  set_tests_properties(native_vfs_io PROPERTIES TIMEOUT 15)
  target_link_libraries(tests_native_core PRIVATE CoreRT)
  add_dependencies(tests_native_core native_fixture)
  add_test(NAME native_core_api COMMAND tests_native_core)
  set_tests_properties(native_core_api PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" TIMEOUT 10)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_test(NAME native_client_refuses_without_security
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_security_refusal.py" "$<TARGET_FILE:tests_native_core>")
endif()

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/source-scope.txt" CONTENT
  "Scope: native shared utilities and public CoreRT foundation. No IS_FXSERVER define. No GTA/FiveM client gameplay, auth, or anti-cheat success claim. CFX_NATIVE_GAME_TARGET=${CFX_NATIVE_GAME_TARGET}\nShared sources: ${sharedSources}\nCoreRT sources: ${coreSources}\n")
