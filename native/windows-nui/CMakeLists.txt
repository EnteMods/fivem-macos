cmake_minimum_required(VERSION 3.20)
project(CfxWindowsNui LANGUAGES C CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CFX_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../port/fivem" CACHE PATH "Isolated public source worktree")
get_filename_component(CFX_SOURCE_DIR "${CFX_SOURCE_DIR}" ABSOLUTE)
string(REPLACE "[" "[[]" CFX_GLOB_ROOT "${CFX_SOURCE_DIR}")
file(READ "${CFX_SOURCE_DIR}/vendor/cef/cef_build_name.txt" cefBuildName)
string(STRIP "${cefBuildName}" cefBuildName)
set(CFX_NUI_COMPONENT_DIR "${CFX_SOURCE_DIR}/code/components/nui-core" CACHE PATH "NUI component source")
get_filename_component(CFX_PROJECT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(CFX_CEF_ROOT "${CFX_PROJECT}/toolchains/cef/${cefBuildName}" CACHE PATH "Original source-pinned Cfx CEF package")
string(REPLACE "[" "[[]" CFX_CEF_GLOB_ROOT "${CFX_CEF_ROOT}")
if(NOT EXISTS "${CFX_CEF_ROOT}/include/cef_api_hash.h" OR NOT EXISTS "${CFX_CEF_ROOT}/Release/libcef.lib")
  message(FATAL_ERROR "Run native/windows-nui/prepare_cef.py to obtain the exact official package build inputs")
endif()
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../windows-core" dependencies/core EXCLUDE_FROM_ALL)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../compiler-rt" dependencies/compiler-rt EXCLUDE_FROM_ALL)

add_library(cfx_nui_options INTERFACE)
target_link_libraries(cfx_nui_options INTERFACE cfx_win_options)
target_include_directories(cfx_nui_options INTERFACE
  "${CFX_VC}/atlmfc/include" "${CFX_SDK}/Include/${CFX_WINSDK_VERSION}/cppwinrt"
  "${CFX_SOURCE_DIR}/code/vendor/cpp-url"
  "${CFX_SOURCE_DIR}/vendor/cpp-url/include" "${CFX_SOURCE_DIR}/vendor/range-v3/include"
  "${CFX_CEF_ROOT}")
target_link_directories(cfx_nui_options INTERFACE "${CFX_VC}/atlmfc/lib/x64")

file(GLOB_RECURSE cefWrapperSources CONFIGURE_DEPENDS
  "${CFX_CEF_GLOB_ROOT}/libcef_dll/*.cc" "${CFX_CEF_GLOB_ROOT}/libcef_dll/*.cpp")
set(cefLoggingOriginal "${CFX_CEF_ROOT}/libcef_dll/base/cef_logging.cc")
if(NOT EXISTS "${CFX_CEF_ROOT}/include/cef_version.h")
  message(FATAL_ERROR "Missing CEF version header")
endif()
file(STRINGS "${CFX_CEF_ROOT}/include/cef_version.h" cefVersionMajor REGEX "^#define CEF_VERSION_MAJOR [0-9]+$")
if(NOT cefVersionMajor STREQUAL "#define CEF_VERSION_MAJOR 103")
  file(READ "${cefLoggingOriginal}" cefLoggingCode)
  set(cefLoggingOld "static constexpr Implementation default_impl = {")
  string(FIND "${cefLoggingCode}" "${cefLoggingOld}" cefLoggingOffset)
  if(cefLoggingOffset LESS 0)
    message(FATAL_ERROR "CEF logger source changed; review the clang-cl dllimport constexpr adaptation")
  endif()
  string(REPLACE "${cefLoggingOld}" "static const Implementation default_impl = {" cefLoggingCode "${cefLoggingCode}")
  set(cefLoggingAdapted "${CMAKE_CURRENT_BINARY_DIR}/cef-compat/cef_logging.cc")
  file(GENERATE OUTPUT "${cefLoggingAdapted}" CONTENT "${cefLoggingCode}")
  list(REMOVE_ITEM cefWrapperSources "${cefLoggingOriginal}")
  list(APPEND cefWrapperSources "${cefLoggingAdapted}")
endif()
add_library(cfx_cef_wrapper STATIC ${cefWrapperSources})
target_include_directories(cfx_cef_wrapper PUBLIC "${CFX_CEF_ROOT}")
target_compile_definitions(cfx_cef_wrapper PRIVATE UNICODE _UNICODE USING_CEF_SHARED NOMINMAX WIN32 WRAPPING_CEF_SHARED DCHECK_ALWAYS_ON)
target_compile_options(cfx_cef_wrapper PRIVATE /EHsc /bigobj /utf-8)

file(GLOB zlibSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/zlib/*.c")
list(FILTER zlibSources EXCLUDE REGEX "/(example|minigzip)\\.c$")
add_library(cfx_nui_zlib STATIC ${zlibSources})
target_compile_definitions(cfx_nui_zlib PRIVATE WIN32)
target_include_directories(cfx_nui_zlib PUBLIC "${CFX_SOURCE_DIR}/vendor/zlib")
set(minizipNames mz_strm mz_strm_mem mz_strm_crc32 mz_strm_zlib mz_zip mz_zip_rw
  mz_os mz_os_win32 mz_strm_win32 mz_strm_buf mz_strm_split)
set(minizipSources)
foreach(name ${minizipNames})
  list(APPEND minizipSources "${CFX_SOURCE_DIR}/vendor/minizip/${name}.c")
endforeach()
add_library(cfx_nui_minizip STATIC ${minizipSources})
target_compile_definitions(cfx_nui_minizip PRIVATE HAVE_ZLIB)
target_include_directories(cfx_nui_minizip PUBLIC "${CFX_SOURCE_DIR}/vendor/minizip")
target_link_libraries(cfx_nui_minizip PUBLIC cfx_nui_zlib)

file(GLOB botanSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/vendor/botan/src/*.cpp")
add_library(cfx_nui_botan SHARED ${botanSources})
target_compile_definitions(cfx_nui_botan PRIVATE "BOTAN_DLL=__declspec(dllexport)" BOTAN_IS_BEING_BUILT _DISABLE_EXTENDED_ALIGNED_STORAGE)
target_include_directories(cfx_nui_botan PUBLIC "${CFX_SOURCE_DIR}/code/vendor/botan/include"
  PRIVATE "${CFX_SOURCE_DIR}/code/vendor/botan/include/external")
target_compile_options(cfx_nui_botan PRIVATE /EHsc /bigobj /clang:-mrdrnd /clang:-mrdseed)
target_link_libraries(cfx_nui_botan PRIVATE cfx_compiler_rt_builtins ws2_32 crypt32)
set_target_properties(cfx_nui_botan PROPERTIES PREFIX "" OUTPUT_NAME botan)

file(GLOB_RECURSE cppUrlSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/cpp-url/src/*.cpp")
list(APPEND cppUrlSources "${CFX_SOURCE_DIR}/code/vendor/cpp-url/range_workaround.cpp")
add_library(cfx_nui_cpp_url STATIC ${cppUrlSources})
target_link_libraries(cfx_nui_cpp_url PUBLIC cfx_nui_options)
target_include_directories(cfx_nui_cpp_url PRIVATE "${CFX_SOURCE_DIR}/vendor/cpp-url/src")
target_compile_options(cfx_nui_cpp_url PRIVATE /permissive-)

function(cfx_component target folder componentDir)
  string(REPLACE "[" "[[]" componentGlob "${componentDir}")
  file(GLOB_RECURSE componentSources CONFIGURE_DEPENDS
    "${componentGlob}/src/*.cpp"
    "${componentGlob}/src/*.cc")
  list(FILTER componentSources EXCLUDE REGEX "\\.Posix\\.cpp$")
  list(APPEND componentSources
    "${CFX_SOURCE_DIR}/code/client/common/StdInc.cpp"
    "${CFX_SOURCE_DIR}/code/client/common/Error.cpp"
    "${componentDir}/component.rc")
  string(TOUPPER "${folder}" exportName)
  string(REPLACE "-" "_" exportName "${exportName}")
  add_library(${target} SHARED ${componentSources})
  target_compile_definitions(${target} PRIVATE "COMPILING_${exportName}=1" HAS_LOCAL_H "_CFX_COMPONENT_NAME=${folder}")
  target_include_directories(${target} PUBLIC "${componentDir}/include" PRIVATE "${componentDir}")
  foreach(directory ${CFX_WIN_INCLUDE_DIRS})
    target_include_directories(${target} PRIVATE "$<$<COMPILE_LANGUAGE:RC>:${directory}>")
  endforeach()
  target_link_libraries(${target} PRIVATE Shared CoreRT cfx_nui_options)
  set_target_properties(${target} PROPERTIES PREFIX "" OUTPUT_NAME "${folder}")
  file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/${folder}-source-scope.txt" CONTENT
    "Full public Windows component source selection, no extra hard-unit exclusions, no server define, no startup proof.\nSources: ${componentSources}\n")
endfunction()

cfx_component(NuiNetBase net-base "${CFX_SOURCE_DIR}/code/components/net-base")
target_link_libraries(NuiNetBase PRIVATE ws2_32 dnsapi)
cfx_component(NuiVfsCore vfs-core "${CFX_SOURCE_DIR}/code/components/vfs-core")
target_link_libraries(NuiVfsCore PRIVATE cfx_nui_minizip cfx_nui_botan ole32)

cfx_component(NuiCore nui-core "${CFX_NUI_COMPONENT_DIR}")
set_source_files_properties("${CFX_NUI_COMPONENT_DIR}/src/NUIApp.cpp"
  PROPERTIES COMPILE_OPTIONS "/std:c++20")
target_link_libraries(NuiCore PRIVATE TBB::tbb cfx_cef_wrapper cfx_nui_cpp_url
  NuiNetBase NuiVfsCore cfx_minhook
  "${CFX_CEF_ROOT}/Release/libcef.lib"
  "${CFX_SOURCE_DIR}/code/deplibs/lib/libGLESv2.lib"
  "${CFX_SOURCE_DIR}/code/components/legitimacy/release/legitimacy.lib"
  delayimp psapi user32 gdi32 ole32 oleaut32 uuid shlwapi shell32 imm32
  d3d11 dxgi shcore windowscodecs runtimeobject comctl32 version winmm)
target_link_options(NuiCore PRIVATE /DELAYLOAD:libcef.dll
  /DELAYLOAD:api-ms-win-core-winrt-error-l1-1-1.dll /DELAYLOAD:api-ms-win-core-winrt-l1-1-0.dll
  /DELAYLOAD:api-ms-win-core-winrt-error-l1-1-0.dll /DELAYLOAD:api-ms-win-core-winrt-string-l1-1-0.dll /DELAYLOAD:ole32.dll)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/nui-artifacts.json" CONTENT
  "{\"nui\":\"$<TARGET_FILE:NuiCore>\",\"net\":\"$<TARGET_FILE:NuiNetBase>\",\"vfs\":\"$<TARGET_FILE:NuiVfsCore>\",\"botan\":\"$<TARGET_FILE:cfx_nui_botan>\",\"core\":\"$<TARGET_FILE:CoreRT>\",\"tbb\":\"$<TARGET_FILE:tbb>\"}\n")
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/cef-wrapper-source-scope.txt" CONTENT
  "All Cfx upstream-selected CEF libcef_dll .cc/.cpp files. Original Windows Cfx package; no generated replacement API. No runtime proof.\nSources: ${cefWrapperSources}\n")
add_executable(nui_load_probe load_probe.cpp)
target_include_directories(nui_load_probe PRIVATE "${CFX_CEF_ROOT}")
target_compile_definitions(nui_load_probe PRIVATE UNICODE _UNICODE)
set_target_properties(nui_load_probe PROPERTIES OUTPUT_NAME nui-load-probe)
