cmake_minimum_required(VERSION 3.20)
project(CfxMainVendorBuild LANGUAGES C CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
get_filename_component(CFX_PROJECT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(CFX_SOURCE_DIR "${CFX_PROJECT}/port/fivem" CACHE PATH "Pinned public source worktree")
add_subdirectory("${CFX_PROJECT}/native/windows-launcher" dependencies/launcher EXCLUDE_FROM_ALL)
include("${CMAKE_CURRENT_SOURCE_DIR}/../vendor-main.cmake")
add_executable(cfx_main_vendor_link_probe link_probe.c)
set_target_properties(cfx_main_vendor_link_probe PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded)
target_link_libraries(cfx_main_vendor_link_probe PRIVATE cfx_main_vendors
  kernel32 user32 advapi32 shell32 ole32 oleaut32 wininet winhttp dbghelp psapi
  crypt32 bcrypt ntdll ws2_32 secur32 winmm iphlpapi)
foreach(target cfx_main_openssl_crypto cfx_main_openssl_ssl cfx_main_nghttp2 cfx_main_curl
    cfx_main_cpr cfx_main_mbedtls cfx_main_tbb cfx_main_boost_locale cfx_main_breakpad
    cfx_main_compiler_rt cfx_main_xz cfx_main_zstd cfx_main_zlib cfx_main_minizip cfx_main_hdiffpatch)
  if(TARGET ${target})
    target_link_options(cfx_main_vendor_link_probe PRIVATE "/WHOLEARCHIVE:$<TARGET_FILE:${target}>")
  endif()
endforeach()
