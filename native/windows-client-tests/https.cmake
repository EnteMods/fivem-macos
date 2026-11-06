cmake_minimum_required(VERSION 3.20)
project(CfxMainHttpsApiProbe LANGUAGES C CXX)
if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang"
   OR NOT CMAKE_CXX_COMPILER_TARGET STREQUAL "x86_64-pc-windows-msvc")
  message(FATAL_ERROR "Use the original Windows x64 clang-cl/MSVC-SDK toolchain")
endif()
foreach(name cpr curl openssl_ssl openssl_crypto nghttp2 compiler_rt)
  add_library(main_${name} STATIC IMPORTED)
  set_target_properties(main_${name} PROPERTIES IMPORTED_LOCATION "${CFX_MAIN_SNAPSHOT_DIR}/cfx_main_${name}.lib")
endforeach()
add_executable(main_https_probe "${CFX_PROJECT_ROOT}/native/windows-client-tests/https.cpp")
target_include_directories(main_https_probe PRIVATE "${CMAKE_BINARY_DIR}"
  "${CFX_PROJECT_ROOT}/port/fivem/vendor/cpr/include"
  "${CFX_PROJECT_ROOT}/port/fivem/code/vendor/cpr/include"
  "${CFX_PROJECT_ROOT}/port/fivem/vendor/curl/include"
  "${CFX_PROJECT_ROOT}/port/fivem/code/vendor/openssl"
  "${CFX_PROJECT_ROOT}/port/fivem/vendor/openssl/include")
target_compile_definitions(main_https_probe PRIVATE CURL_STATICLIB WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(main_https_probe PRIVATE main_cpr main_curl main_openssl_ssl main_openssl_crypto
  main_nghttp2 main_compiler_rt ws2_32 crypt32 advapi32 bcrypt)
target_link_options(main_https_probe PRIVATE "/MAP:${CMAKE_BINARY_DIR}/main-https-probe.map")
set_target_properties(main_https_probe PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
