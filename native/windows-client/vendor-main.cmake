include_guard(GLOBAL)
if(NOT TARGET cfx_win_options)
  message(FATAL_ERROR "Initialize the existing Windows source toolchain/options before MAIN vendors")
endif()
string(REPLACE "[" "[[]" CFX_GLOB_ROOT "${CFX_SOURCE_DIR}")
get_filename_component(CFX_MAIN_PROJECT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(CFX_MAIN_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/main-vendor-generated")
file(MAKE_DIRECTORY "${CFX_MAIN_GENERATED}")
find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_library(cfx_main_options INTERFACE)
target_link_libraries(cfx_main_options INTERFACE cfx_win_options)

function(cfx_main_static target)
  add_library(${target} STATIC ${ARGN})
  target_link_libraries(${target} PUBLIC cfx_main_options)
  set_target_properties(${target} PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded)
endfunction()

# The source list follows the original Windows-x64/five openssl_ext.lua rules.
file(GLOB_RECURSE opensslBuildInfos CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/openssl/crypto/*build.info")
file(GLOB_RECURSE opensslPerlasmInputs CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/openssl/crypto/*.pl")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_LIST_DIR}/openssl_sources.py" "${CFX_SOURCE_DIR}/code/vendor/openssl_ext.lua"
  "${CFX_SOURCE_DIR}/code/vendor/openssl_cfg.lua" "${CFX_SOURCE_DIR}/vendor/openssl/ssl/build.info"
  "${CFX_SOURCE_DIR}/vendor/openssl/build.info" ${opensslBuildInfos})
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/openssl_sources.py"
  --source "${CFX_SOURCE_DIR}" --output "${CFX_MAIN_GENERATED}/openssl-sources.cmake"
  RESULT_VARIABLE opensslEnumerationResult COMMAND_ERROR_IS_FATAL ANY)
include("${CFX_MAIN_GENERATED}/openssl-sources.cmake")
set(opensslC)
set(opensslObjects)
option(CFX_MAIN_OPENSSL_PERLASM "Use original Win64 perlasm with native Clang COFF assembler" ON)
foreach(source IN LISTS CFX_MAIN_OPENSSL_CRYPTO_SOURCES)
  if(source MATCHES "\\.asm$")
    file(RELATIVE_PATH relative "${CFX_SOURCE_DIR}/code/vendor/openssl/asm" "${source}")
    string(REPLACE "/" "_" filename "${relative}")
    set(object "${CFX_MAIN_GENERATED}/openssl-asm/${filename}.obj")
    if(CFX_MAIN_OPENSSL_PERLASM)
      add_custom_command(OUTPUT "${object}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CFX_MAIN_GENERATED}/openssl-asm"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/openssl_perlasm.py"
          --source "${CFX_SOURCE_DIR}" --asm "${source}" --output "${object}" --clang "${CFX_LLVM_BIN}/clang"
        DEPENDS "${source}" "${CMAKE_CURRENT_LIST_DIR}/openssl_perlasm.py" ${opensslPerlasmInputs} ${opensslBuildInfos} VERBATIM)
    else()
      add_custom_command(OUTPUT "${object}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CFX_MAIN_GENERATED}/openssl-asm"
        COMMAND "${CFX_LLVM_ML}" -m64 /c "/Fo${object}" "${source}"
        DEPENDS "${source}" VERBATIM)
    endif()
    set_source_files_properties("${object}" PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
    list(APPEND opensslObjects "${object}")
  else()
    list(APPEND opensslC "${source}")
  endif()
endforeach()
cfx_main_static(cfx_main_openssl_crypto ${opensslC} ${opensslObjects})
cfx_main_static(cfx_main_openssl_ssl ${CFX_MAIN_OPENSSL_SSL_SOURCES})
foreach(target cfx_main_openssl_crypto cfx_main_openssl_ssl)
  target_include_directories(${target} PUBLIC
    "${CFX_SOURCE_DIR}/code/vendor/openssl" "${CFX_SOURCE_DIR}/vendor/openssl/include"
    PRIVATE "${CFX_SOURCE_DIR}/vendor/openssl" "${CFX_SOURCE_DIR}/vendor/openssl/crypto/include"
    "${CFX_SOURCE_DIR}/vendor/openssl/crypto/ec/curve448"
    "${CFX_SOURCE_DIR}/vendor/openssl/crypto/ec/curve448/arch_32"
    "${CFX_SOURCE_DIR}/vendor/openssl/crypto/modes")
  target_compile_definitions(${target} PUBLIC OPENSSL_NO_KRB5 PRIVATE
    NO_WINDOWS_BRAINDEATH WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_DEPRECATE
    OPENSSL_SYSNAME_WIN32 OPENSSL_NO_EC_NISTP_64_GCC_128 L_ENDIAN OPENSSL_EXPORT_VAR_AS_FUNCTION
    "OPENSSLDIR=\"C:\\\\Program Files\\\\Common Files\\\\SSL\""
    OPENSSL_NO_COMP OPENSSL_NO_CT OPENSSL_NO_JPAKE OPENSSL_NO_RC5 OPENSSL_NO_MD2
    OPENSSL_NO_ENGINE OPENSSL_NO_SCTP
    CPUID_ASM OPENSSL_BN_ASM_MONT OPENSSL_CPUID_OBJ SHA1_ASM SHA256_ASM SHA512_ASM GHASH_ASM
    VPAES_ASM BN_ASM BF_ASM BNCO_ASM DES_ASM LIB_BN_ASM MD5_ASM OPENSSL_BN_ASM RIP_ASM
    RMD160_ASM WHIRLPOOL_ASM WP_ASM)
endforeach()
target_link_libraries(cfx_main_openssl_crypto PUBLIC ws2_32 crypt32 advapi32 bcrypt)
target_link_libraries(cfx_main_openssl_ssl PUBLIC cfx_main_openssl_crypto)

# Use a distinct /MT archive for the unchanged LLVM UInt128 builtins.
if(NOT TARGET cfx_compiler_rt_builtins)
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../compiler-rt" "${CMAKE_CURRENT_BINARY_DIR}/main-compiler-rt" EXCLUDE_FROM_ALL)
endif()
get_target_property(mainBuiltinsSources cfx_compiler_rt_builtins SOURCES)
cfx_main_static(cfx_main_compiler_rt ${mainBuiltinsSources})
target_link_libraries(cfx_main_openssl_crypto PUBLIC cfx_main_compiler_rt)

file(READ "${CFX_SOURCE_DIR}/vendor/nghttp2/CMakeLists.txt" nghttp2Cmake)
string(REGEX MATCH "project\\(nghttp2 VERSION ([0-9]+)\\.([0-9]+)\\.([0-9]+)" nghttp2Version "${nghttp2Cmake}")
if(NOT nghttp2Version)
  message(FATAL_ERROR "Review the pinned nghttp2 version-generation rule")
endif()
set(PACKAGE_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}")
math(EXPR PACKAGE_VERSION_NUM "(${CMAKE_MATCH_1} << 16) | (${CMAKE_MATCH_2} << 8) | ${CMAKE_MATCH_3}" OUTPUT_FORMAT HEXADECIMAL)
file(MAKE_DIRECTORY "${CFX_MAIN_GENERATED}/nghttp2")
configure_file("${CFX_SOURCE_DIR}/vendor/nghttp2/lib/includes/nghttp2/nghttp2ver.h.in"
  "${CFX_MAIN_GENERATED}/nghttp2/nghttp2ver.h" @ONLY)
file(GLOB nghttp2Sources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/nghttp2/lib/*.c")
cfx_main_static(cfx_main_nghttp2 ${nghttp2Sources})
target_include_directories(cfx_main_nghttp2 PUBLIC "${CFX_SOURCE_DIR}/vendor/nghttp2/lib/includes" "${CFX_MAIN_GENERATED}")
target_compile_definitions(cfx_main_nghttp2 PUBLIC _SSIZE_T_DEFINED=1 "_U_=" NGHTTP2_STATICLIB "ssize_t=__int64")

file(GLOB_RECURSE curlSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/curl/lib/*.c")
set(curlOriginal "${CFX_SOURCE_DIR}/vendor/curl/lib/vtls/openssl.c")
set(curlCompatible "${CFX_MAIN_GENERATED}/curl/openssl.c")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_LIST_DIR}/prepare_main_overlays.py" "${curlOriginal}")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/prepare_main_overlays.py"
  --source "${CFX_SOURCE_DIR}" --output "${curlCompatible}" COMMAND_ERROR_IS_FATAL ANY)
list(REMOVE_ITEM curlSources "${curlOriginal}")
list(APPEND curlSources "${curlCompatible}")
cfx_main_static(cfx_main_curl ${curlSources})
target_include_directories(cfx_main_curl PUBLIC "${CFX_SOURCE_DIR}/vendor/curl/include" PRIVATE "${CFX_SOURCE_DIR}/vendor/curl/lib")
set_property(SOURCE "${curlCompatible}" APPEND PROPERTY INCLUDE_DIRECTORIES "${CFX_SOURCE_DIR}/vendor/curl/lib/vtls")
target_compile_definitions(cfx_main_curl PUBLIC CURL_STATICLIB PRIVATE
  BUILDING_LIBCURL USE_IPV6 USE_WINDOWS_SSPI USE_OPENSSL OPENSSL_NO_ENGINE USE_NGHTTP2
  CURL_DISABLE_TFTP CURL_DISABLE_FTP CURL_DISABLE_LDAP CURL_DISABLE_TELNET CURL_DISABLE_DICT
  CURL_DISABLE_RTSP CURL_DISABLE_POP3 CURL_DISABLE_IMAP CURL_DISABLE_SMTP CURL_DISABLE_RTMP
  CURL_DISABLE_GOPHER CURL_DISABLE_SMB)
target_link_libraries(cfx_main_curl PUBLIC cfx_main_openssl_ssl cfx_main_nghttp2 ws2_32 crypt32)
file(GLOB cprSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/cpr/cpr/*.cpp")
cfx_main_static(cfx_main_cpr ${cprSources})
target_include_directories(cfx_main_cpr PUBLIC "${CFX_SOURCE_DIR}/vendor/cpr/include" "${CFX_SOURCE_DIR}/code/vendor/cpr/include")
target_compile_definitions(cfx_main_cpr PUBLIC CURL_STATICLIB)
target_link_libraries(cfx_main_cpr PUBLIC cfx_main_curl)
file(GLOB_RECURSE mbedtlsSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/mbedtls/library/*.c")
cfx_main_static(cfx_main_mbedtls ${mbedtlsSources})
target_include_directories(cfx_main_mbedtls PUBLIC "${CFX_SOURCE_DIR}/vendor/mbedtls/include")
target_compile_definitions(cfx_main_mbedtls PRIVATE NATIVE_LITTLE_ENDIAN MBEDTLS_HAVEGE_C)

set(mainTbbNames address_waiter allocator arena arena_slot concurrent_bounded_queue dynamic_link
  exception governor global_control itt_notify main market misc misc_ex observer_proxy parallel_pipeline
  private_server profiling rml_tbb rtm_mutex rtm_rw_mutex semaphore small_object_pool task task_dispatcher
  task_group_context version queuing_rw_mutex)
set(mainTbbSources)
foreach(name ${mainTbbNames})
  list(APPEND mainTbbSources "${CFX_SOURCE_DIR}/vendor/tbb/src/tbb/${name}.cpp")
endforeach()
cfx_main_static(cfx_main_tbb ${mainTbbSources})
target_include_directories(cfx_main_tbb PUBLIC "${CFX_SOURCE_DIR}/vendor/tbb/include" PRIVATE
  "${CFX_SOURCE_DIR}/vendor/tbb/src" "${CFX_SOURCE_DIR}/vendor/tbb/src/rml/include" "${CFX_SOURCE_DIR}/vendor/tbb/build/vs2013")
target_compile_definitions(cfx_main_tbb PUBLIC __TBB_NO_IMPLICIT_LINKAGE=1 PRIVATE
  __TBB_BUILD __TBB_DYNAMIC_LOAD_ENABLED=0 _TBB_USE_DEBUG=0 _HAS_STD_BYTE=0 USE_WINTHREAD)
target_compile_options(cfx_main_tbb PRIVATE /U_WIN32_WINNT /D_WIN32_WINNT=0x0601 /clang:-mrtm /clang:-mwaitpkg)

set(mainBoostLocaleNames encoding/codepage shared/date_time shared/format shared/formatting shared/generator
  shared/ids shared/localization_backend shared/message shared/mo_lambda util/codecvt_converter util/default_locale
  util/encoding util/info util/locale_data win32/collate win32/converter win32/numeric win32/win_backend win32/lcid util/gregorian)
set(mainBoostLocaleSources)
foreach(name ${mainBoostLocaleNames})
  list(APPEND mainBoostLocaleSources "${CFX_SOURCE_DIR}/vendor/boost-submodules/boost-locale/src/boost/locale/${name}.cpp")
endforeach()
cfx_main_static(cfx_main_boost_locale ${mainBoostLocaleSources})
target_include_directories(cfx_main_boost_locale PRIVATE "${CFX_SOURCE_DIR}/vendor/boost-submodules/boost-locale/src")
target_compile_definitions(cfx_main_boost_locale PRIVATE BOOST_LOCALE_NO_STD_BACKEND BOOST_LOCALE_NO_POSIX_BACKEND)
set(mainBreakpadNames client/windows/handler/exception_handler.cc client/windows/crash_generation/client_info.cc
  client/windows/crash_generation/crash_generation_client.cc client/windows/crash_generation/crash_generation_server.cc
  client/windows/crash_generation/minidump_generator.cc common/windows/guid_string.cc common/windows/http_upload.cc common/windows/string_utils.cc)
set(mainBreakpadSources)
foreach(name ${mainBreakpadNames})
  list(APPEND mainBreakpadSources "${CFX_SOURCE_DIR}/vendor/breakpad/src/${name}")
endforeach()
cfx_main_static(cfx_main_breakpad ${mainBreakpadSources})
target_include_directories(cfx_main_breakpad PUBLIC "${CFX_SOURCE_DIR}/vendor/breakpad/src")

option(CFX_MAIN_INCLUDE_CODECS "Include the separately reviewed original MAIN codec graph" ON)
set(mainCodecTargets)
if(CFX_MAIN_INCLUDE_CODECS)
  include("${CMAKE_CURRENT_LIST_DIR}/vendor-codecs.cmake")
  list(APPEND mainCodecTargets cfx_main_codecs)
endif()
add_library(cfx_main_vendors INTERFACE)
target_link_libraries(cfx_main_vendors INTERFACE cfx_main_cpr cfx_main_mbedtls
  cfx_main_openssl_crypto cfx_main_tbb cfx_main_boost_locale cfx_main_breakpad ${mainCodecTargets})
add_custom_target(cfx_main_vendors_build DEPENDS cfx_main_curl cfx_main_cpr cfx_main_mbedtls
  cfx_main_openssl_crypto cfx_main_openssl_ssl cfx_main_nghttp2 cfx_main_tbb
  cfx_main_boost_locale cfx_main_breakpad cfx_main_compiler_rt ${mainCodecTargets})
