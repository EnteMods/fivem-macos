foreach(required vendor/tinyxml2/tinyxml2.cpp vendor/breakpad/src/client/windows/handler/exception_handler.cc vendor/openssl/crypto/sha/sha256.c)
  if(NOT EXISTS "${CFX_SOURCE_DIR}/${required}")
    message(FATAL_ERROR "Missing pinned Chrome build dependency: ${required}")
  endif()
endforeach()

add_library(cfx_tinyxml2 STATIC "${CFX_SOURCE_DIR}/vendor/tinyxml2/tinyxml2.cpp")
target_include_directories(cfx_tinyxml2 PUBLIC "${CFX_SOURCE_DIR}/vendor/tinyxml2")
set_target_properties(cfx_tinyxml2 PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded)

# These are all Windows Breakpad units selected by upstream code/vendor/breakpad.lua.
set(breakpadNames
  client/windows/handler/exception_handler.cc
  client/windows/crash_generation/client_info.cc
  client/windows/crash_generation/crash_generation_client.cc
  client/windows/crash_generation/crash_generation_server.cc
  client/windows/crash_generation/minidump_generator.cc
  common/windows/guid_string.cc
  common/windows/http_upload.cc
  common/windows/string_utils.cc)
set(breakpadSources)
foreach(name ${breakpadNames})
  list(APPEND breakpadSources "${CFX_SOURCE_DIR}/vendor/breakpad/src/${name}")
endforeach()
add_library(cfx_breakpad STATIC ${breakpadSources})
target_include_directories(cfx_breakpad PUBLIC "${CFX_SOURCE_DIR}/vendor/breakpad/src")
target_link_libraries(cfx_breakpad PUBLIC cfx_win_options)

# Chrome's snapshot source calls SHA256 only. Compile the original OpenSSL C
# implementation and its real cleansing routine; no replacement digest or TLS code.
add_library(cfx_chrome_sha256 STATIC
  "${CFX_SOURCE_DIR}/vendor/openssl/crypto/sha/sha256.c"
  "${CFX_SOURCE_DIR}/vendor/openssl/crypto/mem_clr.c")
target_include_directories(cfx_chrome_sha256 PUBLIC
  "${CFX_SOURCE_DIR}/code/vendor/openssl" "${CFX_SOURCE_DIR}/vendor/openssl/include"
  PRIVATE "${CFX_SOURCE_DIR}/vendor/openssl" "${CFX_SOURCE_DIR}/vendor/openssl/crypto/include")
target_compile_definitions(cfx_chrome_sha256 PRIVATE OPENSSL_SYSNAME_WIN32 OPENSSL_NO_EC_NISTP_64_GCC_128 L_ENDIAN)

file(GLOB chromeSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/client/launcher/*.cpp")
set(mainOnlySources Bootstrap CrossBuildLaunch DisableNVSP Download GameSelect Installer Updater UpdaterUI MiniDump Minidump.Symbolication)
foreach(name ${mainOnlySources})
  list(REMOVE_ITEM chromeSources "${CFX_SOURCE_DIR}/code/client/launcher/${name}.cpp")
endforeach()
list(APPEND chromeSources
  "${CFX_SOURCE_DIR}/code/client/common/Error.cpp"
  "${CFX_SOURCE_DIR}/code/client/common/CfxLocale.Win32.cpp"
  "${CFX_SOURCE_DIR}/code/client/launcher/launcher.rc")

set(chromeDelayDlls d3d11.dll d2d1.dll d3dcompiler_47.dll dwrite.dll ole32.dll shcore.dll
  api-ms-win-core-winrt-error-l1-1-1.dll api-ms-win-core-winrt-l1-1-0.dll
  api-ms-win-core-winrt-error-l1-1-0.dll api-ms-win-core-winrt-string-l1-1-0.dll
  api-ms-win-shcore-stream-winrt-l1-1-0.dll version.dll dwmapi.dll bcrypt.dll
  wininet.dll rpcrt4.dll winmm.dll dbghelp.dll shlwapi.dll ws2_32.dll)
set(delayHeader "")
foreach(name ${chromeDelayDlls})
  string(APPEND delayHeader "L\"${name}\",\n")
endforeach()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/DelayList.h" "${delayHeader}")
add_executable(CitiLaunch_chrome WIN32 ${chromeSources})
target_compile_definitions(CitiLaunch_chrome PRIVATE COMPILING_LAUNCH COMPILING_LAUNCHER LAUNCHER_PERSONALITY_CHROME)
target_include_directories(CitiLaunch_chrome PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}" "${CFX_SOURCE_DIR}/code/client/launcher"
  "${CFX_SOURCE_DIR}/vendor/concurrentqueue")
foreach(folder ${CFX_WIN_INCLUDE_DIRS})
  target_include_directories(CitiLaunch_chrome PRIVATE "$<$<COMPILE_LANGUAGE:RC>:${folder}>")
endforeach()
target_link_libraries(CitiLaunch_chrome PRIVATE Shared TBB::tbb cfx_boost_locale cfx_breakpad cfx_chrome_sha256 cfx_tinyxml2
  dbghelp psapi comctl32 wininet winhttp crypt32 user32 gdi32 shell32 ole32 oleaut32
  shlwapi ws2_32 iphlpapi bcrypt ntdll version d3d11 d2d1 d3dcompiler dwrite shcore dwmapi rpcrt4 winmm delayimp)
target_link_options(CitiLaunch_chrome PRIVATE
  /MANIFEST:NO "/DEF:${CFX_SOURCE_DIR}/code/client/launcher/launcher.def"
  /IGNORE:4254 /LARGEADDRESSAWARE /STACK:0x800000)
foreach(name ${chromeDelayDlls})
  target_link_options(CitiLaunch_chrome PRIVATE "/DELAYLOAD:${name}")
endforeach()
set_target_properties(CitiLaunch_chrome PROPERTIES OUTPUT_NAME CitizenFX_SubProcess_chrome SUFFIX ".bin" MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/chrome-source-scope.txt" CONTENT
  "Actual upstream WinMain Chrome subprocess. All launcher C++ units except exactly 10 upstream main-only exclusions. Breakpad Windows selection complete; pinned OpenSSL SHA256 C implementation subset, not full libcrypto. No client, CEF, login or game runtime proof.\nSources: ${chromeSources}\nBreakpad: ${breakpadSources}\n")

set(citiGameSources
  "${CFX_SOURCE_DIR}/code/client/common/Error.cpp"
  "${CFX_SOURCE_DIR}/code/client/citigame/Launcher.cpp"
  "${CFX_SOURCE_DIR}/code/client/citigame/NvCacheWorkaround.cpp"
  "${CFX_SOURCE_DIR}/code/client/common/StdInc.cpp")
add_library(CitiGame SHARED ${citiGameSources})
target_compile_definitions(CitiGame PRIVATE COMPILING_GAME)
target_include_directories(CitiGame PRIVATE "${CFX_SOURCE_DIR}/vendor/nvapi")
target_link_libraries(CitiGame PRIVATE Shared CoreRT
  "${CFX_SOURCE_DIR}/vendor/nvapi/amd64/nvapi64.lib" user32 shell32 advapi32)
set_target_properties(CitiGame PROPERTIES PREFIX "" OUTPUT_NAME CitizenGame MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/citigame-source-scope.txt" CONTENT
  "Actual full public CitiGame source selection from code/premake5.lua:321-344; original tracked NVAPI64 lib, no stubs or security changes. Runtime not tested.\nSources: ${citiGameSources}\n")
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/chrome-artifacts.json" CONTENT
  "{\"chrome\":\"$<TARGET_FILE:CitiLaunch_chrome>\",\"citigame\":\"$<TARGET_FILE:CitiGame>\",\"core\":\"$<TARGET_FILE:CoreRT>\",\"tbb\":\"$<TARGET_FILE:tbb>\"}\n")
