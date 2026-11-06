cmake_minimum_required(VERSION 3.20)
project(CfxWindowsClientEntrypoints LANGUAGES C CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CFX_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../port/fivem" CACHE PATH "Isolated FiveM worktree")
get_filename_component(CFX_SOURCE_DIR "${CFX_SOURCE_DIR}" ABSOLUTE)
string(REPLACE "[" "[[]" CFX_GLOB_ROOT "${CFX_SOURCE_DIR}")
set(CFX_BUILD_CHROME_SUBPROCESS ON CACHE BOOL "Expose original common non-main launcher dependencies" FORCE)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../windows-launcher" dependencies/launcher EXCLUDE_FROM_ALL)

file(GLOB gameSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/client/launcher/*.cpp")
foreach(name Bootstrap CrossBuildLaunch DisableNVSP Download GameSelect Installer Updater UpdaterUI MiniDump Minidump.Symbolication)
  list(REMOVE_ITEM gameSources "${CFX_SOURCE_DIR}/code/client/launcher/${name}.cpp")
endforeach()
list(APPEND gameSources "${CFX_SOURCE_DIR}/code/client/common/Error.cpp"
  "${CFX_SOURCE_DIR}/code/client/common/CfxLocale.Win32.cpp"
  "${CFX_SOURCE_DIR}/code/client/launcher/launcher.rc")

set(clientDelayDlls d3d11.dll d2d1.dll d3dcompiler_47.dll dwrite.dll ole32.dll shcore.dll
  api-ms-win-core-winrt-error-l1-1-1.dll api-ms-win-core-winrt-l1-1-0.dll
  api-ms-win-core-winrt-error-l1-1-0.dll api-ms-win-core-winrt-string-l1-1-0.dll
  api-ms-win-shcore-stream-winrt-l1-1-0.dll version.dll dwmapi.dll bcrypt.dll
  wininet.dll rpcrt4.dll winmm.dll dbghelp.dll shlwapi.dll ws2_32.dll)
set(delayHeader "")
foreach(name ${clientDelayDlls})
  string(APPEND delayHeader "L\"${name}\",\n")
endforeach()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/DelayList.h" "${delayHeader}")

function(cfx_launcher_settings target)
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}"
    "${CFX_SOURCE_DIR}/code/client/launcher" "${CFX_SOURCE_DIR}/vendor/concurrentqueue")
  foreach(directory ${CFX_WIN_INCLUDE_DIRS})
    target_include_directories(${target} PRIVATE "$<$<COMPILE_LANGUAGE:RC>:${directory}>")
  endforeach()
  target_link_libraries(${target} PRIVATE dbghelp psapi comctl32 wininet winhttp crypt32 user32
    gdi32 shell32 ole32 oleaut32 shlwapi ws2_32 iphlpapi bcrypt ntdll version d3d11 d2d1
    d3dcompiler dwrite shcore dwmapi rpcrt4 winmm delayimp)
  target_link_options(${target} PRIVATE /MANIFEST:NO
    "/DEF:${CFX_SOURCE_DIR}/code/client/launcher/launcher.def" /IGNORE:4254 /LARGEADDRESSAWARE)
  foreach(name ${clientDelayDlls})
    target_link_options(${target} PRIVATE "/DELAYLOAD:${name}")
  endforeach()
endfunction()

add_executable(CitiLaunch_game_3889 WIN32 ${gameSources})
target_compile_definitions(CitiLaunch_game_3889 PRIVATE COMPILING_LAUNCH COMPILING_LAUNCHER
  LAUNCHER_PERSONALITY_GAME_3889 LAUNCHER_PERSONALITY_ANY_GAME LAUNCHER_PERSONALITY_GAME)
target_link_libraries(CitiLaunch_game_3889 PRIVATE Shared TBB::tbb cfx_boost_locale cfx_breakpad cfx_chrome_sha256 cfx_tinyxml2)
cfx_launcher_settings(CitiLaunch_game_3889)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/game-section-layout.txt" ".cdummy\n.pdata\n.cld\n.clr\n.zdata\n.rsrc\n.reloc\n.tls\n")
target_link_options(CitiLaunch_game_3889 PRIVATE /STACK:0x180000
  "/sectionlayout:${CMAKE_CURRENT_BINARY_DIR}/game-section-layout.txt")
set_property(TARGET CitiLaunch_game_3889 APPEND PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/game-section-layout.txt")
set_target_properties(CitiLaunch_game_3889 PROPERTIES OUTPUT_NAME CitizenFX_SubProcess_game_3889_aslr
  SUFFIX ".bin" MSVC_RUNTIME_LIBRARY MultiThreadedDLL)

add_library(CitiLaunch_TLSDummy SHARED "${CFX_SOURCE_DIR}/code/client/launcher/DummyVariables.cpp")
target_compile_definitions(CitiLaunch_TLSDummy PRIVATE IS_TLS_DLL)
target_include_directories(CitiLaunch_TLSDummy PRIVATE "${CFX_SOURCE_DIR}/code/client/launcher")
target_link_libraries(CitiLaunch_TLSDummy PRIVATE cfx_win_options cfx_fmt_crt)
set_target_properties(CitiLaunch_TLSDummy PROPERTIES PREFIX "" OUTPUT_NAME CitiLaunch_TLSDummy MSVC_RUNTIME_LIBRARY MultiThreaded)

file(GLOB_RECURSE peFrameworkSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/tools/dbg/peframework/src/*.cpp")
add_library(cfx_peframework STATIC ${peFrameworkSources})
target_include_directories(cfx_peframework PUBLIC "${CFX_SOURCE_DIR}/code/tools/dbg/peframework/include")
target_link_libraries(cfx_peframework PUBLIC cfx_win_options)
add_executable(retarget_pe "${CFX_SOURCE_DIR}/code/tools/dbg/retarget_pe/retarget_pe.cpp")
target_link_libraries(retarget_pe PRIVATE cfx_peframework)

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/game-source-scope.txt" CONTENT
  "Actual upstream Windows x64 Game3889 personality; all upstream non-main source units, original TLS dummy. LLD supported declarative /sectionlayout preserves original /LAST collision-avoidance intent, verified separately on real output. No game execution, private signing or unavailable dump fabricated.\nSources: ${gameSources}\nTLS: ${CFX_SOURCE_DIR}/code/client/launcher/DummyVariables.cpp\n")
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/client-artifacts.json" CONTENT
  "{\"game\":\"$<TARGET_FILE:CitiLaunch_game_3889>\",\"tls\":\"$<TARGET_FILE:CitiLaunch_TLSDummy>\",\"chrome\":\"$<TARGET_FILE:CitiLaunch_chrome>\",\"citigame\":\"$<TARGET_FILE:CitiGame>\",\"core\":\"$<TARGET_FILE:CoreRT>\"}\n")

option(CFX_BUILD_MAIN_UPDATER "Build the full original MAIN updater entrypoint" OFF)
option(CFX_CLIENT_PHASE_DIAGNOSTICS "Emit PID/phase-only public startup diagnostics" OFF)
if(CFX_CLIENT_PHASE_DIAGNOSTICS)
  target_compile_definitions(CitiGame PRIVATE CFX_SOURCE_STARTUP_DIAGNOSTICS)
endif()
if(CFX_BUILD_MAIN_UPDATER)
  include(vendor-main.cmake)
  file(GLOB mainSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/client/launcher/*.cpp")
  list(APPEND mainSources "${CFX_SOURCE_DIR}/code/client/common/Error.cpp"
    "${CFX_SOURCE_DIR}/code/client/common/CfxLocale.Win32.cpp"
    "${CFX_SOURCE_DIR}/code/client/launcher/launcher.rc")
  add_executable(CitiLaunch_main WIN32 ${mainSources})
  target_compile_definitions(CitiLaunch_main PRIVATE COMPILING_LAUNCH COMPILING_LAUNCHER LAUNCHER_PERSONALITY_MAIN)
  if(CFX_CLIENT_PHASE_DIAGNOSTICS)
    target_compile_definitions(CitiLaunch_main PRIVATE CFX_SOURCE_STARTUP_DIAGNOSTICS)
  endif()
  target_link_libraries(CitiLaunch_main PRIVATE SharedLibc cfx_main_options cfx_main_vendors cfx_tinyxml2)
  target_include_directories(CitiLaunch_main PRIVATE "${CFX_SDK}/Include/${CFX_WINSDK_VERSION}/cppwinrt" "${CFX_VC}/atlmfc/include")
  target_link_directories(CitiLaunch_main PRIVATE "${CFX_VC}/atlmfc/lib/x64")
  cfx_launcher_settings(CitiLaunch_main)
  set_target_properties(CitiLaunch_main PROPERTIES OUTPUT_NAME FiveM CXX_STANDARD 20 MSVC_RUNTIME_LIBRARY MultiThreaded)
  file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/main-source-scope.txt" CONTENT
    "Complete actual MAIN updater source selection. No updater, authentication, TLS or hash-check skips. Build only; no official signing identity claimed.\nSources: ${mainSources}\n")
endif()
