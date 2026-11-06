cmake_minimum_required(VERSION 3.20)
project(CfxUpstreamConsole LANGUAGES C CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CFX_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../port/fivem" CACHE PATH "Isolated FiveM source")
get_filename_component(CFX_SOURCE_DIR "${CFX_SOURCE_DIR}" ABSOLUTE)
string(REPLACE "[" "[[]" CFX_GLOB_ROOT "${CFX_SOURCE_DIR}")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../windows-core" dependencies/core EXCLUDE_FROM_ALL)

# Upstream CitiCon requires the independent static-runtime SharedLibc variant.
add_library(cfx_fmt_crt STATIC "${CFX_SOURCE_DIR}/vendor/fmtlib/src/format.cc" "${CFX_SOURCE_DIR}/vendor/fmtlib/src/os.cc")
target_include_directories(cfx_fmt_crt PUBLIC "${CFX_SOURCE_DIR}/vendor/fmtlib/include")
set_target_properties(cfx_fmt_crt PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded)
add_library(cfx_minhook_crt STATIC
  "${CFX_SOURCE_DIR}/vendor/minhook/src/buffer.c"
  "${CFX_SOURCE_DIR}/vendor/minhook/src/hook.c"
  "${CFX_SOURCE_DIR}/vendor/minhook/src/trampoline.c"
  "${CFX_SOURCE_DIR}/vendor/minhook/src/HDE/hde64.c")
target_link_libraries(cfx_minhook_crt PUBLIC cfx_win_options)
set_target_properties(cfx_minhook_crt PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded)
file(GLOB sharedLibcSources CONFIGURE_DEPENDS
  "${CFX_GLOB_ROOT}/code/client/shared/*.cpp" "${CFX_GLOB_ROOT}/code/shared/*.cpp")
list(FILTER sharedLibcSources EXCLUDE REGEX "\\.Posix\\.cpp$")
set(sharedLibcAsm "${CMAKE_CURRENT_BINARY_DIR}/AsmUtils.SharedLibc.Win32.obj")
add_custom_command(OUTPUT "${sharedLibcAsm}"
  COMMAND "${CFX_LLVM_ML}" -m64 /c "/Fo${sharedLibcAsm}" "${CFX_SOURCE_DIR}/code/client/shared/AsmUtils.Win32.asm"
  DEPENDS "${CFX_SOURCE_DIR}/code/client/shared/AsmUtils.Win32.asm" VERBATIM)
set_source_files_properties("${sharedLibcAsm}" PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
add_library(SharedLibc STATIC ${sharedLibcSources} "${sharedLibcAsm}")
add_dependencies(SharedLibc cfx_udis_tables)
target_compile_definitions(SharedLibc PRIVATE COMPILING_SHARED COMPILING_SHARED_LIBC)
target_link_libraries(SharedLibc PUBLIC cfx_win_options cfx_fmt_crt cfx_minhook_crt)
set_target_properties(SharedLibc PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded)

file(GLOB consoleSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/client/console/*.cpp")
list(APPEND consoleSources "${CFX_SOURCE_DIR}/code/client/common/Error.cpp")
add_executable(CitiCon ${consoleSources})
target_compile_definitions(CitiCon PRIVATE COMPILING_CONSOLE)
target_link_libraries(CitiCon PRIVATE SharedLibc kernel32 user32 advapi32 shell32 ntdll)
target_link_options(CitiCon PRIVATE /ENTRY:wmainCRTStartup)
set_target_properties(CitiCon PROPERTIES OUTPUT_NAME FiveM SUFFIX ".com" MSVC_RUNTIME_LIBRARY MultiThreaded)

# Own fixture exercises the real upstream ToolMode_Init dispatcher, not a game component.
add_library(CitiConFixture SHARED tool_fixture.cpp)
target_link_libraries(CitiConFixture PRIVATE CoreRT Shared cfx_boost_program_options)
set_target_properties(CitiConFixture PROPERTIES PREFIX "" OUTPUT_NAME probe-tool MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
add_dependencies(CitiConFixture CoreRT)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/tool-fixture.json"
  "{\"name\":\"probe:tool\",\"version\":\"1.0.0.0\",\"dependencies\":[],\"provides\":[],\"shouldAutoInstance\":false}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/tool-fixture.rc"
  "FXCOMPONENT 115 \"${CMAKE_CURRENT_BINARY_DIR}/tool-fixture.json\"\n")
target_sources(CitiConFixture PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/tool-fixture.rc")
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/launch-artifacts.json" CONTENT
  "{\"console\":\"$<TARGET_FILE:CitiCon>\",\"core\":\"$<TARGET_FILE:CoreRT>\",\"tbb\":\"$<TARGET_FILE:tbb>\",\"fixture\":\"$<TARGET_FILE:CitiConFixture>\"}\n")
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/console-source-scope.txt" CONTENT
  "Actual upstream client/console entrypoint, /MT SharedLibc, /MD CoreRT. Tool-only, no GUI/game/auth proof.\nConsole: ${consoleSources}\nSharedLibc: ${sharedLibcSources}\n")

option(CFX_BUILD_CHROME_SUBPROCESS "Build the genuine upstream non-main Chrome WinMain target" OFF)
if(CFX_BUILD_CHROME_SUBPROCESS)
  include(chrome.cmake)
endif()
