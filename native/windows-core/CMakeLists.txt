cmake_minimum_required(VERSION 3.20)
project(CfxWindowsCore LANGUAGES C CXX RC)
if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Use the supplied x64 Windows clang-cl SDK toolchain; this is not a native macOS client build.")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
set(CFX_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../port/fivem" CACHE PATH "Isolated FiveM source worktree")
get_filename_component(CFX_SOURCE_DIR "${CFX_SOURCE_DIR}" ABSOLUTE)
string(REPLACE "[" "[[]" CFX_GLOB_ROOT "${CFX_SOURCE_DIR}")
set(CFX_LLVM_ML "${CFX_LLVM_BIN}/llvm-ml" CACHE FILEPATH "Native MASM-compatible assembler")
set(CFX_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${CFX_GENERATED}/udis86/libudis86")

foreach(required vendor/fmtlib/CMakeLists.txt vendor/tbb/CMakeLists.txt vendor/rapidjson/include/rapidjson/document.h vendor/utfcpp/source/utf8.h vendor/jitasm/jitasm.h vendor/minhook/include/MinHook.h vendor/udis86/scripts/ud_itab.py)
  if(NOT EXISTS "${CFX_SOURCE_DIR}/${required}")
    message(FATAL_ERROR "Missing pinned dependency ${required}")
  endif()
endforeach()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(GLOB udisScripts "${CFX_GLOB_ROOT}/vendor/udis86/scripts/*.py")
add_custom_command(
  OUTPUT "${CFX_GENERATED}/udis86/libudis86/itab.c" "${CFX_GENERATED}/udis86/libudis86/itab.h"
  COMMAND "${Python3_EXECUTABLE}" "${CFX_SOURCE_DIR}/vendor/udis86/scripts/ud_itab.py"
    "${CFX_SOURCE_DIR}/vendor/udis86/docs/x86/optable.xml" "${CFX_GENERATED}/udis86/libudis86"
  DEPENDS ${udisScripts} "${CFX_SOURCE_DIR}/vendor/udis86/docs/x86/optable.xml"
  VERBATIM)
add_custom_target(cfx_udis_tables DEPENDS "${CFX_GENERATED}/udis86/libudis86/itab.c" "${CFX_GENERATED}/udis86/libudis86/itab.h")

file(GLOB boostIncludes "${CFX_GLOB_ROOT}/vendor/boost-submodules/*/include")
add_library(cfx_win_options INTERFACE)
target_include_directories(cfx_win_options INTERFACE
  "${CFX_SOURCE_DIR}/code/client/shared" "${CFX_SOURCE_DIR}/code/client/citicore"
  "${CFX_SOURCE_DIR}/code/shared" "${CFX_SOURCE_DIR}/code/deplibs/include"
  "${CFX_SOURCE_DIR}/vendor/rapidjson/include" "${CFX_SOURCE_DIR}/vendor/utfcpp/source"
  "${CFX_SOURCE_DIR}/vendor/jitasm" "${CFX_SOURCE_DIR}/vendor/minhook/include"
  "${CFX_SOURCE_DIR}/vendor/udis86" "${CFX_GENERATED}/udis86" "${CFX_GENERATED}/udis86/libudis86"
  ${boostIncludes})
target_compile_definitions(cfx_win_options INTERFACE
  UNICODE _UNICODE BOOST_ALL_NO_LIB BOOST_NULLPTR=nullptr _HAS_AUTO_PTR_ETC
  _PPLTASK_ASYNC_LOGGING=0 _CRT_SECURE_NO_WARNINGS
  _WIN32_WINNT=0x0A00 WINVER=0x0A00 GTA_FIVE
  "GAME_BUILDS=(1)(1604)(2060)(2189)(2372)(2545)(2612)(2699)(2802)(2944)(3095)(3258)(3323)(3407)(3570)(3751)(3788)(3889)")
target_compile_options(cfx_win_options INTERFACE "$<$<COMPILE_LANGUAGE:CXX>:/EHsc>" "$<$<COMPILE_LANGUAGE:CXX>:/clang:-fno-operator-names>" /utf-8 /bigobj /Zc:__cplusplus)

set(FMT_TEST OFF CACHE BOOL "" FORCE)
set(FMT_DOC OFF CACHE BOOL "" FORCE)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory("${CFX_SOURCE_DIR}/vendor/fmtlib" dependencies/fmt)
set(TBB_TEST OFF CACHE BOOL "" FORCE)
set(TBB_EXAMPLES OFF CACHE BOOL "" FORCE)
set(TBB_STRICT OFF CACHE BOOL "" FORCE)
set(TBBMALLOC_BUILD OFF CACHE BOOL "" FORCE)
set(TBB_ENABLE_IPO OFF CACHE BOOL "" FORCE)
include("${CFX_SOURCE_DIR}/vendor/tbb/cmake/utils.cmake")
include("${CFX_SOURCE_DIR}/vendor/tbb/cmake/config_generation.cmake")
include("${CFX_SOURCE_DIR}/vendor/tbb/cmake/vars_utils.cmake")
add_subdirectory("${CFX_SOURCE_DIR}/vendor/tbb" dependencies/tbb)

file(GLOB udisSources "${CFX_GLOB_ROOT}/vendor/udis86/libudis86/*.c")
list(FILTER udisSources EXCLUDE REGEX "/itab\\.c$")
add_library(cfx_udis86 STATIC ${udisSources} "${CFX_GENERATED}/udis86/libudis86/itab.c")
add_dependencies(cfx_udis86 cfx_udis_tables)
target_link_libraries(cfx_udis86 PUBLIC cfx_win_options)
target_compile_definitions(cfx_udis86 PRIVATE HAVE_STRING_H=1)
target_include_directories(cfx_udis86 PRIVATE "${CFX_SOURCE_DIR}/vendor/udis86/libudis86")
add_library(cfx_minhook STATIC
  "${CFX_SOURCE_DIR}/vendor/minhook/src/buffer.c"
  "${CFX_SOURCE_DIR}/vendor/minhook/src/hook.c"
  "${CFX_SOURCE_DIR}/vendor/minhook/src/trampoline.c"
  "${CFX_SOURCE_DIR}/vendor/minhook/src/HDE/hde64.c")
target_link_libraries(cfx_minhook PUBLIC cfx_win_options)

set(boostProgramOptionNames cmdline config_file convert options_description parsers positional_options split utf8_codecvt_facet value_semantic variables_map winmain)
set(boostProgramOptionsSources)
foreach(name ${boostProgramOptionNames})
  list(APPEND boostProgramOptionsSources "${CFX_SOURCE_DIR}/vendor/boost-submodules/boost-program-options/src/${name}.cpp")
endforeach()
add_library(cfx_boost_program_options STATIC ${boostProgramOptionsSources})
target_link_libraries(cfx_boost_program_options PUBLIC cfx_win_options)
set(boostLocaleNames
  encoding/codepage shared/date_time shared/format shared/formatting shared/generator shared/ids
  shared/localization_backend shared/message shared/mo_lambda util/codecvt_converter util/default_locale
  util/encoding util/info util/locale_data win32/collate win32/converter win32/numeric win32/win_backend
  win32/lcid util/gregorian)
set(boostLocaleSources)
foreach(name ${boostLocaleNames})
  list(APPEND boostLocaleSources "${CFX_SOURCE_DIR}/vendor/boost-submodules/boost-locale/src/boost/locale/${name}.cpp")
endforeach()
add_library(cfx_boost_locale STATIC ${boostLocaleSources})
target_link_libraries(cfx_boost_locale PUBLIC cfx_win_options)
target_include_directories(cfx_boost_locale PRIVATE "${CFX_SOURCE_DIR}/vendor/boost-submodules/boost-locale/src")
target_compile_definitions(cfx_boost_locale PRIVATE BOOST_LOCALE_NO_STD_BACKEND BOOST_LOCALE_NO_POSIX_BACKEND)

file(GLOB sharedSources CONFIGURE_DEPENDS
  "${CFX_GLOB_ROOT}/code/client/shared/*.cpp" "${CFX_GLOB_ROOT}/code/shared/*.cpp")
list(FILTER sharedSources EXCLUDE REGEX "\\.Posix\\.cpp$")
set(asmObject "${CMAKE_CURRENT_BINARY_DIR}/AsmUtils.Win32.obj")
add_custom_command(OUTPUT "${asmObject}"
  COMMAND "${CFX_LLVM_ML}" -m64 /c "/Fo${asmObject}" "${CFX_SOURCE_DIR}/code/client/shared/AsmUtils.Win32.asm"
  DEPENDS "${CFX_SOURCE_DIR}/code/client/shared/AsmUtils.Win32.asm" VERBATIM)
set_source_files_properties("${asmObject}" PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
add_library(Shared STATIC ${sharedSources} "${asmObject}")
add_dependencies(Shared cfx_udis_tables)
target_compile_definitions(Shared PRIVATE COMPILING_SHARED)
target_link_libraries(Shared PUBLIC cfx_win_options fmt::fmt cfx_minhook)

file(GLOB_RECURSE coreSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/code/client/citicore/*.cpp")
list(FILTER coreSources EXCLUDE REGEX "\\.Posix\\.cpp$")
list(APPEND coreSources
  "${CFX_SOURCE_DIR}/code/client/common/Error.cpp"
  "${CFX_SOURCE_DIR}/code/client/common/StdInc.cpp"
  "${CFX_SOURCE_DIR}/code/client/common/CfxLocale.Win32.cpp")
add_library(CoreRT SHARED ${coreSources})
add_dependencies(CoreRT cfx_udis_tables)
target_compile_definitions(CoreRT PRIVATE COMPILING_CORE)
target_link_libraries(CoreRT PRIVATE Shared TBB::tbb cfx_udis86 cfx_boost_program_options cfx_boost_locale
  user32 gdi32 advapi32 shell32 ole32 oleaut32 shlwapi ws2_32 iphlpapi psapi dbghelp bcrypt ntdll comctl32 version d3dcompiler winmm)
set_target_properties(CoreRT PROPERTIES PREFIX "" OUTPUT_NAME CoreRT)
option(CFX_CORE_MAPPING_DIAGNOSTICS "Emit fixed-field opt-in socialclub.dll mapping diagnostics" OFF)
if(CFX_CORE_MAPPING_DIAGNOSTICS)
  target_compile_definitions(CoreRT PRIVATE CFX_CORE_MAPPING_DIAGNOSTICS)
endif()
option(CFX_CORE_ACCOUNT_FREE_TESTS "Add explicit test instrumentation and local-only fixture executables" OFF)
if(CFX_CORE_ACCOUNT_FREE_TESTS)
  target_sources(CoreRT PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../windows-tests/core_dll_entry.cpp")
  add_library(windows_fixture SHARED "${CMAKE_CURRENT_SOURCE_DIR}/../windows-tests/core_dll_fixture.cpp")
  target_link_libraries(windows_fixture PRIVATE Shared)
  set_target_properties(windows_fixture PROPERTIES PREFIX "" OUTPUT_NAME "windows-fixture")
  file(WRITE "${CFX_GENERATED}/fixture.json"
    "{\"name\":\"windows:fixture\",\"version\":\"1.2.3.0\",\"provides\":[],\"dependencies\":[],\"shouldAutoInstance\":false}")
  file(WRITE "${CFX_GENERATED}/fixture.rc" "FXCOMPONENT 115 \"${CFX_GENERATED}/fixture.json\"\n")
  target_sources(windows_fixture PRIVATE "${CFX_GENERATED}/fixture.rc")
  add_executable(corert_full_probe "${CMAKE_CURRENT_SOURCE_DIR}/../windows-tests/core_dll_probe.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../windows-tests/handled_seh.c")
  target_link_libraries(corert_full_probe PRIVATE cfx_win_options)
endif()
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/source-scope.txt" CONTENT
  "Scope: full public Windows x64 CoreRT + Shared source selection with GTA_FIVE, /MD; no IS_FXSERVER. Not a complete FiveM client or successful runtime proof.\nShared sources: ${sharedSources}\nCoreRT sources: ${coreSources}\n")
