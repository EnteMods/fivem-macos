include_guard(GLOBAL)
if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Main codecs require the original Windows x64 SDK toolchain")
endif()
if(NOT DEFINED CFX_SOURCE_DIR)
  message(FATAL_ERROR "CFX_SOURCE_DIR must point at the pinned public source worktree")
endif()
if(NOT DEFINED CFX_GLOB_ROOT)
  string(REPLACE "[" "[[]" CFX_GLOB_ROOT "${CFX_SOURCE_DIR}")
endif()
foreach(required vendor/xz/windows/vs2019/config.h vendor/zstd/lib/zstd.h
    vendor/zlib/zlib.h vendor/minizip/mz_zip_rw.c
    vendor/hdiffpatch/libHDiffPatch/HPatch/patch.c)
  if(NOT EXISTS "${CFX_SOURCE_DIR}/${required}")
    message(FATAL_ERROR "Missing pinned Main codec dependency: ${required}")
  endif()
endforeach()

# Source selection follows code/vendor/{xz,zstd,zlib,minizip,hdiffpatch}[-crt].lua.
file(GLOB_RECURSE mainXzSources CONFIGURE_DEPENDS
  "${CFX_GLOB_ROOT}/vendor/xz/src/liblzma/*.c")
list(FILTER mainXzSources EXCLUDE REGEX "/(crc32_small|crc64_small|[^/]*_tablegen)\\.c$")
list(APPEND mainXzSources "${CFX_SOURCE_DIR}/vendor/xz/src/common/tuklib_physmem.c"
  "${CFX_SOURCE_DIR}/vendor/xz/src/common/tuklib_cpucores.c")
add_library(cfx_main_xz STATIC ${mainXzSources})
target_compile_definitions(cfx_main_xz PRIVATE
  HAVE_STDINT_H=1 HAVE_CONFIG_H=1 HAVE_USABLE_CLMUL=1)
target_include_directories(cfx_main_xz PUBLIC "${CFX_SOURCE_DIR}/vendor/xz/src/liblzma/api"
  PRIVATE "${CFX_SOURCE_DIR}/vendor/xz/windows"
    "${CFX_SOURCE_DIR}/vendor/xz/windows/vs2019"
    "${CFX_SOURCE_DIR}/vendor/xz/src/common")
foreach(folder common check delta lz lzma rangecoder simple)
  target_include_directories(cfx_main_xz PRIVATE "${CFX_SOURCE_DIR}/vendor/xz/src/liblzma/${folder}")
endforeach()

file(GLOB mainZstdSources CONFIGURE_DEPENDS
  "${CFX_GLOB_ROOT}/vendor/zstd/lib/common/*.c"
  "${CFX_GLOB_ROOT}/vendor/zstd/lib/decompress/*.c")
add_library(cfx_main_zstd STATIC ${mainZstdSources})
target_include_directories(cfx_main_zstd PUBLIC "${CFX_SOURCE_DIR}/vendor/zstd/lib")
target_compile_definitions(cfx_main_zstd PRIVATE ZSTD_MULTITHREAD)

file(GLOB mainZlibSources CONFIGURE_DEPENDS "${CFX_GLOB_ROOT}/vendor/zlib/*.c")
list(FILTER mainZlibSources EXCLUDE REGEX "/(example|minigzip)\\.c$")
add_library(cfx_main_zlib STATIC ${mainZlibSources})
target_include_directories(cfx_main_zlib PUBLIC "${CFX_SOURCE_DIR}/vendor/zlib")
target_compile_definitions(cfx_main_zlib PRIVATE WIN32)

set(mainMinizipSources)
foreach(name mz_strm mz_strm_mem mz_strm_crc32 mz_strm_zlib mz_zip mz_zip_rw
    mz_os mz_os_win32 mz_strm_win32 mz_strm_buf mz_strm_split)
  list(APPEND mainMinizipSources "${CFX_SOURCE_DIR}/vendor/minizip/${name}.c")
endforeach()
add_library(cfx_main_minizip STATIC ${mainMinizipSources})
target_include_directories(cfx_main_minizip PUBLIC "${CFX_SOURCE_DIR}/vendor/minizip")
target_compile_definitions(cfx_main_minizip PRIVATE HAVE_ZLIB)
target_link_libraries(cfx_main_minizip PUBLIC cfx_main_zlib)

file(GLOB_RECURSE mainHdiffSources CONFIGURE_DEPENDS
  "${CFX_GLOB_ROOT}/vendor/hdiffpatch/libHDiffPatch/HPatch/*.c")
add_library(cfx_main_hdiffpatch STATIC ${mainHdiffSources})
target_include_directories(cfx_main_hdiffpatch PUBLIC
  "${CFX_SOURCE_DIR}/vendor/hdiffpatch/libHDiffPatch/HPatch")

add_library(cfx_main_codecs INTERFACE)
set(mainCodecTargets cfx_main_xz cfx_main_zstd cfx_main_zlib cfx_main_minizip cfx_main_hdiffpatch)
foreach(target ${mainCodecTargets})
  set_target_properties(${target} PROPERTIES MSVC_RUNTIME_LIBRARY MultiThreaded)
  if(TARGET cfx_main_options)
    target_link_libraries(${target} PUBLIC cfx_main_options)
  elseif(TARGET cfx_win_options)
    target_link_libraries(${target} PUBLIC cfx_win_options)
  endif()
  target_link_libraries(cfx_main_codecs INTERFACE ${target})
endforeach()

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/main-codecs-source-scope.txt" CONTENT
  "Windows x64 /MT; upstream Main codec source selection plus the real pinned XZ tuklib_cpucores implementation required by hardware_cputhreads (upstream xz-crt.lua omits this helper).\nXZ: ${mainXzSources}\nZstd: ${mainZstdSources}\nZlib: ${mainZlibSources}\nMinizip: ${mainMinizipSources}\nHDiffPatch: ${mainHdiffSources}\nZstd upstream selects common+decompress, not compressor. XZ excludes only upstream small-CRC/table-generator alternatives. No integrity, decompression or patch-validation code disabled.\n")
