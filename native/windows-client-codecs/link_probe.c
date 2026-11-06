#include <stdio.h>
#include <lzma.h>
#include <zstd.h>
#include <zlib.h>
#include <mz.h>
#include <mz_zip_rw.h>
#include <patch.h>

/* Build-only consumer; /WHOLEARCHIVE also resolves every selected codec unit. */
int main(void)
{
    printf("lzma=%s zstd=%s zlib=%s\n",
        lzma_version_string(), ZSTD_versionString(), zlibVersion());
    return 0;
}
