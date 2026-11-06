#include <stdio.h>
#include <stddef.h>
#include <sys/uio.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include <SDL.h>

_Static_assert(sizeof(void *) == 8, "Require 64-bit ABI");
_Static_assert(sizeof(giovec_t) == sizeof(struct iovec), "Require original iovec layout");
_Static_assert(offsetof(giovec_t, iov_len) == offsetof(struct iovec, iov_len), "Require iovec field ABI");
_Static_assert(sizeof(SDL_version) == 3, "Require SDL2 version ABI");

int main(void)
{
    int status = gnutls_global_init();
    if (status != GNUTLS_E_SUCCESS) return 1;
    unsigned char key[16] = {0};
    gnutls_datum_t key_data = {key, sizeof(key)};
    gnutls_cipher_hd_t cipher;
    status = gnutls_cipher_init(&cipher, GNUTLS_CIPHER_AES_128_CBC, &key_data, NULL);
    if (status != GNUTLS_E_SUCCESS || gnutls_mac_get_key_size(GNUTLS_MAC_SHA256) == 0) return 2;
    gnutls_cipher_deinit(cipher);
    gnutls_session_t session;
    if (gnutls_init(&session, GNUTLS_CLIENT) != GNUTLS_E_SUCCESS) return 3;
    gnutls_deinit(session);
    printf("GNUTLS header=%s runtime=%s cipher=PASS session=PASS\n", GNUTLS_VERSION, gnutls_check_version(NULL));
    gnutls_global_deinit();
    FT_Library freetype;
    if (FT_Init_FreeType(&freetype)) return 4;
    int major, minor, patch;
    FT_Library_Version(freetype, &major, &minor, &patch);
    printf("FREETYPE header=%d.%d.%d runtime=%d.%d.%d init=PASS\n",
           FREETYPE_MAJOR, FREETYPE_MINOR, FREETYPE_PATCH, major, minor, patch);
    FT_Done_FreeType(freetype);
    SDL_version version;
    SDL_GetVersion(&version);
    if (SDL_Init(0) != 0) return 5;
    printf("SDL2 header=%d.%d.%d runtime=%u.%u.%u init0=PASS\n",
           SDL_MAJOR_VERSION, SDL_MINOR_VERSION, SDL_PATCHLEVEL, version.major, version.minor, version.patch);
    SDL_Quit();
    return 0;
}
