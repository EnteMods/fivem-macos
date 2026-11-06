#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <exception>
#include <string>
#include <cpr/session.h>
#include <openssl/ssl.h>
#include "https-target.h"

static std::string json_string(const std::string& text)
{
    std::string result = "\"";
    for (unsigned char c : text) {
        if (c == '\\' || c == '"') { result += '\\'; result += (char)c; }
        else if (c < 32) { char buffer[7]; std::snprintf(buffer, sizeof(buffer), "\\u%04x", c); result += buffer; }
        else result += (char)c;
    }
    return result + '"';
}

struct TransferLimits { size_t body_bytes = 0; size_t header_bytes = 0; };

static size_t reject_body(char*, size_t size, size_t count, void* data)
{
    static_cast<TransferLimits*>(data)->body_bytes += size * count;
    return 0;
}

static size_t bounded_headers(char*, size_t size, size_t count, void* data)
{
    auto limits = static_cast<TransferLimits*>(data);
    size_t bytes = size * count;
    if (bytes > 32768 || limits->header_bytes > 32768 - bytes) return 0;
    limits->header_bytes += bytes;
    return bytes;
}

static long native_root_count()
{
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) return -1;
    long count = 0;
    const CERT_CONTEXT* context = nullptr;
    while ((context = CertEnumCertificatesInStore(store, context)) != nullptr) ++count;
    CertCloseStore(store, 0);
    return count;
}

static int perform_head()
{
    CURLcode init = curl_global_init(CURL_GLOBAL_ALL);
    if (init != CURLE_OK) {
        std::printf("HTTPS_HEAD_SETUP_ERROR {\"curl_code\":%d,\"message\":%s}\n", (int)init, json_string(curl_easy_strerror(init)).c_str());
        return 2;
    }
    int exit_code = 1;
    {
        cpr::Session session;
        session.SetUrl(cpr::Url{HTTPS_TARGET_URL});
        session.SetVerifySsl(cpr::VerifySsl{true});
        session.SetHttpVersion(cpr::HttpVersion{cpr::HttpVersionCode::VERSION_2_0_TLS});
        session.SetRedirect(cpr::Redirect{false});
        session.SetConnectTimeout(cpr::ConnectTimeout{10000});
        session.SetTimeout(cpr::Timeout{20000});
        session.SetUserAgent(cpr::UserAgent{"CfxMainVendorApiProbe/1"});
        session.PrepareHead();
        auto holder = session.GetCurlHolder();
        CURL* handle = holder ? holder->handle : nullptr;
        if (!handle) {
            std::puts("HTTPS_HEAD_SETUP_ERROR {\"message\":\"CPR produced no CURL handle\"}");
            return 2;
        }
        TransferLimits limits;
        CURLcode setup = CURLE_OK;
#define SET_OPTION(option, value) do { CURLcode code = curl_easy_setopt(handle, option, value); if (code != CURLE_OK && setup == CURLE_OK) setup = code; } while (0)
        SET_OPTION(CURLOPT_SSL_VERIFYPEER, 1L);
        SET_OPTION(CURLOPT_SSL_VERIFYHOST, 2L);
        SET_OPTION(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2);
        SET_OPTION(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        SET_OPTION(CURLOPT_NOBODY, 1L);
        SET_OPTION(CURLOPT_FOLLOWLOCATION, 0L);
        SET_OPTION(CURLOPT_PROXY, "");
        SET_OPTION(CURLOPT_NETRC, CURL_NETRC_IGNORED);
        SET_OPTION(CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        SET_OPTION(CURLOPT_WRITEFUNCTION, reject_body);
        SET_OPTION(CURLOPT_WRITEDATA, &limits);
        SET_OPTION(CURLOPT_HEADERFUNCTION, bounded_headers);
        SET_OPTION(CURLOPT_HEADERDATA, &limits);
#undef SET_OPTION
        if (setup != CURLE_OK) {
            std::printf("HTTPS_HEAD_SETUP_ERROR {\"curl_code\":%d,\"message\":%s}\n", (int)setup, json_string(curl_easy_strerror(setup)).c_str());
            return 2;
        }
        long roots = native_root_count();
        const curl_version_info_data* versions = curl_version_info(CURLVERSION_NOW);
        std::printf("HTTPS_HEAD_BEGIN {\"native_root_certificate_count\":%ld,\"method\":\"HEAD\",\"verify_peer\":1,\"verify_host\":2,\"requested_tls\":\"TLSv1.2 only\"}\n", roots);
        std::fflush(stdout);
        CURLcode code = curl_easy_perform(handle);
        long status = 0, verify = -1, http_version = 0, redirects = -1;
        curl_off_t downloaded = -1, content_length = -1;
        char* effective = nullptr;
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
        curl_easy_getinfo(handle, CURLINFO_SSL_VERIFYRESULT, &verify);
        curl_easy_getinfo(handle, CURLINFO_HTTP_VERSION, &http_version);
        curl_easy_getinfo(handle, CURLINFO_REDIRECT_COUNT, &redirects);
        curl_easy_getinfo(handle, CURLINFO_SIZE_DOWNLOAD_T, &downloaded);
        curl_easy_getinfo(handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &content_length);
        curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &effective);
        const auto response = session.Complete(code);
        const bool exact_url = effective && std::string(effective) == HTTPS_TARGET_URL;
        const bool tls_verified = code == CURLE_OK && verify == 0;
        const bool http_response = tls_verified && status >= 100 && status <= 599;
        const bool passed = http_response && status == 200 && content_length == HTTPS_EXPECTED_BYTES &&
            limits.body_bytes == 0 && downloaded == 0 && redirects == 0 && exact_url;
        std::printf("HTTPS_HEAD_RESULT {\"passed\":%s,\"curl_code\":%d,\"curl_error\":%s,\"curl_error_buffer\":%s,"
            "\"cpr_error_code\":%d,\"cpr_error_message\":%s,\"http_status\":%ld,\"ssl_verify_result\":%ld,"
            "\"tls_verified\":%s,\"http_response_received\":%s,\"http_version\":%ld,\"redirect_count\":%ld,"
            "\"exact_effective_url\":%s,\"received_body_bytes\":%zu,\"curl_downloaded_bytes\":%lld,"
            "\"content_length\":%lld,\"received_header_bytes\":%zu,\"native_root_certificate_count\":%ld,"
            "\"curl_version\":%s,\"ssl_backend\":%s,\"http2_feature_available\":%s,\"nghttp2_version\":%s}\n",
            passed ? "true" : "false", (int)code, json_string(curl_easy_strerror(code)).c_str(),
            json_string(holder->error.data()).c_str(), (int)response.error.code, json_string(response.error.message).c_str(),
            status, verify, tls_verified ? "true" : "false", http_response ? "true" : "false", http_version, redirects,
            exact_url ? "true" : "false", limits.body_bytes, (long long)downloaded, (long long)content_length,
            limits.header_bytes, roots, json_string(versions->version ? versions->version : "").c_str(),
            json_string(versions->ssl_version ? versions->ssl_version : "").c_str(),
            versions->features & CURL_VERSION_HTTP2 ? "true" : "false",
            json_string(versions->nghttp2_version ? versions->nghttp2_version : "").c_str());
        exit_code = passed ? 0 : 1;
    }
    curl_global_cleanup();
    return exit_code;
}

int main()
{
    try { return perform_head(); }
    catch (const std::exception& error) {
        std::printf("HTTPS_HEAD_EXCEPTION {\"message\":%s}\n", json_string(error.what()).c_str());
        return 2;
    }
}
