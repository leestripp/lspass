#include "crypto.hpp"

#include <cstring>
#include <mutex>

namespace lspass::crypto {

void init() {
    static std::once_flag once;
    static int rc = -1;
    std::call_once(once, [] { rc = sodium_init(); });
    if (rc < 0)
        throw CryptoError("libsodium initialisation failed");
}

Bytes random_bytes(std::size_t n) {
    init();
    Bytes out(n);
    randombytes_buf(out.data(), out.size());
    return out;
}

KdfParams KdfParams::moderate() {
    return {crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE};
}

KdfParams KdfParams::interactive() {
    return {crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE};
}

SecureBytes derive_key(const std::string& password,
                       std::span<const std::byte> salt,
                       const KdfParams& params) {
    init();
    if (salt.size() != crypto_pwhash_SALTBYTES)
        throw CryptoError("invalid salt length");

    SecureBytes key(KEY_LEN);
    // crypto_pwhash() is Argon2id by default in libsodium >= 1.0.15.
    if (crypto_pwhash(reinterpret_cast<unsigned char*>(key.data()), key.size(),
                      password.data(), password.size(),
                      reinterpret_cast<const unsigned char*>(salt.data()),
                      params.ops_limit, params.mem_limit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw CryptoError("Argon2id key derivation failed (out of memory?)");
    }
    return key;
}

Bytes aead_encrypt(std::span<const std::byte> key,
                   std::span<const std::byte> plaintext,
                   std::span<const std::byte> aad) {
    init();
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        throw CryptoError("invalid key length");

    Bytes nonce = random_bytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    Bytes blob(nonce.size() + plaintext.size() +
               crypto_aead_xchacha20poly1305_ietf_ABYTES);

    std::memcpy(blob.data(), nonce.data(), nonce.size());

    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(blob.data() + nonce.size()), &clen,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
        nullptr,
        reinterpret_cast<const unsigned char*>(nonce.data()),
        reinterpret_cast<const unsigned char*>(key.data()));

    blob.resize(nonce.size() + clen);
    return blob;
}

std::optional<SecureBytes> aead_decrypt(std::span<const std::byte> key,
                                        std::span<const std::byte> blob,
                                        std::span<const std::byte> aad) {
    init();
    constexpr std::size_t nlen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    constexpr std::size_t tlen = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        throw CryptoError("invalid key length");
    if (blob.size() < nlen + tlen)
        return std::nullopt;

    const std::byte* nonce = blob.data();
    const std::byte* ct    = blob.data() + nlen;
    const std::size_t ctlen = blob.size() - nlen;

    SecureBytes out(ctlen - tlen);
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(out.data()), &mlen,
            nullptr,
            reinterpret_cast<const unsigned char*>(ct), ctlen,
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
            reinterpret_cast<const unsigned char*>(nonce),
            reinterpret_cast<const unsigned char*>(key.data())) != 0) {
        return std::nullopt; // authentication failed: wrong key or tampered
    }
    // mlen == ctlen - tlen exactly; no resize needed (and SecureBytes::resize
    // wipes by design, which would erase the plaintext).
    return out;
}

Bytes wrap_key(std::span<const std::byte> kek,
               std::span<const std::byte> dek) {
    static const std::string aad = "lspass:v1:wrap";
    return aead_encrypt(kek, dek,
                        {reinterpret_cast<const std::byte*>(aad.data()), aad.size()});
}

std::optional<SecureBytes> unwrap_key(std::span<const std::byte> kek,
                                      std::span<const std::byte> blob) {
    static const std::string aad = "lspass:v1:wrap";
    return aead_decrypt(kek, blob,
                        {reinterpret_cast<const std::byte*>(aad.data()), aad.size()});
}

bool constant_time_equal(std::span<const std::byte> a,
                         std::span<const std::byte> b) {
    if (a.size() != b.size())
        return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace lspass::crypto
