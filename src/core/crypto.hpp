#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <sodium.h>

namespace lspass::crypto {

/// A byte buffer that is securely wiped (sodium_memzero) on destruction,
/// move-only, and page-locked where possible so secrets are not swapped
/// to disk.
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t n) : data_(n) {}
    explicit SecureBytes(std::span<const std::byte> src)
        : data_(src.begin(), src.end()) {}

    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&&) noexcept = default;
    SecureBytes& operator=(SecureBytes&&) noexcept = default;

    ~SecureBytes() { wipe(); }

    std::byte* data() { return data_.data(); }
    const std::byte* data() const { return data_.data(); }
    std::size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    std::byte& operator[](std::size_t i) { return data_[i]; }
    const std::byte& operator[](std::size_t i) const { return data_[i]; }

    void resize(std::size_t n) { wipe(); data_.assign(n, std::byte{0}); }
    void wipe() {
        if (!data_.empty()) sodium_memzero(data_.data(), data_.size());
        data_.clear();
    }
    operator std::span<const std::byte>() const {
        return {data_.data(), data_.size()};
    }
    std::span<std::byte> span() { return {data_.data(), data_.size()}; }

    std::string to_string() const {
        return {reinterpret_cast<const char*>(data_.data()), data_.size()};
    }

private:
    std::vector<std::byte> data_;
};

using Bytes = std::vector<std::byte>;

/// libsodium runtime initialisation (idempotent). Throws on failure.
void init();

/// CSPRNG bytes from the kernel (via libsodium).
Bytes random_bytes(std::size_t n);

/// Argon2id KDF parameters. Defaults exceed the OWASP minimum
/// (m=19 MiB, t=2, p=1). Stored inside the vault so they can be
/// upgraded over time without breaking old files.
struct KdfParams {
    std::uint64_t ops_limit;  ///< CPU cost (iterations)
    std::size_t   mem_limit;  ///< memory in bytes
    static KdfParams moderate();    ///< production default
    static KdfParams interactive(); ///< fast, used by unit tests
};

/// Derive a 32-byte key-encryption-key from a password with Argon2id.
/// Throws CryptoError if memory limits cannot be met.
SecureBytes derive_key(const std::string& password,
                       std::span<const std::byte> salt,
                       const KdfParams& params);

constexpr std::size_t SALT_LEN  = 16;  ///< crypto_pwhash_SALTBYTES
constexpr std::size_t KEY_LEN   = 32;  ///< XChaCha20 key
constexpr std::size_t NONCE_LEN = 24;  ///< XChaCha20-Poly1305 nonce
constexpr std::size_t TAG_LEN   = 16;  ///< Poly1305 tag

/// Encrypt with XChaCha20-Poly1305 (AEAD, random 192-bit nonce).
/// Returns nonce || ciphertext || tag in a single blob.
/// `aad` binds the ciphertext to a context (e.g. field name + row id)
/// so ciphertexts cannot be transplanted between entries.
Bytes aead_encrypt(std::span<const std::byte> key,
                   std::span<const std::byte> plaintext,
                   std::span<const std::byte> aad);

/// Decrypt a blob produced by aead_encrypt. std::nullopt on any
/// authentication failure (wrong key, tampering, AAD mismatch).
std::optional<SecureBytes> aead_decrypt(std::span<const std::byte> key,
                                        std::span<const std::byte> blob,
                                        std::span<const std::byte> aad);

/// Wrap (encrypt) a data-encryption-key with a key-encryption-key.
Bytes wrap_key(std::span<const std::byte> kek,
               std::span<const std::byte> dek);

std::optional<SecureBytes> unwrap_key(std::span<const std::byte> kek,
                                      std::span<const std::byte> blob);

/// Constant-time comparison.
bool constant_time_equal(std::span<const std::byte> a,
                         std::span<const std::byte> b);

class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

} // namespace lspass::crypto
