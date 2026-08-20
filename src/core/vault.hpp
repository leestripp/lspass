#pragma once

#include "crypto.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace lspass {

enum class EntryType : int {
    Login  = 0,  ///< username + password + url
    Note   = 1,  ///< free-form secure note
    ApiKey = 2,  ///< service + API key/secret
};

std::string entry_type_name(EntryType t);

struct Entry {
    std::int64_t id = 0;
    EntryType    type = EntryType::Login;
    std::string  title;     ///< plaintext (needed for listing/search)
    std::string  username;  ///< plaintext (needed for listing/search)
    std::string  url;       ///< plaintext (needed for listing/search)
    std::string  secret;    ///< ENCRYPTED at rest (password / note body / API key)
    std::string  notes;     ///< ENCRYPTED at rest
    std::int64_t created = 0;
    std::int64_t updated = 0;
};

class VaultError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class WrongPassword : public VaultError {
public:
    WrongPassword() : VaultError("wrong master password or corrupted vault") {}
};

/// Encrypted password vault backed by SQLite.
///
/// Security design (envelope encryption):
///   master password --[Argon2id, random salt]--> KEK (32 B, RAM only)
///   random DEK (32 B) wrapped by KEK, stored in the vault header.
///   Each secret field is individually sealed with XChaCha20-Poly1305
///   under the DEK, a fresh random 192-bit nonce, and AAD binding the
///   ciphertext to (entry id, field) to prevent transplant attacks.
/// The DEK lives in a wiped-on-destruction SecureBytes and is never
/// written to disk in the clear. Nothing is ever stored as plaintext
/// except the listing metadata described above.
class Vault {
public:
    /// Create a new vault file. Fails if it already exists.
    /// `params` lets tests use cheaper KDF settings.
    static Vault create(const std::string& path,
                        const std::string& master_password,
                        crypto::KdfParams params = crypto::KdfParams::moderate());

    /// Open and unlock an existing vault. Throws WrongPassword on failure.
    static Vault open(const std::string& path,
                      const std::string& master_password);

    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;
    Vault(Vault&&) noexcept;
    Vault& operator=(Vault&&) noexcept;
    ~Vault();

    static bool exists(const std::string& path);

    /// Decrypt a stored field blob. Public so tests and the row mapper
    /// can verify integrity; throws on authentication failure.
    std::string decrypt_field(std::int64_t id, const char* field,
                              std::span<const std::byte> blob) const;


    std::int64_t add_entry(Entry e);
    void         update_entry(const Entry& e);
    void         delete_entry(std::int64_t id);
    std::optional<Entry> get_entry(std::int64_t id);
    std::vector<Entry>   list_entries(const std::string& filter = "");

    /// Re-wraps the DEK under a key derived from the new password with a
    /// fresh salt. Entry payloads are untouched.
    /// Per-vault settings (stored in the meta table, prefixed "setting:").
    /// Not secret — used for UI/generator preferences.
    std::string get_setting(const std::string& key,
                            const std::string& fallback = "") const;
    void        set_setting(const std::string& key, const std::string& value);

    void change_master_password(const std::string& new_password,
                                crypto::KdfParams params = crypto::KdfParams::moderate());

private:
    explicit Vault(sqlite3* db) : db_(db) {}

    void init_schema();
    void store_wrapped_dek(const crypto::Bytes& salt,
                           const crypto::KdfParams& params,
                           const crypto::Bytes& wrapped);
    crypto::SecureBytes load_and_unwrap_dek(const std::string& password);

    crypto::Bytes encrypt_field(std::int64_t id, const char* field,
                                const std::string& plaintext) const;

    sqlite3*           db_ = nullptr;
    crypto::SecureBytes dek_;
};

} // namespace lspass
