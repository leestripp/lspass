#include "vault.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <memory>
#include <sys/stat.h>

namespace lspass {

namespace {

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// RAII wrapper for prepared statements.
struct Stmt {
    sqlite3_stmt* s = nullptr;
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) != SQLITE_OK)
            throw VaultError(std::string("sqlite prepare failed: ") +
                             sqlite3_errmsg(db));
    }
    ~Stmt() { sqlite3_finalize(s); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
};

void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown";
        sqlite3_free(err);
        throw VaultError("sqlite error: " + msg);
    }
}

void bind_text(sqlite3_stmt* s, int idx, const std::string& v) {
    sqlite3_bind_text(s, idx, v.data(), static_cast<int>(v.size()),
                      SQLITE_TRANSIENT);
}

void bind_blob(sqlite3_stmt* s, int idx, std::span<const std::byte> v) {
    sqlite3_bind_blob(s, idx, v.data(), static_cast<int>(v.size()),
                      SQLITE_TRANSIENT);
}

crypto::Bytes column_blob(sqlite3_stmt* s, int idx) {
    const void* p = sqlite3_column_blob(s, idx);
    int n = sqlite3_column_bytes(s, idx);
    crypto::Bytes out(static_cast<std::size_t>(n));
    if (n > 0) std::memcpy(out.data(), p, static_cast<std::size_t>(n));
    return out;
}

std::string meta_get(sqlite3* db, const std::string& key) {
    Stmt st(db, "SELECT value FROM meta WHERE key=?1");
    bind_text(st.s, 1, key);
    if (sqlite3_step(st.s) != SQLITE_ROW)
        throw VaultError("vault meta key missing: " + key);
    return reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
}

crypto::Bytes meta_get_blob(sqlite3* db, const std::string& key) {
    Stmt st(db, "SELECT value FROM meta WHERE key=?1");
    bind_text(st.s, 1, key);
    if (sqlite3_step(st.s) != SQLITE_ROW)
        throw VaultError("vault meta key missing: " + key);
    return column_blob(st.s, 0);
}

void restrict_permissions(const std::string& path) {
    // Owner read/write only — the vault holds wrapped keys and metadata.
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
}

} // namespace

std::string entry_type_name(EntryType t) {
    switch (t) {
        case EntryType::Login:  return "Login";
        case EntryType::Note:   return "Secure Note";
        case EntryType::ApiKey: return "API Key";
    }
    return "Unknown";
}

bool Vault::exists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec) &&
           std::filesystem::file_size(path, ec) > 0;
}

Vault::Vault(Vault&& o) noexcept : db_(o.db_), dek_(std::move(o.dek_)) {
    o.db_ = nullptr;
}

Vault& Vault::operator=(Vault&& o) noexcept {
    if (this != &o) {
        if (db_) sqlite3_close(db_);
        db_ = o.db_;
        o.db_ = nullptr;
        dek_ = std::move(o.dek_);
    }
    return *this;
}

Vault::~Vault() {
    if (db_) sqlite3_close(db_);
    // dek_ is a SecureBytes: wiped automatically.
}

void Vault::init_schema() {
    exec(db_,
         "PRAGMA journal_mode=WAL;"
         "PRAGMA foreign_keys=ON;"
         "CREATE TABLE IF NOT EXISTS meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value BLOB NOT NULL"
         ");"
         "CREATE TABLE IF NOT EXISTS entries ("
         "  id       INTEGER PRIMARY KEY AUTOINCREMENT,"
         "  type     INTEGER NOT NULL,"
         "  title    TEXT    NOT NULL,"
         "  username TEXT    NOT NULL DEFAULT '',"
         "  url      TEXT    NOT NULL DEFAULT '',"
         "  secret   BLOB    NOT NULL,"
         "  notes    BLOB    NOT NULL,"
         "  created  INTEGER NOT NULL,"
         "  updated  INTEGER NOT NULL"
         ");");
}

Vault Vault::create(const std::string& path, const std::string& master_password,
                    crypto::KdfParams params) {
    crypto::init();
    if (exists(path))
        throw VaultError("vault already exists: " + path);
    if (master_password.empty())
        throw VaultError("master password must not be empty");

    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path());

    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        std::string msg = db ? sqlite3_errmsg(db) : "out of memory";
        if (db) sqlite3_close(db);
        throw VaultError("cannot create vault: " + msg);
    }
    restrict_permissions(path);

    Vault v(db);
    v.init_schema();

    // Envelope encryption: random DEK, wrapped by password-derived KEK.
    auto dek = crypto::SecureBytes(crypto::random_bytes(crypto::KEY_LEN));
    auto salt = crypto::random_bytes(crypto::SALT_LEN);
    auto kek = crypto::derive_key(master_password, salt, params);
    auto wrapped = crypto::wrap_key(
        {kek.data(), kek.size()}, {dek.data(), dek.size()});

    v.store_wrapped_dek(salt, params, wrapped);
    v.dek_ = std::move(dek);
    return v;
}

Vault Vault::open(const std::string& path, const std::string& master_password) {
    crypto::init();
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        std::string msg = db ? sqlite3_errmsg(db) : "out of memory";
        if (db) sqlite3_close(db);
        throw VaultError("cannot open vault: " + msg);
    }
    restrict_permissions(path);

    Vault v(db);
    v.init_schema(); // no-op on existing vaults
    v.dek_ = v.load_and_unwrap_dek(master_password); // throws WrongPassword
    return v;
}

void Vault::store_wrapped_dek(const crypto::Bytes& salt,
                              const crypto::KdfParams& params,
                              const crypto::Bytes& wrapped) {
    Stmt st(db_, "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)");

    auto put = [&](const char* k, std::span<const std::byte> v) {
        sqlite3_reset(st.s);
        sqlite3_clear_bindings(st.s);
        bind_text(st.s, 1, k);
        bind_blob(st.s, 2, v);
        if (sqlite3_step(st.s) != SQLITE_DONE)
            throw VaultError("failed to store vault header");
    };
    auto put_u64 = [&](const char* k, std::uint64_t v) {
        sqlite3_reset(st.s);
        sqlite3_clear_bindings(st.s);
        bind_text(st.s, 1, k);
        sqlite3_bind_int64(st.s, 2, static_cast<sqlite3_int64>(v));
        if (sqlite3_step(st.s) != SQLITE_DONE)
            throw VaultError("failed to store vault header");
    };

    put_u64("version", 1);
    Stmt tag(db_, "INSERT OR REPLACE INTO meta(key,value) VALUES('kdf_algo','argon2id')");
    sqlite3_step(tag.s);
    put("kdf_salt", salt);
    put_u64("kdf_opslimit", params.ops_limit);
    put_u64("kdf_memlimit", static_cast<std::uint64_t>(params.mem_limit));
    put("wrapped_dek", wrapped);
}

crypto::SecureBytes Vault::load_and_unwrap_dek(const std::string& password) {
    const std::string algo = meta_get(db_, "kdf_algo");
    if (algo != "argon2id")
        throw VaultError("unsupported KDF: " + algo);

    auto salt    = meta_get_blob(db_, "kdf_salt");
    auto wrapped = meta_get_blob(db_, "wrapped_dek");
    crypto::KdfParams params{
        static_cast<std::uint64_t>(std::stoull(meta_get(db_, "kdf_opslimit"))),
        static_cast<std::size_t>(std::stoull(meta_get(db_, "kdf_memlimit"))),
    };

    auto kek = crypto::derive_key(password, salt, params);
    // AEAD unwrap doubles as password verification: Poly1305
    // authentication fails unless the password was correct.
    auto dek = crypto::unwrap_key({kek.data(), kek.size()}, wrapped);
    if (!dek)
        throw WrongPassword();
    return std::move(*dek);
}

crypto::Bytes Vault::encrypt_field(std::int64_t id, const char* field,
                                   const std::string& plaintext) const {
    const std::string aad =
        "lspass:v1:entry:" + std::to_string(id) + ":" + field;
    return crypto::aead_encrypt(
        {dek_.data(), dek_.size()},
        {reinterpret_cast<const std::byte*>(plaintext.data()), plaintext.size()},
        {reinterpret_cast<const std::byte*>(aad.data()), aad.size()});
}

std::string Vault::decrypt_field(std::int64_t id, const char* field,
                                 std::span<const std::byte> blob) const {
    const std::string aad =
        "lspass:v1:entry:" + std::to_string(id) + ":" + field;
    auto plain = crypto::aead_decrypt(
        {dek_.data(), dek_.size()}, blob,
        {reinterpret_cast<const std::byte*>(aad.data()), aad.size()});
    if (!plain)
        throw VaultError("entry failed integrity check — vault tampered with?");
    return plain->to_string();
}

std::int64_t Vault::add_entry(Entry e) {
    // Insert with placeholder blobs to learn the row id, then seal the
    // secrets with AAD bound to that id.
    Stmt st(db_,
            "INSERT INTO entries(type,title,username,url,secret,notes,"
            "created,updated) VALUES(?1,?2,?3,?4,x'',x'',?5,?5)");
    const std::int64_t now = now_unix();
    sqlite3_bind_int64(st.s, 1, static_cast<int>(e.type));
    bind_text(st.s, 2, e.title);
    bind_text(st.s, 3, e.username);
    bind_text(st.s, 4, e.url);
    sqlite3_bind_int64(st.s, 5, now);
    if (sqlite3_step(st.s) != SQLITE_DONE)
        throw VaultError("failed to insert entry");

    const std::int64_t id = sqlite3_last_insert_rowid(db_);
    e.id = id;
    update_entry(e);
    return id;
}

void Vault::update_entry(const Entry& e) {
    auto secret_blob = encrypt_field(e.id, "secret", e.secret);
    auto notes_blob  = encrypt_field(e.id, "notes",  e.notes);

    Stmt st(db_,
            "UPDATE entries SET type=?1,title=?2,username=?3,url=?4,"
            "secret=?5,notes=?6,updated=?7 WHERE id=?8");
    sqlite3_bind_int64(st.s, 1, static_cast<int>(e.type));
    bind_text(st.s, 2, e.title);
    bind_text(st.s, 3, e.username);
    bind_text(st.s, 4, e.url);
    bind_blob(st.s, 5, secret_blob);
    bind_blob(st.s, 6, notes_blob);
    sqlite3_bind_int64(st.s, 7, now_unix());
    sqlite3_bind_int64(st.s, 8, e.id);
    if (sqlite3_step(st.s) != SQLITE_DONE || sqlite3_changes(db_) != 1)
        throw VaultError("failed to update entry");
}

void Vault::delete_entry(std::int64_t id) {
    Stmt st(db_, "DELETE FROM entries WHERE id=?1");
    sqlite3_bind_int64(st.s, 1, id);
    if (sqlite3_step(st.s) != SQLITE_DONE || sqlite3_changes(db_) != 1)
        throw VaultError("failed to delete entry");
}

namespace {
Entry row_to_entry(Vault& v, sqlite3_stmt* s) {
    Entry e;
    e.id       = sqlite3_column_int64(s, 0);
    e.type     = static_cast<EntryType>(sqlite3_column_int(s, 1));
    e.title    = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
    e.username = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
    e.url      = reinterpret_cast<const char*>(sqlite3_column_text(s, 4));
    auto secret = column_blob(s, 5);
    auto notes  = column_blob(s, 6);
    e.created  = sqlite3_column_int64(s, 7);
    e.updated  = sqlite3_column_int64(s, 8);
    e.secret = v.decrypt_field(e.id, "secret", secret);
    e.notes  = v.decrypt_field(e.id, "notes", notes);
    return e;
}
} // namespace

std::optional<Entry> Vault::get_entry(std::int64_t id) {
    Stmt st(db_,
            "SELECT id,type,title,username,url,secret,notes,created,updated"
            " FROM entries WHERE id=?1");
    sqlite3_bind_int64(st.s, 1, id);
    if (sqlite3_step(st.s) != SQLITE_ROW)
        return std::nullopt;
    return row_to_entry(*this, st.s);
}

std::vector<Entry> Vault::list_entries(const std::string& filter) {
    std::vector<Entry> out;
    if (filter.empty()) {
        Stmt st(db_,
                "SELECT id,type,title,username,url,secret,notes,created,updated"
                " FROM entries ORDER BY lower(title)");
        while (sqlite3_step(st.s) == SQLITE_ROW)
            out.push_back(row_to_entry(*this, st.s));
    } else {
        Stmt st(db_,
                "SELECT id,type,title,username,url,secret,notes,created,updated"
                " FROM entries"
                " WHERE title LIKE ?1 OR username LIKE ?1 OR url LIKE ?1"
                " ORDER BY lower(title)");
        bind_text(st.s, 1, "%" + filter + "%");
        while (sqlite3_step(st.s) == SQLITE_ROW)
            out.push_back(row_to_entry(*this, st.s));
    }
    return out;
}

std::string Vault::get_setting(const std::string& key,
                               const std::string& fallback) const {
    Stmt st(db_, "SELECT value FROM meta WHERE key=?1");
    bind_text(st.s, 1, "setting:" + key);
    if (sqlite3_step(st.s) != SQLITE_ROW)
        return fallback;
    return reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
}

void Vault::set_setting(const std::string& key, const std::string& value) {
    Stmt st(db_, "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)");
    bind_text(st.s, 1, "setting:" + key);
    bind_text(st.s, 2, value);
    if (sqlite3_step(st.s) != SQLITE_DONE)
        throw VaultError("failed to store setting");
}

void Vault::change_master_password(const std::string& new_password,
                                   crypto::KdfParams params) {
    if (new_password.empty())
        throw VaultError("master password must not be empty");
    auto salt = crypto::random_bytes(crypto::SALT_LEN);
    auto kek = crypto::derive_key(new_password, salt, params);
    auto wrapped = crypto::wrap_key({kek.data(), kek.size()},
                                    {dek_.data(), dek_.size()});
    store_wrapped_dek(salt, params, wrapped);
}

} // namespace lspass
