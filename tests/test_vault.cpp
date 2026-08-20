#include "vault.hpp"
#include "test_framework.hpp"

#include <cstdio>
#include <sqlite3.h>
#include <filesystem>
#include <fstream>
#include <string>

using namespace lspass;

namespace {
std::string tmp_vault(const std::string& name) {
    auto dir = std::filesystem::temp_directory_path() / "lspass-tests";
    std::filesystem::create_directories(dir);
    auto p = dir / name;
    std::filesystem::remove(p);
    std::filesystem::remove(p.string() + "-wal");
    std::filesystem::remove(p.string() + "-shm");
    return p.string();
}
Entry sample_login() {
    Entry e;
    e.type = EntryType::Login;
    e.title = "Example Mail";
    e.username = "alice@example.com";
    e.url = "https://mail.example.com";
    e.secret = "Tr0ub4dor&3-extra";
    e.notes = "recovery code: 12345";
    return e;
}
} // namespace

TEST(create_and_reopen) {
    auto path = tmp_vault("create.db");
    {
        auto v = Vault::create(path, "master pw", crypto::KdfParams::interactive());
        CHECK(Vault::exists(path));
    }
    {
        auto v = Vault::open(path, "master pw");
        CHECK(v.list_entries().empty());
    }
}

TEST(wrong_password_rejected) {
    auto path = tmp_vault("wrongpw.db");
    { auto v = Vault::create(path, "right", crypto::KdfParams::interactive()); }
    CHECK_THROWS_AS(Vault::open(path, "wrong"), WrongPassword);
}

TEST(crud_roundtrip) {
    auto path = tmp_vault("crud.db");
    auto v = Vault::create(path, "pw", crypto::KdfParams::interactive());
    auto id = v.add_entry(sample_login());
    CHECK(id > 0);
    auto got = v.get_entry(id);
    CHECK(got.has_value());
    CHECK(got->title == "Example Mail");
    CHECK(got->username == "alice@example.com");
    CHECK(got->secret == "Tr0ub4dor&3-extra");  // decrypted correctly
    CHECK(got->notes == "recovery code: 12345");

    got->secret = "rotated-password";
    got->title = "Example Mail 2";
    v.update_entry(*got);
    auto got2 = v.get_entry(id);
    CHECK(got2->secret == "rotated-password");
    CHECK(got2->title == "Example Mail 2");

    v.delete_entry(id);
    CHECK(!v.get_entry(id).has_value());
}

TEST(persistence_across_sessions) {
    auto path = tmp_vault("persist.db");
    std::int64_t id;
    {
        auto v = Vault::create(path, "pw", crypto::KdfParams::interactive());
        Entry e; e.type = EntryType::ApiKey; e.title = "GitHub";
        e.secret = "ghp_secret_token_value";
        id = v.add_entry(e);
    }
    {
        auto v = Vault::open(path, "pw");
        auto e = v.get_entry(id);
        CHECK(e.has_value());
        CHECK(e->secret == "ghp_secret_token_value");
        CHECK(e->type == EntryType::ApiKey);
    }
}

TEST(secrets_not_stored_in_plaintext) {
    auto path = tmp_vault("noplain.db");
    const std::string canary = "CANARY-super-secret-9f8e7d";
    {
        auto v = Vault::create(path, "pw", crypto::KdfParams::interactive());
        Entry e; e.type = EntryType::Note; e.title = "note";
        e.secret = canary;
        v.add_entry(e);
    } // close + flush
    // Scan raw vault files for the canary.
    for (auto suffix : {"", "-wal", "-shm"}) {
        std::ifstream f(path + suffix, std::ios::binary);
        if (!f) continue;
        std::string data((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        CHECK(data.find(canary) == std::string::npos);
    }
}

TEST(entry_types) {
    auto path = tmp_vault("types.db");
    auto v = Vault::create(path, "pw", crypto::KdfParams::interactive());
    for (auto t : {EntryType::Login, EntryType::Note, EntryType::ApiKey}) {
        Entry e; e.type = t; e.title = entry_type_name(t); e.secret = "x";
        v.add_entry(e);
    }
    auto all = v.list_entries();
    CHECK(all.size() == 3);
}

TEST(search_filter) {
    auto path = tmp_vault("search.db");
    auto v = Vault::create(path, "pw", crypto::KdfParams::interactive());
    Entry a = sample_login();
    v.add_entry(a);
    Entry b; b.type = EntryType::Login; b.title = "Bank"; b.username = "alice";
    b.secret = "s"; v.add_entry(b);
    CHECK(v.list_entries("bank").size() == 1);
    CHECK(v.list_entries("alice").size() == 2);
    CHECK(v.list_entries("nomatch").empty());
}

TEST(change_master_password) {
    auto path = tmp_vault("changepw.db");
    std::int64_t id;
    {
        auto v = Vault::create(path, "old pw", crypto::KdfParams::interactive());
        Entry e = sample_login();
        id = v.add_entry(e);
        v.change_master_password("new pw", crypto::KdfParams::interactive());
    }
    CHECK_THROWS_AS(Vault::open(path, "old pw"), WrongPassword);
    auto v = Vault::open(path, "new pw");
    auto e = v.get_entry(id);
    CHECK(e.has_value());
    CHECK(e->secret == "Tr0ub4dor&3-extra"); // entries survive re-wrap
}

TEST(tampered_entry_detected) {
    auto path = tmp_vault("tamper.db");
    {
        auto v = Vault::create(path, "pw", crypto::KdfParams::interactive());
        Entry e = sample_login();
        v.add_entry(e);
    }
    // Flip a byte in the stored secret blob via raw SQL.
    {
        sqlite3* db = nullptr;
        CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
        sqlite3_exec(db, "UPDATE entries SET secret = "
                         "substr(secret,1,30) || char(255) || "
                         "substr(secret,32) WHERE id=1",
                     nullptr, nullptr, nullptr);
        sqlite3_close(db);
    }
    auto v = Vault::open(path, "pw");
    CHECK_THROWS_AS(v.list_entries(), VaultError);
}

TEST(settings_persist) {
    auto path = tmp_vault("settings.db");
    {
        auto v = Vault::create(path, "pw", crypto::KdfParams::interactive());
        CHECK(v.get_setting("gen_length", "20") == "20"); // fallback
        v.set_setting("gen_length", "28");
        v.set_setting("gen_symbols", "0");
        CHECK(v.get_setting("gen_length") == "28");
    }
    {
        auto v = Vault::open(path, "pw");
        CHECK(v.get_setting("gen_length") == "28");
        CHECK(v.get_setting("gen_symbols") == "0");
        v.set_setting("gen_length", "16"); // overwrite
        CHECK(v.get_setting("gen_length") == "16");
    }
}

TEST_MAIN
