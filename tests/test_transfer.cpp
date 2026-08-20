#include "transfer.hpp"
#include "test_framework.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace lspass;

namespace {
std::string tmp_file(const std::string& name) {
    auto dir = std::filesystem::temp_directory_path() / "lspass-tests";
    std::filesystem::create_directories(dir);
    auto p = dir / name;
    std::filesystem::remove(p);
    std::filesystem::remove(p.string() + "-wal");
    std::filesystem::remove(p.string() + "-shm");
    return p.string();
}
void write(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    f << content;
}
std::string read_all(const std::string& path) {
    std::ifstream f(path);
    return {(std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()};
}
}

TEST(roundtrip_all_types) {
    auto p1 = tmp_file("rt1.db");
    auto pj = tmp_file("rt.json");
    auto p2 = tmp_file("rt2.db");

    {
        auto v = Vault::create(p1, "pw", crypto::KdfParams::interactive());
        Entry l; l.type = EntryType::Login; l.title = "GitHub";
        l.username = "alice@example.com"; l.url = "https://github.com";
        l.secret = "s3cr3t!"; l.notes = "2fa backup codes";
        v.add_entry(l);
        Entry n; n.type = EntryType::Note; n.title = "Recovery";
        n.secret = "note body with\nnewlines 🔐"; n.notes = "extra remarks";
        v.add_entry(n);
        Entry k; k.type = EntryType::ApiKey; k.title = "AWS";
        k.username = "prod-deploy"; k.secret = "AKIA...SECRET";
        v.add_entry(k);
        export_json(v, pj);
    }

    // plaintext export must exist and be owner-only
    CHECK(read_all(pj).find("s3cr3t!") != std::string::npos); // yes, plaintext!
    CHECK((std::filesystem::status(pj).permissions() &
           std::filesystem::perms::others_all) == std::filesystem::perms::none);

    {
        auto v = Vault::create(p2, "pw", crypto::KdfParams::interactive());
        auto res = import_json(v, pj);
        CHECK(res.imported == 3);
        CHECK(res.skipped == 0);

        auto all = v.list_entries();
        CHECK(all.size() == 3);
        bool got_login = false, got_note = false, got_key = false;
        for (auto& e : all) {
            if (e.title == "GitHub") {
                got_login = true;
                CHECK(e.type == EntryType::Login);
                CHECK(e.username == "alice@example.com");
                CHECK(e.url == "https://github.com");
                CHECK(e.secret == "s3cr3t!");
                CHECK(e.notes == "2fa backup codes");
            }
            if (e.title == "Recovery") {
                got_note = true;
                CHECK(e.type == EntryType::Note);
                CHECK(e.secret == "note body with\nnewlines 🔐");
                CHECK(e.notes == "extra remarks");
            }
            if (e.title == "AWS") {
                got_key = true;
                CHECK(e.type == EntryType::ApiKey);
                CHECK(e.secret == "AKIA...SECRET");
                CHECK(e.username == "prod-deploy");
            }
        }
        CHECK(got_login && got_note && got_key);
    }
}

TEST(import_bitwarden_shapes) {
    auto pj = tmp_file("bw.json");
    write(pj, R"({
  "encrypted": false,
  "folders": [{"id": "f1", "name": "Banking"}],
  "items": [
    {"type": 1, "name": "Bank", "folderId": "f1",
     "login": {"uris": [{"uri": "https://bank.example", "match": null}],
               "username": "lee", "password": "pw1"},
     "notes": "main account",
     "creationDate": "2025-04-02T04:30:45.923Z",
     "revisionDate": "2025-04-02T04:30:45.923Z"},
    {"type": 2, "name": "Safe combo", "folderId": null,
     "secureNote": {"type": 0}, "notes": "12-34-56"},
    {"type": 3, "name": "Visa card",
     "card": {"cardholderName": "Lee", "number": "4111"}},
    {"type": 1, "name": "NoPass",
     "login": {"uris": [], "username": null, "password": null}}
  ]
})");
    auto pv = tmp_file("bw.db");
    auto v = Vault::create(pv, "pw", crypto::KdfParams::interactive());
    auto res = import_json(v, pj);
    CHECK(res.imported == 3);
    CHECK(res.skipped == 1); // card skipped

    auto all = v.list_entries();
    for (auto& e : all) {
        if (e.title == "Bank") {
            CHECK(e.type == EntryType::Login);
            CHECK(e.url == "https://bank.example");
            CHECK(e.secret == "pw1");
            CHECK(e.notes.find("[Folder: Banking]") != std::string::npos);
            CHECK(e.created > 0); // date parsed
        }
        if (e.title == "Safe combo") {
            CHECK(e.type == EntryType::Note);
            CHECK(e.secret == "12-34-56");
        }
        if (e.title == "NoPass") {
            CHECK(e.secret.empty() && e.username.empty()); // nulls tolerated
        }
    }
}

TEST(import_invalid_json_throws) {
    auto pj = tmp_file("bad.json");
    write(pj, "{ not json !!");
    auto pv = tmp_file("badjson.db");
    auto v = Vault::create(pv, "pw", crypto::KdfParams::interactive());
    CHECK_THROWS_AS(import_json(v, pj), VaultError);
}

TEST(import_missing_file_throws) {
    auto pv = tmp_file("missing.db");
    auto v = Vault::create(pv, "pw", crypto::KdfParams::interactive());
    CHECK_THROWS_AS(import_json(v, "/nonexistent/file.json"), VaultError);
}

TEST_MAIN
