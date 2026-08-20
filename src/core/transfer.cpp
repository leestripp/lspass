#include "transfer.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <fstream>
#include <map>
#include <sys/stat.h>

namespace lspass {

namespace {

using nlohmann::json;

std::string iso8601(std::int64_t unix) {
    std::time_t t = static_cast<std::time_t>(unix);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[40];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S.000Z", &tm);
    return buf;
}

std::int64_t parse_iso8601(const std::string& s) {
    std::tm tm{};
    if (strptime(s.c_str(), "%Y-%m-%dT%H:%M:%S", &tm) == nullptr)
        return 0;
    return static_cast<std::int64_t>(timegm(&tm));
}

// Non-cryptographic id: Bitwarden needs a string id, any unique one works.
std::string make_id(std::int64_t eid) {
    return "lspass-" + std::to_string(eid);
}

} // namespace

void export_json(Vault& vault, const std::string& path) {
    json root;
    root["encrypted"] = false;
    root["folders"] = json::array();
    root["items"] = json::array();

    for (const auto& e : vault.list_entries()) {
        json item;
        item["id"] = make_id(e.id);
        item["favorite"] = false;
        item["reprompt"] = 0;
        item["collectionIds"] = nullptr;
        item["folderId"] = nullptr;
        item["fields"] = json::array();
        item["passwordHistory"] = json::array();
        item["creationDate"] = iso8601(e.created);
        item["revisionDate"] = iso8601(e.updated);
        item["name"] = e.title;

        switch (e.type) {
        case EntryType::Login:
            item["type"] = 1;
            item["login"] = {
                {"username", e.username},
                {"password", e.secret},
                {"uris", e.url.empty()
                     ? json::array()
                     : json::array({{{"uri", e.url}, {"match", nullptr}}})},
                {"fido2Credentials", json::array()},
            };
            if (!e.notes.empty()) item["notes"] = e.notes;
            break;

        case EntryType::Note:
            item["type"] = 2;
            item["secureNote"] = {{"type", 0}};
            item["notes"] = e.secret; // note body lives in Bitwarden "notes"
            if (!e.notes.empty()) {
                item["fields"].push_back(
                    {{"name", "Additional notes"},
                     {"value", e.notes}, {"type", 0}});
            }
            break;

        case EntryType::ApiKey:
            // No native Bitwarden type: export as a secure note with the
            // key in a custom field, tagged so lsPass can round-trip it.
            item["type"] = 2;
            item["secureNote"] = {{"type", 0}};
            item["fields"].push_back(
                {{"name", "lsPassType"}, {"value", "apikey"}, {"type", 0}});
            item["fields"].push_back(
                {{"name", "API Key"}, {"value", e.secret}, {"type", 0}});
            if (!e.username.empty())
                item["fields"].push_back(
                    {{"name", "Key name"}, {"value", e.username}, {"type", 0}});
            if (!e.notes.empty()) item["notes"] = e.notes;
            break;
        }
        root["items"].push_back(std::move(item));
    }

    std::ofstream f(path, std::ios::trunc);
    if (!f) throw VaultError("cannot write export file: " + path);
    f << root.dump(2) << '\n';
    f.close();
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR); // plaintext secrets: owner-only
}

TransferResult import_json(Vault& vault, const std::string& path) {
    std::ifstream f(path);
    if (!f) throw VaultError("cannot open import file: " + path);

    json root;
    try {
        f >> root;
    } catch (const json::exception& e) {
        throw VaultError(std::string("invalid JSON: ") + e.what());
    }

    // folder id -> name
    std::map<std::string, std::string> folders;
    for (const auto& fo : root.value("folders", json::array()))
        if (fo.contains("id") && !fo["id"].is_null())
            folders[fo["id"].get<std::string>()] =
                fo.value("name", std::string{});

    auto str = [](const json& j, const char* key) -> std::string {
        return j.contains(key) && j[key].is_string()
                   ? j[key].get<std::string>() : std::string{};
    };

    TransferResult res;
    for (const auto& item : root.value("items", json::array())) {
        Entry e;
        e.title = str(item, "name");
        if (e.title.empty()) { ++res.skipped; continue; }

        const int type = item.value("type", 0);
        e.notes = str(item, "notes");

        // preserve folder as a notes line
        const std::string fid = str(item, "folderId");
        if (auto it = folders.find(fid); it != folders.end() && !it->second.empty()) {
            if (!e.notes.empty()) e.notes += "\n";
            e.notes += "[Folder: " + it->second + "]";
        }

        // lsPass round-trip tag?
        bool is_apikey = false;
        std::string field_apikey, field_keyname;
        for (const auto& fld : item.value("fields", json::array())) {
            const std::string n = str(fld, "name");
            if (n == "lsPassType" && str(fld, "value") == "apikey")
                is_apikey = true;
            else if (n == "API Key")
                field_apikey = str(fld, "value");
            else if (n == "Key name")
                field_keyname = str(fld, "value");
        }

        if (type == 1) { // Login
            e.type = EntryType::Login;
            const auto& login = item.contains("login") ? item["login"] : json{};
            e.username = str(login, "username");
            e.secret   = str(login, "password");
            const auto uris = login.contains("uris") && login["uris"].is_array()
                                  ? login["uris"] : json::array();
            for (const auto& u : uris) {
                const std::string uri = str(u, "uri");
                if (!uri.empty()) { e.url = uri; break; }
            }
        } else if (type == 2) { // Secure Note
            if (is_apikey) {
                e.type = EntryType::ApiKey;
                e.secret = field_apikey;
                e.username = field_keyname;
            } else {
                e.type = EntryType::Note;
                e.secret = e.notes;   // note body
                e.notes.clear();
                // recover "Additional notes" field written by our exporter
                for (const auto& fld : item.value("fields", json::array()))
                    if (str(fld, "name") == "Additional notes")
                        e.notes = str(fld, "value");
            }
        } else { // 3=Card, 4=Identity — no lsPass equivalent
            ++res.skipped;
            continue;
        }

        e.created = parse_iso8601(str(item, "creationDate"));
        e.updated = parse_iso8601(str(item, "revisionDate"));
        vault.add_entry(std::move(e));
        ++res.imported;
    }
    return res;
}

} // namespace lspass
