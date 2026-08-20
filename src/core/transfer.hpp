#pragma once

#include "vault.hpp"
#include <string>

namespace lspass {

struct TransferResult {
    int imported = 0;
    int exported = 0;
    int skipped  = 0;   ///< unsupported item types (cards, identities)
};

/// Export all entries to Bitwarden-compatible plaintext JSON.
/// WARNING: the output file contains ALL SECRETS IN PLAINTEXT.
/// File permissions are set to 0600; delete it after use.
void export_json(Vault& vault, const std::string& path);

/// Import a Bitwarden-format plaintext JSON export.
///   type 1 (Login)  -> Login entry (first URI becomes the URL)
///   type 2 (Note)   -> Secure Note (notes become the note body)
///   lsPass API keys round-trip via custom fields (lsPassType=apikey)
///   types 3/4 (Card/Identity) are skipped and counted
/// Folder names are preserved as a "[Folder: name]" notes line.
TransferResult import_json(Vault& vault, const std::string& path);

} // namespace lspass
