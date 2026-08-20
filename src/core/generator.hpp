#pragma once

#include <string>

namespace lspass {

struct PasswordOptions {
    int  length        = 20;
    bool lower         = true;
    bool upper         = true;
    bool digits        = true;
    bool symbols       = true;
    bool ambiguous_ok  = false; ///< allow Il1O0 etc.
};

/// Cryptographically secure password generator.
/// Uses the kernel CSPRNG (via libsodium) with rejection sampling,
/// so there is no modulo bias. Guarantees at least one character from
/// every enabled class. Throws std::invalid_argument for unusable options.
std::string generate_password(const PasswordOptions& opt);

/// Shannon entropy (bits) of the configured character space.
double password_entropy_bits(const PasswordOptions& opt);

/// A readable passphrase of `words` lower-case words joined by `sep`.
std::string generate_passphrase(int words = 4, char sep = '-');

} // namespace lspass
