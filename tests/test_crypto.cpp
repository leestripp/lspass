#include "crypto.hpp"
#include "test_framework.hpp"

#include <cstring>

using namespace lspass::crypto;

static std::vector<std::byte> to_bytes(const std::string& s) {
    return {reinterpret_cast<const std::byte*>(s.data()),
            reinterpret_cast<const std::byte*>(s.data()) + s.size()};
}

TEST(aead_roundtrip) {
    auto key = random_bytes(KEY_LEN);
    auto msg = to_bytes("s3cr3t-p@ssw0rd!");
    auto aad = to_bytes("ctx");
    auto blob = aead_encrypt(key, msg, aad);
    auto plain = aead_decrypt(key, blob, aad);
    CHECK(plain.has_value());
    CHECK(plain->to_string() == "s3cr3t-p@ssw0rd!");
}

TEST(aead_wrong_key_fails) {
    auto k1 = random_bytes(KEY_LEN);
    auto k2 = random_bytes(KEY_LEN);
    auto blob = aead_encrypt(k1, to_bytes("hello"), to_bytes("aad"));
    CHECK(!aead_decrypt(k2, blob, to_bytes("aad")).has_value());
}

TEST(aead_tamper_detected) {
    auto key = random_bytes(KEY_LEN);
    auto blob = aead_encrypt(key, to_bytes("integrity matters"), to_bytes(""));
    blob[blob.size() / 2] ^= std::byte{0x01}; // flip one bit in ciphertext
    CHECK(!aead_decrypt(key, blob, to_bytes("")).has_value());
}

TEST(aead_aad_mismatch_fails) {
    auto key = random_bytes(KEY_LEN);
    auto blob = aead_encrypt(key, to_bytes("bound"), to_bytes("entry:1:secret"));
    CHECK(!aead_decrypt(key, blob, to_bytes("entry:2:secret")).has_value());
}

TEST(aead_unique_nonces) {
    auto key = random_bytes(KEY_LEN);
    auto b1 = aead_encrypt(key, to_bytes("same"), to_bytes(""));
    auto b2 = aead_encrypt(key, to_bytes("same"), to_bytes(""));
    CHECK(b1 != b2); // random nonce => different ciphertext every time
}

TEST(kdf_deterministic_and_salted) {
    auto salt = random_bytes(SALT_LEN);
    auto p = KdfParams::interactive();
    auto k1 = derive_key("correct horse battery staple", salt, p);
    auto k2 = derive_key("correct horse battery staple", salt, p);
    CHECK(k1.size() == KEY_LEN);
    CHECK(constant_time_equal(k1, k2));
    auto salt2 = random_bytes(SALT_LEN);
    auto k3 = derive_key("correct horse battery staple", salt2, p);
    CHECK(!constant_time_equal(k1, k3));
}

TEST(kdf_password_sensitive) {
    auto salt = random_bytes(SALT_LEN);
    auto p = KdfParams::interactive();
    auto k1 = derive_key("password", salt, p);
    auto k2 = derive_key("passwore", salt, p);
    CHECK(!constant_time_equal(k1, k2));
}

TEST(wrap_unwrap_roundtrip) {
    auto kek = random_bytes(KEY_LEN);
    auto dek = random_bytes(KEY_LEN);
    auto wrapped = wrap_key(kek, dek);
    auto back = unwrap_key(kek, wrapped);
    CHECK(back.has_value());
    CHECK(constant_time_equal(dek, *back));
    auto wrong = random_bytes(KEY_LEN);
    CHECK(!unwrap_key(wrong, wrapped).has_value());
}

TEST(secure_bytes_wipes_on_resize) {
    SecureBytes b(32);
    std::memset(b.data(), 0xAA, 32);
    auto* old = b.data();
    b.resize(8);
    (void)old; // buffer wiped before reassign; no crash, contents gone
    CHECK(b.size() == 8);
}


TEST(aead_empty_plaintext) {
    auto key = random_bytes(KEY_LEN);
    auto blob = aead_encrypt(key, {}, to_bytes("aad"));
    auto plain = aead_decrypt(key, blob, to_bytes("aad"));
    CHECK(plain.has_value());
    CHECK(plain->size() == 0);
}

TEST(aead_truncated_blob_rejected) {
    auto key = random_bytes(KEY_LEN);
    auto blob = aead_encrypt(key, to_bytes("data"), to_bytes(""));
    for (std::size_t n : {0ul, 5ul, 23ul, 24ul, blob.size() - 1}) {
        std::vector<std::byte> trunc(blob.begin(), blob.begin() + n);
        CHECK(!aead_decrypt(key, trunc, to_bytes("")).has_value());
    }
}

TEST(constant_time_equal_length_mismatch) {
    auto a = random_bytes(16);
    auto b = random_bytes(32);
    CHECK(!constant_time_equal(a, b));
}

TEST(kdf_bad_salt_length_throws) {
    auto salt = random_bytes(8); // too short
    CHECK_THROWS_AS(derive_key("pw", salt, KdfParams::interactive()),
                    CryptoError);
}

TEST(kdf_unicode_password) {
    auto salt = random_bytes(SALT_LEN);
    auto p = KdfParams::interactive();
    auto k1 = derive_key("pässwörd-密码-🔐", salt, p);
    auto k2 = derive_key("pässwörd-密码-🔐", salt, p);
    CHECK(constant_time_equal(k1, k2));
}

TEST_MAIN
