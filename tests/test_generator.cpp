#include "generator.hpp"
#include "test_framework.hpp"

#include <set>
#include <stdexcept>

using namespace lspass;

TEST(length_and_charset) {
    PasswordOptions o; o.length = 32;
    auto pw = generate_password(o);
    CHECK(pw.size() == 32);
}

TEST(only_digits) {
    PasswordOptions o; o.length = 16;
    o.lower = o.upper = o.symbols = false; o.digits = true;
    auto pw = generate_password(o);
    CHECK(pw.size() == 16);
    for (char c : pw) CHECK(c >= '0' && c <= '9');
}

TEST(each_class_represented) {
    PasswordOptions o; o.length = 8;
    for (int i = 0; i < 200; ++i) {
        auto pw = generate_password(o);
        bool lo=false, up=false, di=false, sy=false;
        for (char c : pw) {
            lo |= c >= 'a' && c <= 'z';
            up |= c >= 'A' && c <= 'Z';
            di |= c >= '0' && c <= '9';
            sy |= !((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9'));
        }
        CHECK(lo && up && di && sy);
    }
}

TEST(no_ambiguous_by_default) {
    PasswordOptions o; o.length = 64;
    auto pw = generate_password(o);
    for (char c : pw)
        CHECK(std::string("Il1O0").find(c) == std::string::npos);
}

TEST(uniqueness) {
    PasswordOptions o; o.length = 24;
    std::set<std::string> seen;
    for (int i = 0; i < 100; ++i)
        seen.insert(generate_password(o));
    CHECK(seen.size() == 100); // collisions would indicate a broken CSPRNG
}

TEST(invalid_options_throw) {
    PasswordOptions o;
    o.lower = o.upper = o.digits = o.symbols = false;
    CHECK_THROWS_AS(generate_password(o), std::invalid_argument);
    PasswordOptions o2; o2.length = 2; // fewer than 4 classes
    CHECK_THROWS_AS(generate_password(o2), std::invalid_argument);
}

TEST(entropy_estimate) {
    PasswordOptions o; o.length = 20;
    double bits = password_entropy_bits(o);
    CHECK(bits > 100.0); // 20 chars from ~87 symbols ≈ 128 bits
}

TEST(passphrase_format) {
    auto pp = generate_passphrase(5, '-');
    int words = 1;
    for (char c : pp) if (c == '-') ++words;
    CHECK(words == 5);
    CHECK(!pp.empty());
}

TEST_MAIN
