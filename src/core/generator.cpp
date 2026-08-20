#include "generator.hpp"

#include "crypto.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lspass {

namespace {

char random_char_from(const std::string& set) {
    // Rejection sampling: discard bytes that would introduce modulo bias.
    const std::uint32_t bound =
        256u - (256u % static_cast<std::uint32_t>(set.size()));
    for (;;) {
        auto b = crypto::random_bytes(1);
        const auto v = static_cast<std::uint8_t>(b[0]);
        if (v < bound)
            return set[v % set.size()];
    }
}

std::string ambiguous_filtered(std::string s) {
    const std::string bad = "Il1O0`'\"\\";
    s.erase(std::remove_if(s.begin(), s.end(),
                           [&](char c) { return bad.find(c) != std::string::npos; }),
            s.end());
    return s;
}

} // namespace

std::string generate_password(const PasswordOptions& opt) {
    std::vector<std::string> classes;
    std::string all;

    std::string lower   = "abcdefghijklmnopqrstuvwxyz";
    std::string upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string digits  = "0123456789";
    std::string symbols = "!@#$%^&*()-_=+[]{};:,.<>?/~";

    if (!opt.ambiguous_ok) {
        lower   = ambiguous_filtered(lower);
        upper   = ambiguous_filtered(upper);
        digits  = ambiguous_filtered(digits);
        symbols = ambiguous_filtered(symbols);
    }

    if (opt.lower)   { classes.push_back(lower);   all += lower; }
    if (opt.upper)   { classes.push_back(upper);   all += upper; }
    if (opt.digits)  { classes.push_back(digits);  all += digits; }
    if (opt.symbols) { classes.push_back(symbols); all += symbols; }

    if (all.empty())
        throw std::invalid_argument("at least one character class required");
    if (opt.length < static_cast<int>(classes.size()))
        throw std::invalid_argument("length too short for enabled classes");
    if (opt.length > 1024)
        throw std::invalid_argument("length unreasonable");

    std::string out;
    out.reserve(static_cast<std::size_t>(opt.length));

    // Guarantee one char from each enabled class.
    for (const auto& cls : classes)
        out.push_back(random_char_from(cls));
    while (static_cast<int>(out.size()) < opt.length)
        out.push_back(random_char_from(all));

    // Shuffle with the CSPRNG so the guaranteed chars are not at the front.
    for (std::size_t i = out.size() - 1; i > 0; --i) {
        const std::uint32_t bound =
            256u - (256u % static_cast<std::uint32_t>(i + 1));
        std::size_t j;
        for (;;) {
            auto b = crypto::random_bytes(1);
            const auto v = static_cast<std::uint8_t>(b[0]);
            if (v < bound) { j = v % (i + 1); break; }
        }
        std::swap(out[i], out[j]);
    }
    return out;
}

double password_entropy_bits(const PasswordOptions& opt) {
    std::size_t space = 0;
    if (opt.lower)   space += 26;
    if (opt.upper)   space += 26;
    if (opt.digits)  space += 10;
    if (opt.symbols) space += 25;
    if (space == 0) return 0.0;
    // log2(space) * length
    double bits = 0.0;
    for (std::size_t s = space; s > 1; s >>= 1) bits += 1.0;
    // precise log2 via frexp-style loop is overkill; use log from <cmath>
    return opt.length * std::log2(static_cast<double>(space));
}

std::string generate_passphrase(int words, char sep) {
    static const std::vector<std::string> wordlist = {
        "amber","anchor","april","aspen","atlas","baker","basil","beacon",
        "birch","bison","breeze","brook","cabin","cactus","cedar","cinder",
        "cliff","clover","cobalt","comet","coral","crane","creek","crystal",
        "dagger","delta","drift","dune","eagle","ember","falcon","fern",
        "fjord","flint","forge","fox","frost","gale","garnet","glacier",
        "granite","grove","harbor","hazel","heron","hollow","island","ivory",
        "jade","juniper","kelp","kestrel","lagoon","larch","laurel","lilac",
        "linden","lotus","lunar","maple","marble","meadow","mesa","mist",
        "moss","north","oasis","onyx","opal","orbit","otter","pearl",
        "pebble","pine","plume","quartz","quill","raven","reed","ridge",
        "river","rowan","sable","sage","shadow","shore","sierra","slate",
        "solar","sparrow","spruce","stone","storm","summit","thorn","tide",
        "timber","topaz","trail","tundra","vale","velvet","violet","walnut",
        "willow","winter","wren","zephyr","zinc",
    };
    if (words < 2 || words > 16)
        throw std::invalid_argument("words must be between 2 and 16");

    std::string out;
    for (int i = 0; i < words; ++i) {
        if (i) out.push_back(sep);
        // rejection sampling over wordlist size
        const std::uint32_t n = static_cast<std::uint32_t>(wordlist.size());
        const std::uint32_t bound = 256u - (256u % n);
        for (;;) {
            auto b = crypto::random_bytes(1);
            const auto v = static_cast<std::uint8_t>(b[0]);
            if (v < bound) { out += wordlist[v % n]; break; }
        }
    }
    return out;
}

} // namespace lspass
