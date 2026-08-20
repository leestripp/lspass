#pragma once
// Minimal test framework: TEST() registers, CHECK() verifies, main() runs.
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace tf {
struct Case { std::string name; std::function<void()> fn; };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
inline int& failures() { static int f = 0; return f; }
struct Registrar {
    Registrar(std::string name, std::function<void()> fn) {
        registry().push_back({std::move(name), std::move(fn)});
    }
};
} // namespace tf

#define TEST(name) \
    static void name(); \
    static tf::Registrar reg_##name(#name, name); \
    static void name()

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        ++tf::failures(); \
    } \
} while (0)

#define CHECK_THROWS_AS(expr, exctype) do { \
    bool threw = false; \
    try { (void)(expr); } catch (const exctype&) { threw = true; } \
    catch (...) {} \
    if (!threw) { \
        std::fprintf(stderr, "  FAIL %s:%d: expected %s from %s\n", \
                     __FILE__, __LINE__, #exctype, #expr); \
        ++tf::failures(); \
    } \
} while (0)

#define TEST_MAIN \
int main() { \
    int failed_cases = 0; \
    for (auto& c : tf::registry()) { \
        std::fprintf(stderr, "[ RUN  ] %s\n", c.name.c_str()); \
        int before = tf::failures(); \
        try { c.fn(); } \
        catch (const std::exception& e) { \
            std::fprintf(stderr, "  FAIL exception: %s\n", e.what()); \
            ++tf::failures(); \
        } \
        if (tf::failures() == before) std::fprintf(stderr, "[  OK  ] %s\n", c.name.c_str()); \
        else { std::fprintf(stderr, "[ FAIL ] %s\n", c.name.c_str()); ++failed_cases; } \
    } \
    std::fprintf(stderr, "%zu case(s), %d failed\n", tf::registry().size(), failed_cases); \
    return failed_cases ? 1 : 0; \
}
