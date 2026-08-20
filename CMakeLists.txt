cmake_minimum_required(VERSION 3.25)
project(lsPass VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Security hardening for release builds (stack canaries, fortified libc
# calls, PIE + full RELRO / immediate binding).
add_compile_options($<$<CONFIG:Release>:-fstack-protector-strong>
                    $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>
                    $<$<CONFIG:Release>:-fPIE>)
add_link_options($<$<CONFIG:Release>:-pie>
                 $<$<CONFIG:Release>:-Wl,-z,relro,-z,now>)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(GTKMM REQUIRED IMPORTED_TARGET gtkmm-4.0)

# ---- Core library (no GTK dependency, fully unit-testable) ----
find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp REQUIRED)

add_library(lspass_core STATIC
    src/core/crypto.cpp
    src/core/vault.cpp
    src/core/generator.cpp
    src/core/transfer.cpp
)
target_include_directories(lspass_core SYSTEM PUBLIC ${NLOHMANN_JSON_INCLUDE_DIR})
target_include_directories(lspass_core PUBLIC src/core)
target_link_libraries(lspass_core PUBLIC PkgConfig::SQLITE3 PkgConfig::SODIUM)

# ---- GTK application ----
add_executable(lspass
    src/ui/main.cpp
    src/ui/main_window.cpp
    src/ui/entry_dialog.cpp
)
target_link_libraries(lspass PRIVATE lspass_core PkgConfig::GTKMM)

# ---- Tests ----
enable_testing()
foreach(t crypto vault generator transfer)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE lspass_core)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()

# ---- Installation & packaging (.deb via CPack) ----
install(TARGETS lspass RUNTIME DESTINATION bin)
install(FILES packaging/com.lspass.App.desktop
        DESTINATION share/applications)
install(FILES packaging/com.lspass.App.svg
        DESTINATION share/icons/hicolor/scalable/apps)

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "lspass")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "Lee Stripp <leestripp@gmail.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Local encrypted password manager (GTK4)")
set(CPACK_PACKAGE_DESCRIPTION
    "lsPass stores logins, secure notes and API keys in a local encrypted
 SQLite vault. Argon2id key derivation, XChaCha20-Poly1305 AEAD,
 envelope encryption. No network, no cloud, no telemetry.")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://gitlab.com/leestripp/lspass")
# dpkg-shlibdeps resolves exact library dependencies (libgtkmm-4.0-0t64,
# libsodium23, libsqlite3-0, ...) with correct versions automatically.
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
# .deb output lands in ./packages/deb/
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_SOURCE_DIR}/packages/deb")
include(CPack)
