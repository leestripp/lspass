cmake_minimum_required(VERSION 3.25)
project(lsPass VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(GTKMM REQUIRED IMPORTED_TARGET gtkmm-4.0)

# ---- Core library (no GTK dependency, fully unit-testable) ----
add_library(lspass_core STATIC
    src/core/crypto.cpp
    src/core/vault.cpp
    src/core/generator.cpp
)
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
foreach(t crypto vault generator)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE lspass_core)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()
