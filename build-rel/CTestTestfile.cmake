# CMake generated Testfile for 
# Source directory: /workspace/Apps-GTK4/lsPass
# Build directory: /workspace/Apps-GTK4/lsPass/build-rel
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[crypto]=] "/workspace/Apps-GTK4/lsPass/build-rel/test_crypto")
set_tests_properties([=[crypto]=] PROPERTIES  _BACKTRACE_TRIPLES "/workspace/Apps-GTK4/lsPass/CMakeLists.txt;49;add_test;/workspace/Apps-GTK4/lsPass/CMakeLists.txt;0;")
add_test([=[vault]=] "/workspace/Apps-GTK4/lsPass/build-rel/test_vault")
set_tests_properties([=[vault]=] PROPERTIES  _BACKTRACE_TRIPLES "/workspace/Apps-GTK4/lsPass/CMakeLists.txt;49;add_test;/workspace/Apps-GTK4/lsPass/CMakeLists.txt;0;")
add_test([=[generator]=] "/workspace/Apps-GTK4/lsPass/build-rel/test_generator")
set_tests_properties([=[generator]=] PROPERTIES  _BACKTRACE_TRIPLES "/workspace/Apps-GTK4/lsPass/CMakeLists.txt;49;add_test;/workspace/Apps-GTK4/lsPass/CMakeLists.txt;0;")
