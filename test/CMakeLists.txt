enable_language(CXX)

# Default to C++17
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
endif()

find_package(GTest REQUIRED)

macro(add_cache_test NAME)
  add_executable(test_${NAME} "main.cpp" "test_${NAME}.cpp")
  target_link_libraries(test_${NAME}
    createrepo-cache
    GTest::gtest)
  add_test(NAME ${NAME} COMMAND test_${NAME})
endmacro()

macro(add_integration_test NAME)
  add_executable(test_${NAME} "integration_main.cpp" "test_${NAME}.cpp")
  target_link_libraries(test_${NAME}
    createrepo-agent-lib
    GTest::gtest)
  add_test(NAME ${NAME} COMMAND test_${NAME})
endmacro()

add_test(NAME agent_help COMMAND createrepo-agent --help)
add_test(NAME agent_version COMMAND createrepo-agent --version)

file(COPY "fixtures" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_cache_test(coordinator)
add_cache_test(copy_file)
add_cache_test(repo_cache_flush)
add_cache_test(repo_cache_invalidate)
add_cache_test(repo_cache_modify)

add_integration_test(smoke)
