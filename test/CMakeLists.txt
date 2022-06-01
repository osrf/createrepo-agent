enable_language(CXX)

find_package(GTest REQUIRED)

macro(add_cache_test NAME)
  add_executable(test_${NAME} "test_${NAME}.cpp")
  target_link_libraries(test_${NAME}
    GTest::gtest
    GTest::gtest_main
    createrepo-cache)
  add_test(${NAME} test_${NAME})
endmacro()

add_cache_test(repo_cache_flush)
add_cache_test(repo_cache_modify)
add_cache_test(repo_cache_invalidate)
