enable_language(CXX)

# Default to C++17
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
endif()

find_package(GTest REQUIRED)

macro(add_cache_test NAME)
  add_executable(test_${NAME} "test_${NAME}.cpp")
  target_link_libraries(test_${NAME}
    ${GTEST_LIBRARIES}
    ${GTEST_MAIN_LIBRARIES}
    createrepo-cache)
  add_test(${NAME} test_${NAME})
endmacro()

add_cache_test(repo_cache_flush)
add_cache_test(repo_cache_modify)
add_cache_test(repo_cache_invalidate)
