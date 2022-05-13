cmake_minimum_required(VERSION 3.10)

project(createrepo-agent C)

# Default to C11
if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

add_compile_options(-Wall -Wextra -Wconversion -Wpedantic)

include(FindPkgConfig)
pkg_check_modules(CREATEREPO_C REQUIRED createrepo_c>=0.18.0)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(GPG_ERROR REQUIRED gpg-error)
pkg_check_modules(LIBASSUAN REQUIRED libassuan)

# Repository operations
add_library(createrepo-cache STATIC
  src/createrepo-cache/coordinator.c
  src/createrepo-cache/repo_cache.c)
target_include_directories(createrepo-cache PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:include>)
target_include_directories(createrepo-cache SYSTEM PUBLIC
  ${CREATEREPO_C_INCLUDE_DIRS}
  ${GLIB2_INCLUDE_DIRS})
target_link_libraries(createrepo-cache PRIVATE
  ${CREATEREPO_C_LIBRARIES}
  ${GLIB2_LIBRARIES})
target_compile_definitions(createrepo-cache PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_CACHE")

# Agent
add_executable(createrepo-agent
  src/createrepo-agent/agent.c
  src/createrepo-agent/client.c
  src/createrepo-agent/command.c
  src/createrepo-agent/options.c)
target_include_directories(createrepo-agent PRIVATE src)
target_include_directories(createrepo-agent SYSTEM PRIVATE
  ${CREATEREPO_C_INCLUDE_DIRS}
  ${GLIB2_INCLUDE_DIRS}
  ${GPG_ERROR_INCLUDE_DIRS}
  ${LIBASSUAN_INCLUDE_DIRS})
target_link_libraries(createrepo-agent PRIVATE
  createrepo-cache
  ${CREATEREPO_C_LIBRARIES}
  ${GLIB2_LIBRARIES}
  ${GPG_ERROR_LIBRARIES}
  ${LIBASSUAN_LIBRARIES})
target_compile_definitions(createrepo-agent PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_AGENT")

install(TARGETS
  createrepo-agent)
