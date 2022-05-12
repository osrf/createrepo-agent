cmake_minimum_required(VERSION 3.10)

project(createrepo_agent C)

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
add_library(createrepo_cache STATIC
  src/createrepo_cache/coordinator.c
  src/createrepo_cache/repo_cache.c)
target_include_directories(createrepo_cache PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:include>)
target_include_directories(createrepo_cache SYSTEM PUBLIC
  ${CREATEREPO_C_INCLUDE_DIRS}
  ${GLIB2_INCLUDE_DIRS})
target_link_libraries(createrepo_cache PRIVATE
  ${CREATEREPO_C_LIBRARIES}
  ${GLIB2_LIBRARIES})
target_compile_definitions(createrepo_cache PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_CACHE")

# Server
add_executable(createrepo-agent
  src/createrepo_agent/agent.c
  src/createrepo_agent/agent_options.c
  src/createrepo_agent/client.c
  src/createrepo_agent/command.c)
target_include_directories(createrepo-agent PRIVATE src)
target_include_directories(createrepo-agent SYSTEM PRIVATE
  ${CREATEREPO_C_INCLUDE_DIRS}
  ${GLIB2_INCLUDE_DIRS}
  ${GPG_ERROR_INCLUDE_DIRS}
  ${LIBASSUAN_INCLUDE_DIRS})
target_link_libraries(createrepo-agent PRIVATE
  createrepo_cache
  ${CREATEREPO_C_LIBRARIES}
  ${GLIB2_LIBRARIES}
  ${GPG_ERROR_LIBRARIES}
  ${LIBASSUAN_LIBRARIES})
target_compile_definitions(createrepo-agent PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_AGENT")

# Client
add_executable(createrepo_connect_agent
  src/createrepo_agent/client.c
  src/createrepo_agent/connect-agent.c)
target_include_directories(createrepo_connect_agent PRIVATE src)
target_include_directories(createrepo_connect_agent SYSTEM PRIVATE
  ${GLIB2_INCLUDE_DIRS}
  ${GPG_ERROR_INCLUDE_DIRS}
  ${LIBASSUAN_INCLUDE_DIRS})
target_link_libraries(createrepo_connect_agent PRIVATE
  ${GLIB2_LIBRARIES}
  ${GPG_ERROR_LIBRARIES}
  ${LIBASSUAN_LIBRARIES})

install(TARGETS
  createrepo-agent
  createrepo_connect_agent)
