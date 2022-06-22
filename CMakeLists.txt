cmake_minimum_required(VERSION 3.10)

project(createrepo-agent C)

set(CRA_VERSION_MAJOR 0)
set(CRA_VERSION_MINOR 3)
set(CRA_VERSION_PATCH 0)
set(CRA_VERSION "${CRA_VERSION_MAJOR}.${CRA_VERSION_MINOR}.${CRA_VERSION_PATCH}")

# Default to C11
if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

add_compile_options(-Wall -Wextra -Wconversion -Wpedantic)

include(FindPkgConfig)
pkg_check_modules(CREATEREPO_C REQUIRED createrepo_c)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(GPG_ERROR REQUIRED gpg-error)
pkg_check_modules(GPGME REQUIRED gpgme)
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
  ${GLIB2_INCLUDE_DIRS}
  ${GPGME_INCLUDE_DIRS})
target_link_libraries(createrepo-cache PRIVATE
  ${CREATEREPO_C_LIBRARIES}
  ${GLIB2_LIBRARIES}
  ${GPGME_LIBRARIES})
target_compile_definitions(createrepo-cache PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_CACHE")
set_target_properties(createrepo-cache PROPERTIES
  SOVERSION ${CRA_VERSION_MAJOR}
  VERSION ${CRA_VERSION})

# Agent
configure_file(
  "src/${PROJECT_NAME}/common.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/gen/${PROJECT_NAME}/common.h"
  @ONLY)
add_executable(${PROJECT_NAME}
  src/${PROJECT_NAME}/agent.c
  src/${PROJECT_NAME}/client.c
  src/${PROJECT_NAME}/command.c
  src/${PROJECT_NAME}/options.c)
target_include_directories(${PROJECT_NAME} PRIVATE src "${CMAKE_CURRENT_BINARY_DIR}/gen")
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE
  ${CREATEREPO_C_INCLUDE_DIRS}
  ${GLIB2_INCLUDE_DIRS}
  ${GPG_ERROR_INCLUDE_DIRS}
  ${GPGME_INCLUDE_DIRS}
  ${LIBASSUAN_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE
  createrepo-cache
  ${CREATEREPO_C_LIBRARIES}
  ${GLIB2_LIBRARIES}
  ${GPG_ERROR_LIBRARIES}
  ${GPGME_LIBRARIES}
  ${LIBASSUAN_LIBRARIES})
target_compile_definitions(${PROJECT_NAME} PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_AGENT")
install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION bin
  COMPONENT bin)

add_subdirectory(doc)

set(MEMORYCHECK_SUPPRESSIONS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/test/valgrind.supp"
  CACHE FILEPATH "File that contains suppressions for the memory checker")

include(CTest)
if(BUILD_TESTING)
  add_subdirectory(test)
endif()
