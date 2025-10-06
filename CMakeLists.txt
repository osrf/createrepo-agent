cmake_minimum_required(VERSION 3.15)

project(createrepo-agent C)

set(CRA_VERSION_MAJOR 0)
set(CRA_VERSION_MINOR 4)
set(CRA_VERSION_PATCH 2)
set(CRA_VERSION "${CRA_VERSION_MAJOR}.${CRA_VERSION_MINOR}.${CRA_VERSION_PATCH}")

# Default to C11
if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

add_compile_options(-Wall -Wextra -Wconversion -Wpedantic)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(createrepo_c 0.13.0 MODULE REQUIRED)
find_package(glib-2.0 MODULE REQUIRED)
find_package(gpg-error 1.13 MODULE REQUIRED)
find_package(gpgme 1.7.0 MODULE REQUIRED)
find_package(assuan 2.2.0 MODULE REQUIRED)

# Repository operations
add_library(createrepo-cache STATIC
  src/createrepo-cache/coordinator.c
  src/createrepo-cache/repo_cache.c)
target_include_directories(createrepo-cache PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
target_link_libraries(createrepo-cache PUBLIC
  createrepo_c
  glib-2.0
  gpg-error
  gpgme)
target_compile_definitions(createrepo-cache PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_CACHE")
set_target_properties(createrepo-cache PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  SOVERSION ${CRA_VERSION_MAJOR}
  VERSION ${CRA_VERSION})

# Client/Server
configure_file(
  "src/${PROJECT_NAME}/common.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/gen/${PROJECT_NAME}/common.h"
  @ONLY)
add_library(createrepo-agent-lib OBJECT
  src/${PROJECT_NAME}/client.c
  src/${PROJECT_NAME}/command.c
  src/${PROJECT_NAME}/options.c
  src/${PROJECT_NAME}/server.c)
target_include_directories(createrepo-agent-lib PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/gen>)
target_link_libraries(createrepo-agent-lib PRIVATE
  createrepo-cache
  createrepo_c)
target_link_libraries(createrepo-agent-lib PUBLIC
  assuan
  gpg-error
  glib-2.0)
target_compile_definitions(createrepo-agent-lib PRIVATE
  -DG_LOG_DOMAIN="CREATEREPO_AGENT")
set_target_properties(createrepo-agent-lib PROPERTIES
  POSITION_INDEPENDENT_CODE ON)

# Executable
add_executable(${PROJECT_NAME}
  src/${PROJECT_NAME}/agent.c)
target_link_libraries(${PROJECT_NAME} PRIVATE
  assuan
  createrepo-agent-lib
  createrepo_c
  glib-2.0
  gpg-error
  gpgme)
install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION bin
  COMPONENT bin)

# Python bindings
cmake_policy(SET CMP0094 NEW)
set(Python_FIND_UNVERSIONED_NAMES FIRST
  CACHE STRING "Defines how the generic names will be searched for Python")
if(CMAKE_VERSION VERSION_LESS "3.18")
  set(Python_COMPONENTS Interpreter Development)
else()
  set(Python_COMPONENTS Interpreter Development.Module)
endif()
find_package(Python 3 QUIET COMPONENTS ${Python_COMPONENTS})
option(WITH_PYTHON "Build Python bindings" ${Python_FOUND})
if(WITH_PYTHON)
  # Find Python again, this time REQUIRED
  find_package(Python 3 REQUIRED COMPONENTS ${Python_COMPONENTS})

  python_add_library(createrepo_agent MODULE
    src/python/client.c
    src/python/init.c
    src/python/server.c)
  target_link_libraries(createrepo_agent PRIVATE
    createrepo-agent-lib)

  if(SKBUILD)
    set(PYTHON_INSTALL_DIR ${SKBUILD_PLATLIB_DIR})
  else()
    # Determine package installation location
    string(JOIN "; " PYTHON_INSTALL_DIR_CMD
      "from os.path import sep"
      "from sys import stdout"
      "from sysconfig import get_path"
      "stdout.write(get_path('platlib', vars={'base': '', 'platbase': ''}).lstrip(sep))"
    )
    execute_process(COMMAND ${Python_EXECUTABLE} -c "${PYTHON_INSTALL_DIR_CMD}"
      OUTPUT_VARIABLE PYTHON_INSTALL_DIR)

    set(DISTINFO_NAME "createrepo_agent-${CRA_VERSION}.dist-info")
    set(DISTINFO_DIR "${CMAKE_CURRENT_BINARY_DIR}/${DISTINFO_NAME}")
    file(GENERATE
      OUTPUT "${DISTINFO_DIR}/INSTALLER"
      CONTENT "cmake\n")
    file(GENERATE
      OUTPUT "${DISTINFO_DIR}/METADATA"
      CONTENT "Metadata-Version: 1.1\nName: createrepo-agent\nVersion: ${CRA_VERSION}\n")
    string(JOIN "\n" RECORD_CONTENT
        "$<TARGET_FILE_NAME:createrepo_agent>,,"
        "${DISTINFO_NAME}/INSTALLER,,"
        "${DISTINFO_NAME}/METADATA,,"
        "${DISTINFO_NAME}/RECORD,,"
        "${DISTINFO_NAME}/top_level.txt,,"
    )
    file(GENERATE
      OUTPUT "${DISTINFO_DIR}/RECORD"
      CONTENT "${RECORD_CONTENT}\n")
    file(GENERATE
      OUTPUT "${DISTINFO_DIR}/top_level.txt"
      CONTENT "createrepo_agent\n")
    install(DIRECTORY ${DISTINFO_DIR}
      DESTINATION ${PYTHON_INSTALL_DIR}
      COMPONENT python)
  endif()

  install(TARGETS createrepo_agent
    RUNTIME DESTINATION ${PYTHON_INSTALL_DIR}
    LIBRARY DESTINATION ${PYTHON_INSTALL_DIR}
    COMPONENT python)
endif()

add_subdirectory(doc)

set(MEMORYCHECK_SUPPRESSIONS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/test/valgrind.supp"
  CACHE FILEPATH "File that contains suppressions for the memory checker")

include(CTest)
if(BUILD_TESTING)
  add_subdirectory(test)
endif()
