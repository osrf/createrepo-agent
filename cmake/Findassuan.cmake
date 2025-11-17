cmake_minimum_required(VERSION 3.15)

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(assuan QUIET IMPORTED_TARGET libassuan)
  list(GET assuan_LINK_LIBRARIES 0 assuan_LIBRARY)
endif()

if(NOT assuan_FOUND)
  find_program(LIBASSUAN_CONFIG NAMES libassuan-config)
  if(LIBASSUAN_CONFIG)
    include(use_config_util)

    extract_libs(assuan_LINK_LIBRARIES
      ${LIBASSUAN_CONFIG} --libs)
    list(GET assuan_LINK_LIBRARIES 0 assuan_LIBRARY)

    extract_includes(assuan_INCLUDE_DIRS
      ${LIBASSUAN_CONFIG} --cflags)

    execute_process(
      COMMAND ${LIBASSUAN_CONFIG} --version
      OUTPUT_VARIABLE assuan_VERSION
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
endif()

find_package_handle_standard_args(assuan
  REQUIRED_VARS
    assuan_LIBRARY
    assuan_VERSION
  VERSION_VAR assuan_VERSION)

if(TARGET PkgConfig::assuan)
  add_library(assuan ALIAS PkgConfig::assuan)
else()
  add_library(assuan UNKNOWN IMPORTED)
  set_target_properties(assuan PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${assuan_INCLUDE_DIRS}")
  set(assuan_OTHER_LIBRARIES ${assuan_LINK_LIBRARIES})
  list(POP_FRONT assuan_OTHER_LIBRARIES)
  set_target_properties(assuan PROPERTIES INTERFACE_LINK_LIBRARIES "${assuan_OTHER_LIBRARIES}")
  unset(assuan_OTHER_LIBRARIES)
  set_property(TARGET assuan APPEND PROPERTY IMPORTED_LOCATION "${assuan_LIBRARY}")
endif()

mark_as_advanced(assuan_LIBRARY)
