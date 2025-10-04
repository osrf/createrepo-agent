cmake_minimum_required(VERSION 3.15)

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(gpgme QUIET IMPORTED_TARGET gpgme)
  list(GET gpgme_LINK_LIBRARIES 0 gpgme_LIBRARY)
endif()

if(NOT gpgme_FOUND)
  find_program(GPGME_CONFIG NAMES gpgme-config)
  if(GPGME_CONFIG)
    include(use_config_util)

    extract_libs(gpgme_LINK_LIBRARIES
      ${GPGME_CONFIG} --libs)
    list(GET gpgme_LINK_LIBRARIES 0 gpgme_LIBRARY)

    extract_includes(gpgme_INCLUDE_DIRS
      ${GPGME_CONFIG} --cflags)

    execute_process(
      COMMAND ${GPGME_CONFIG} --version
      OUTPUT_VARIABLE gpgme_VERSION
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
endif()

find_package_handle_standard_args(gpgme
  REQUIRED_VARS
    gpgme_LIBRARY
    gpgme_VERSION
  VERSION_VAR gpgme_VERSION)

if(TARGET PkgConfig::gpgme)
  add_library(gpgme ALIAS PkgConfig::gpgme)
else()
  add_library(gpgme UNKNOWN IMPORTED)
  set_target_properties(gpgme PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${gpgme_INCLUDE_DIRS}")
  set(gpgme_OTHER_LIBRARIES ${gpgme_LINK_LIBRARIES})
  list(POP_FRONT gpgme_OTHER_LIBRARIES)
  set_target_properties(gpgme PROPERTIES INTERFACE_LINK_LIBRARIES "${gpgme_OTHER_LIBRARIES}")
  unset(gpgme_OTHER_LIBRARIES)
  set_property(TARGET gpgme APPEND PROPERTY IMPORTED_LOCATION "${gpgme_LIBRARY}")
endif()

mark_as_advanced(gpgme_LIBRARY)
