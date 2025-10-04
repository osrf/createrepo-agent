cmake_minimum_required(VERSION 3.15)

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(gpg-error QUIET IMPORTED_TARGET gpg-error)
  list(GET gpg-error_LINK_LIBRARIES 0 gpg-error_LIBRARY)
endif()

if(NOT gpg-error_FOUND)
  find_program(GPG_ERROR_CONFIG NAMES gpg-error-config)
  if(GPG_ERROR_CONFIG)
    include(use_config_util)

    extract_libs(gpg-error_LINK_LIBRARIES
      ${GPG_ERROR_CONFIG} --libs)
    list(GET gpg-error_LINK_LIBRARIES 0 gpg-error_LIBRARY)

    extract_includes(gpg-error_INCLUDE_DIRS
      ${GPG_ERROR_CONFIG} --cflags)

    execute_process(
      COMMAND ${GPG_ERROR_CONFIG} --version
      OUTPUT_VARIABLE gpg-error_VERSION
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
endif()

find_package_handle_standard_args(gpg-error
  REQUIRED_VARS
    gpg-error_LIBRARY
    gpg-error_VERSION
  VERSION_VAR gpg-error_VERSION)

if(TARGET PkgConfig::gpg-error)
  add_library(gpg-error ALIAS PkgConfig::gpg-error)
else()
  add_library(gpg-error UNKNOWN IMPORTED)
  set_target_properties(gpg-error PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${gpg-error_INCLUDE_DIRS}")
  set(gpg-error_OTHER_LIBRARIES ${gpg-error_LINK_LIBRARIES})
  list(POP_FRONT gpg-error_OTHER_LIBRARIES)
  set_target_properties(gpg-error PROPERTIES INTERFACE_LINK_LIBRARIES "${gpg-error_OTHER_LIBRARIES}")
  unset(gpg-error_OTHER_LIBRARIES)
  set_property(TARGET gpg-error APPEND PROPERTY IMPORTED_LOCATION "${gpg-error_LIBRARY}")
endif()

mark_as_advanced(gpg-error_LIBRARY)
