cmake_minimum_required(VERSION 3.15)

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(glib-2.0 QUIET REQUIRED IMPORTED_TARGET glib-2.0)
  list(GET glib-2.0_LINK_LIBRARIES 0 glib-2.0_LIBRARY)
  mark_as_advanced(glib-2.0_LIBRARY)
endif()

find_package_handle_standard_args(glib-2.0
  REQUIRED_VARS
    glib-2.0_LIBRARY
    glib-2.0_VERSION
  VERSION_VAR glib-2.0_VERSION)

add_library(glib-2.0 ALIAS PkgConfig::glib-2.0)
