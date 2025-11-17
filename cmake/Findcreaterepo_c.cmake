cmake_minimum_required(VERSION 3.15)

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(createrepo_c QUIET REQUIRED IMPORTED_TARGET createrepo_c)
  list(GET createrepo_c_LINK_LIBRARIES 0 createrepo_c_LIBRARY)
  mark_as_advanced(createrepo_c_LIBRARY)
endif()

find_package_handle_standard_args(createrepo_c
  REQUIRED_VARS
    createrepo_c_LIBRARY
    createrepo_c_VERSION
  VERSION_VAR createrepo_c_VERSION)

add_library(createrepo_c ALIAS PkgConfig::createrepo_c)
