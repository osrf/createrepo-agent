function(extract_includes OUT_VAR)
  list(SUBLIST ARGV 1 -1 CMDARGS)
  execute_process(
    COMMAND ${CMDARGS}
    OUTPUT_VARIABLE STANDARD_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE COMMAND_RESULT)
  if(NOT "${COMMAND_RESULT}" STREQUAL "0")
    return()
  endif()

  separate_arguments(STANDARD_OUTPUT)

  set(INCDIRS)
  foreach(arg ${STANDARD_OUTPUT})
    if("${arg}" MATCHES "^-I(.+)")
      list(APPEND INCDIRS "${CMAKE_MATCH_1}")
    endif()
  endforeach()

  set(FULL_INCDIRS)
  foreach(incdir ${INCDIRS})
    file(TO_CMAKE_PATH "${incdir}" incdir)
    list(APPEND FULL_INCDIRS "${incdir}")
  endforeach()

  set(${OUT_VAR} ${FULL_INCDIRS} PARENT_SCOPE)
endfunction()

function(extract_libs OUT_VAR)
  list(SUBLIST ARGV 1 -1 CMDARGS)
  execute_process(
    COMMAND ${CMDARGS}
    OUTPUT_VARIABLE STANDARD_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE COMMAND_RESULT)
  if(NOT "${COMMAND_RESULT}" STREQUAL "0")
    return()
  endif()

  separate_arguments(STANDARD_OUTPUT)

  set(LIBDIRS)
  set(LIBS)
  foreach(arg ${STANDARD_OUTPUT})
    if("${arg}" MATCHES "^-L(.+)")
      list(APPEND LIBDIRS "${CMAKE_MATCH_1}")
    elseif("${arg}" MATCHES "^-l(.+)")
      list(APPEND LIBS "${CMAKE_MATCH_1}")
    endif()
  endforeach()

  set(HINTS)
  foreach(libdir ${LIBDIRS})
    file(TO_CMAKE_PATH "${libdir}" libdir)
    list(APPEND HINTS "${libdir}")
  endforeach()

  set(FULL_LIBS)
  foreach(lib ${LIBS})
    find_library(${lib}_path
      NAMES ${lib}
      HINTS ${HINTS})
    if(NOT ${${lib}_path_FOUND})
      return()
    endif()
    list(APPEND FULL_LIBS ${${lib}_path})
  endforeach()

  set(${OUT_VAR} ${FULL_LIBS} PARENT_SCOPE)
endfunction()
