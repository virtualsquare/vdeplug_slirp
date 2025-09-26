cmake_minimum_required(VERSION 3.25)
project("vdeplug_slirp"
    DESCRIPTION "libvdeplug plugin module for slirp"
    HOMEPAGE_URL "https://github.com/rd235/vdeplug_slirp"
    VERSION 0.1.0
    LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

set(CMAKE_REQUIRED_QUIET TRUE)
set(LIBS_REQUIRED vdeslirp vdeplug_mod)
set(HEADERS_REQUIRED libvdeplug.h slirp/libvdeslirp.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(vdeplug_slirp SHARED libvdeplug_slirp.c)
target_link_libraries(vdeplug_slirp vdeslirp vdeplug_mod)

install(TARGETS vdeplug_slirp DESTINATION ${CMAKE_INSTALL_LIBDIR}/vdeplug)

add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
