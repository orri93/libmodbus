cmake_minimum_required(VERSION 3.8.2)

project(LibModbus VERSION 3.1.6
  DESCRIPTION "LibModbus CMake Project"
  LANGUAGES C)

set(LIBMODBUS_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(LIBMODBUS_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(LIBMODBUS_VERSION_MICRO ${PROJECT_VERSION_PATCH})
set(LIBMODBUS_VERSION ${PROJECT_VERSION})

option(LIBMODBUS_TESTS "Build libmodbus tests" OFF)
option(LIBMODBUS_WITH_RTU "Build libmodbus with RTU support" ON)
option(LIBMODBUS_WITH_TCP "Build libmodbus with TCP support" ON)
option(BUILD_SHARED_LIBS "Build libmodbus as shared library" OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_PLATFORM_INDEPENDENT_CODE ON)

list(APPEND libmodbus_include ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_subdirectory(src)

if (LIB_MODBUS_TESTS)
  add_subdirectory(tests)
endif ()

message(STATUS "")
message(STATUS "libmodbus ${PROJECT_VERSION} BUILD SUMMARY")
message(STATUS "  Install prefix            : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  CMAKE_GENERATOR           : ${CMAKE_GENERATOR}")
message(STATUS "  CMAKE_SOURCE_DIR          : ${CMAKE_SOURCE_DIR}")
message(STATUS "  CMAKE_CURRENT_SOURCE_DIR  : ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "  BUILD_SHARED_LIBS         : ${BUILD_SHARED_LIBS}")
message(STATUS "  Compiler ID               : ${CMAKE_C_COMPILER_ID}")
message(STATUS "  Compiler Version          : ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  Compiler flags            : ${CMAKE_C_FLAGS}")
if(MSVC_VERSION)
message(STATUS "  MSVC Version              : ${MSVC_VERSION}")
endif(MSVC_VERSION)
message(STATUS "  Build tests               : ${LIB_MODBUS_TESTS}")