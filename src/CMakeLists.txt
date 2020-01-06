list(APPEND libmodbus_source modbus.c modbus-data.c)
list(APPEND libmodbus_public_header modbus.h 
  "${CMAKE_CURRENT_BINARY_DIR}/modbus-version.h")

if (LIBMODBUS_WITH_RTU)
  list(APPEND libmodbus_source modbus-rtu.c)
  list(APPEND libmodbus_public_header modbus-rtu.h)
endif ()
if (LIBMODBUS_WITH_TCP)
  list(APPEND libmodbus_source modbus-tcp.c)
  list(APPEND libmodbus_public_header modbus-tcp.h)
endif ()
if (LIBMODBUS_WITH_UDP)
  list(APPEND libmodbus_source modbus-udp.c)
  list(APPEND libmodbus_public_header modbus-udp.h)
endif ()

add_library(${libmodbus_library_target} ${libmodbus_source})

if (BUILD_SHARED_LIBS)
  set(LIBMODBUS_DEFINE_BUILD_SHARED_LIBS "#define LIBMODBUS_BUILD_SHARED_LIBS")
endif ()

configure_file(modbus-version.h.in modbus-version.h @ONLY)
list(APPEND libmodbus_include ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
  list(APPEND libmodbus_include ${libmodbus_config_include})
  target_compile_options(${libmodbus_library_target} PRIVATE /wd4273)
  target_compile_options(${libmodbus_library_target} PRIVATE /wd4244)
  target_compile_options(${libmodbus_library_target} PRIVATE /wd4996)
  target_compile_options(${libmodbus_library_target} PRIVATE /wd4267)
  target_compile_definitions(${libmodbus_library_target} PUBLIC
    HAVE_CONFIG_H)
  target_compile_definitions(${libmodbus_library_target} PUBLIC
    _CRT_SECURE_NO_DEPRECATE=1)
  target_compile_definitions(${libmodbus_library_target} PUBLIC
    _CRT_NONSTDC_NO_DEPRECATE=1)
  if (CMAKE_BUILD_TYPE EQUAL "DEBUG")
    target_compile_definitions(${libmodbus_library_target} PUBLIC W32DEBUG)
  endif()
  if(BUILD_SHARED_LIBS)
    list(APPEND libmodbus_libraries ws2_32)
    target_compile_definitions(${libmodbus_library_target} PUBLIC DLLBUILD)
  endif()
endif()

target_include_directories(${libmodbus_library_target} PUBLIC
  ${libmodbus_include})

set_target_properties(${libmodbus_library_target}  PROPERTIES PUBLIC_HEADER
  "${libmodbus_public_header}")

if (libmodbus_libraries)
  target_link_libraries(${libmodbus_library_target} ${libmodbus_libraries})
endif ()

install(TARGETS ${libmodbus_library_target}
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/modbus
  ARCHIVE DESTINATION lib)
