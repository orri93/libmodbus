list(APPEND libmodbus_source modbus.c)

if (LIB_MODBUS_WITH_DATA)
  list(APPEND libmodbus_source modbus-data.c)
endif ()
if (LIB_MODBUS_WITH_RTU)
  list(APPEND libmodbus_source modbus-rtu.c)
endif ()
if (LIB_MODBUS_WITH_TCP)
  list(APPEND libmodbus_source modbus-tcp.c)
endif ()

add_library(libmodbus ${libmodbus_source})

configure_file(modbus-version.h.in modbus-version.h @ONLY)
list(APPEND libmodbus_include ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
  configure_file(win32/config.h.win32 win32/config.h @ONLY)
  list(APPEND libmodbus_include ${CMAKE_CURRENT_BINARY_DIR}/win32)
  target_compile_options(libmodbus PRIVATE /wd4273)
  target_compile_options(libmodbus PRIVATE /wd4244)
  target_compile_options(libmodbus PRIVATE /wd4996)
  target_compile_options(libmodbus PRIVATE /wd4267)
  target_compile_definitions(libmodbus PUBLIC HAVE_CONFIG_H)
  target_compile_definitions(libmodbus PUBLIC _CRT_SECURE_NO_DEPRECATE=1)
  target_compile_definitions(libmodbus PUBLIC _CRT_NONSTDC_NO_DEPRECATE=1)
  if (CMAKE_BUILD_TYPE EQUAL "DEBUG")
    target_compile_definitions(libmodbus PUBLIC W32DEBUG)
  endif()
  if(BUILD_SHARED_LIBS)
    list(APPEND libmodbus_libraries ws2_32)
    target_compile_definitions(libmodbus PUBLIC DLLBUILD)
  endif()
endif()

target_include_directories(libmodbus PUBLIC "${libmodbus_include}")

if (libmodbus_libraries)
  target_link_libraries(libmodbus ${libmodbus_libraries})
endif ()

if (lib_modbus_tests)
  enable_testing()
endif ()

install(TARGETS libmodbus
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
