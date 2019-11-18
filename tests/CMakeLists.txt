# The following variables are for the unit-test.h.in
if(MSVC)
  set(HAVE_INTTYPES_H 1)
  set(HAVE_STDINT_H 1)
endif()
configure_file(unit-test.h.in unit-test.h @ONLY)
set(libmodbus_unit_test_include ${CMAKE_CURRENT_BINARY_DIR})

list(APPEND modbus_tests_libraries ${libmodbus_library_target})
if (MSVC)
  list(APPEND modbus_tests_libraries 
    ws2_32)
endif ()

set(version_target "version")
add_executable(${version_target} "version.c")
target_include_directories(${version_target} PUBLIC
  ${libmodbus_config_include}
  ${libmodbus_include})
target_link_libraries(${version_target}
  ${modbus_tests_libraries})
#target_compile_definitions(${version_target} PUBLIC NO_DEFINES)
install(TARGETS ${version_target}
  LIBRARY DESTINATION bin
  ARCHIVE DESTINATION bin)

if (LIBMODBUS_WITH_TCP)
  set(random_test_client_target "random-test-client")
  add_executable(${random_test_client_target} "random-test-client.c")
  target_include_directories(${random_test_client_target} PUBLIC
    ${libmodbus_config_include}
    ${libmodbus_include})
  target_link_libraries(${random_test_client_target}
    ${modbus_tests_libraries})
  #target_compile_definitions(${random_test_client_target} PUBLIC NO_DEFINES)
  install(TARGETS ${random_test_client_target}
    LIBRARY DESTINATION bin
    ARCHIVE DESTINATION bin)

  set(random_test_server_target "random-test-server")
  add_executable(${random_test_server_target} "random-test-server.c")
  target_include_directories(${random_test_server_target} PUBLIC
    ${libmodbus_config_include}
    ${libmodbus_include})
  target_link_libraries(${random_test_server_target}
    ${modbus_tests_libraries})
  #target_compile_definitions(${random_test_server_target} PUBLIC NO_DEFINES)
  install(TARGETS ${random_test_server_target}
    LIBRARY DESTINATION bin
    ARCHIVE DESTINATION bin)
  if (MSVC)
    target_compile_options(${random_test_server_target} PRIVATE /wd4013)
    target_compile_options(${random_test_server_target} PRIVATE /wd6387)
  endif ()
endif ()

if (LIBMODBUS_WITH_TCP AND LIBMODBUS_WITH_RTU)
  if(NOT MSVC)
    set(unit_test_client_target "unit-test-client")
    add_executable(${unit_test_client_target} "unit-test-client.c")
    target_include_directories(${unit_test_client_target} PUBLIC
      ${libmodbus_unit_test_include}
      ${libmodbus_config_include}
      ${libmodbus_include})
    target_link_libraries(${unit_test_client_target}
      ${modbus_tests_libraries})
    #target_compile_definitions(${unit_test_client_target} PUBLIC NO_DEFINES)
    install(TARGETS ${unit_test_client_target}
      LIBRARY DESTINATION bin
      ARCHIVE DESTINATION bin)

    set(unit_test_server_target "unit-test-server")
    add_executable(${unit_test_server_target} "unit-test-server.c")
    target_include_directories(${unit_test_server_target} PUBLIC
      ${libmodbus_unit_test_include}
      ${libmodbus_config_include}
      ${libmodbus_include})
    target_link_libraries(${unit_test_server_target}
      ${modbus_tests_libraries})
    #target_compile_definitions(${unit_test_client_target} PUBLIC NO_DEFINES)
    install(TARGETS ${unit_test_server_target}
      LIBRARY DESTINATION bin
      ARCHIVE DESTINATION bin)
  endif()

  set(bandwidth_client_target "bandwidth-client")
  set(bandwidth_client_source "bandwidth-client.c")
  add_executable(${bandwidth_client_target} ${bandwidth_client_source})
  if (MSVC)
    target_compile_options(${bandwidth_client_target} PRIVATE /wd4101)
  endif ()
  target_include_directories(${bandwidth_client_target} PUBLIC
    ${libmodbus_config_include}
    ${libmodbus_include})
  target_link_libraries(${bandwidth_client_target}
    ${modbus_tests_libraries})
  #target_compile_definitions(${bandwidth_client_target} PUBLIC NO_DEFINES)
  install(TARGETS ${bandwidth_client_target}
    LIBRARY DESTINATION bin
    ARCHIVE DESTINATION bin)

  set(bandwidth_server_one_target "bandwidth-server-one")
  add_executable(${bandwidth_server_one_target} "bandwidth-server-one.c")
  target_include_directories(${bandwidth_server_one_target} PUBLIC
    ${libmodbus_config_include}
    ${libmodbus_include})
  target_link_libraries(${bandwidth_server_one_target}
    ${modbus_tests_libraries})
  #target_compile_definitions(${bandwidth_server_one_target} PUBLIC NO_DEFINES)
  install(TARGETS ${bandwidth_server_one_target}
    LIBRARY DESTINATION bin
    ARCHIVE DESTINATION bin)

  if(NOT MSVC)
    set(bandwidth_server_many_up_target "bandwidth-server-many-up")
    add_executable(${bandwidth_server_many_up_target}
      "bandwidth-server-many-up.c")
    target_include_directories(${bandwidth_server_many_up_target} PUBLIC
      ${libmodbus_config_include}
      ${libmodbus_include})
    target_link_libraries(${bandwidth_server_many_up_target}
      ${modbus_tests_libraries})
    #target_compile_definitions(${bandwidth_server_many_up_target} PUBLIC NO_DEFINES)
    install(TARGETS ${bandwidth_server_many_up_target}
      LIBRARY DESTINATION bin
      ARCHIVE DESTINATION bin)
  endif()

endif ()