file(GLOB TESTS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*-test.toit" "*_test.toit")

# Exclude hardware-specific tests that require ESP32 or a specific network setup.
list(FILTER TESTS EXCLUDE REGEX "^esp32-")
list(FILTER TESTS EXCLUDE REGEX "^pc-")

find_program(TOIT_EXEC toit)

if(TOIT_EXEC)
    separate_arguments(TOIT_CMD NATIVE_COMMAND "${TOIT_EXEC}")
else()
    find_program(JAG_EXEC jag)
    if(JAG_EXEC)
        set(TOIT_CMD "${JAG_EXEC}" toit)
    else()
        # Fallback if find_program fails (e.g., if it's not in PATH yet)
        set(TOIT_CMD "toit${CMAKE_EXECUTABLE_SUFFIX}")
    endif()
endif()
set(TEST_TIMEOUT 40 CACHE STRING "The maximal amount of time each test is allowed to run")

add_custom_target(
  "install-pkgs"
  COMMAND ${TOIT_CMD} pkg install
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

include(ProcessorCount)
ProcessorCount(NUM_CPU)

add_custom_target(
  "check"
  COMMAND "${CMAKE_CTEST_COMMAND}" -j${NUM_CPU} --output-on-failure -C Debug
  USES_TERMINAL
)

foreach(file ${TESTS})
  set(test_name "/tests/${file}")
  add_test(
    NAME "${test_name}"
    COMMAND ${TOIT_CMD} "tests/${file}"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
  set_tests_properties(${test_name} PROPERTIES TIMEOUT ${TEST_TIMEOUT})
endforeach()
