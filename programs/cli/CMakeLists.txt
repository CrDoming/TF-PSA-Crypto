set(EXECUTABLE_TARGET_NAME cli)

set(${EXECUTABLE_TARGET_NAME}_SOURCES
        main.c
)

add_executable(${EXECUTABLE_TARGET_NAME} ${${EXECUTABLE_TARGET_NAME}_SOURCES})

target_link_libraries(${EXECUTABLE_TARGET_NAME}
        PUBLIC
        sencrypt
)