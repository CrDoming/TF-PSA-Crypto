set(EXECUTABLE_TARGET_NAME cli)

set(${EXECUTABLE_TARGET_NAME}_SOURCES
        main.c
)

add_executable(${EXECUTABLE_TARGET_NAME} ${${EXECUTABLE_TARGET_NAME}_SOURCES})

target_link_libraries(${EXECUTABLE_TARGET_NAME}
        PRIVATE
        sencrypt
)

if (BUILD_SHARED_LIBS)
    add_custom_command(
            TARGET ${EXECUTABLE_TARGET_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:sencrypt>
            $<TARGET_FILE_DIR:${EXECUTABLE_TARGET_NAME}>
    )
endif ()
