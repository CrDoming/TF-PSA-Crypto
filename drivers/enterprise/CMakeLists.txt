set(LIBRARY_TARGET_NAME enterprise)

set(${LIBRARY_TARGET_NAME}_HEADERS
        include/enterprise/enterprise_driver_entrypoints.h
)

set(${LIBRARY_TARGET_NAME}_SOURCES
        src/enterprise_driver_entrypoints.c
)

add_library(${LIBRARY_TARGET_NAME} ${${LIBRARY_TARGET_NAME}_HEADERS} ${${LIBRARY_TARGET_NAME}_SOURCES})

target_include_directories(${LIBRARY_TARGET_NAME}
        PUBLIC include
)

target_link_libraries(${LIBRARY_TARGET_NAME}
        PUBLIC ${tfpsacrypto_target}
)