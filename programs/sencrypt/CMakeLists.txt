set(LIBRARY_TARGET_NAME sencrypt)

set(CORE_DIR "${PROJECT_SOURCE_DIR}/core")
file(GLOB ${LIBRARY_TARGET_NAME}_SOURCES "${CORE_DIR}/*.c")
list(FIND ${LIBRARY_TARGET_NAME}_SOURCES
        "${CORE_DIR}/psa_crypto_driver_wrappers_no_static.c"
        _IDX)
if (NOT _IDX EQUAL -1)
    list(REMOVE_AT ${LIBRARY_TARGET_NAME}_SOURCES ${_IDX})
endif ()
list(APPEND ${LIBRARY_TARGET_NAME}_SOURCES
        "${CORE_DIR}/psa_crypto_driver_wrappers_no_static.c"
        src/platform_alt.c
)

# TODO: Do not include all drivers.
set(TARGET_OBJECTS "")
foreach (DRIVER_TARGET ${TF_PSA_CRYPTO_DRIVER_TARGETS})
    list(APPEND DRIVER_OBJECTS "$<TARGET_OBJECTS:${DRIVER_TARGET}>")
endforeach ()
foreach (OBJLIB_TARGET ${TF_PSA_CRYPTO_OBJLIB_STATIC_TARGETS})
    list(APPEND TARGET_OBJECTS "$<TARGET_OBJECTS:${OBJLIB_TARGET}>")
endforeach ()

add_library(${LIBRARY_TARGET_NAME} ${${LIBRARY_TARGET_NAME}_SOURCES} ${TARGET_OBJECTS})

target_include_directories(${LIBRARY_TARGET_NAME}
        PUBLIC
        include
        ${PROJECT_BINARY_DIR}/include
        ${PROJECT_SOURCE_DIR}/include
        PRIVATE
        ${TF_PSA_CRYPTO_PRIVATE_INCLUDE_DIRS}
)

# TODO: Do not include all drivers.
foreach (DRIVER_TARGET ${TF_PSA_CRYPTO_DRIVER_TARGETS})
    get_target_property(PUBLIC_INCLUDE_DIRS ${DRIVER_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
    foreach (DIR IN LISTS PUBLIC_INCLUDE_DIRS)
        target_include_directories(${LIBRARY_TARGET_NAME} PUBLIC $<BUILD_INTERFACE:${DIR}>)
    endforeach ()
endforeach ()

tf_psa_crypto_set_base_compile_options(${LIBRARY_TARGET_NAME})
tf_psa_crypto_set_config_files_compile_definitions(${LIBRARY_TARGET_NAME})
target_compile_definitions(${LIBRARY_TARGET_NAME}
        PUBLIC
        TF_PSA_CRYPTO_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/include/crypto_config_alt.h")

if (USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${LIBRARY_TARGET_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif (USE_SHARED_TF_PSA_CRYPTO_LIBRARY)