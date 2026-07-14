set(LIBRARY_TARGET_NAME enterprise)

set(${LIBRARY_TARGET_NAME}_SOURCES
        src/enterprise_driver_entrypoints.c
)

add_library(${LIBRARY_TARGET_NAME} OBJECT ${${LIBRARY_TARGET_NAME}_SOURCES})

target_include_directories(${LIBRARY_TARGET_NAME}
        PUBLIC
        include
        PRIVATE
        ${PROJECT_BINARY_DIR}/include
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/core
        ${PROJECT_SOURCE_DIR}/dispatch
        ${TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS}
)

tf_psa_crypto_set_base_compile_options(${LIBRARY_TARGET_NAME})
tf_psa_crypto_set_config_files_compile_definitions(${LIBRARY_TARGET_NAME})

if (USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${LIBRARY_TARGET_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif (USE_SHARED_TF_PSA_CRYPTO_LIBRARY)