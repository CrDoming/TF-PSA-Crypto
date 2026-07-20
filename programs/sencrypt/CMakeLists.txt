set(LIBRARY_TARGET_NAME sencrypt)

option(ENABLE_FIRMWARE_DRIVER "Enable the firmware transparent driver." OFF)

if (ENABLE_FIRMWARE_DRIVER)
    add_compile_definitions(FIRMWARE_DRIVER_ENABLED=1)
endif ()

set(${LIBRARY_TARGET_NAME}_SOURCES "")

set(EXTERNAL_SOURCE_DIRS
        "${PROJECT_SOURCE_DIR}/drivers/builtin/src"
        "${PROJECT_SOURCE_DIR}/dispatch"
        "${PROJECT_SOURCE_DIR}/extras"
        "${PROJECT_SOURCE_DIR}/platform"
        "${PROJECT_SOURCE_DIR}/utilities"
        "${PROJECT_SOURCE_DIR}/core"
)

foreach (_DIR ${EXTERNAL_SOURCE_DIRS})
    file(GLOB _SOURCES "${_DIR}/*.c")
    list(APPEND ${LIBRARY_TARGET_NAME}_SOURCES ${_SOURCES})
endforeach ()

list(FIND ${LIBRARY_TARGET_NAME}_SOURCES
        "${PROJECT_SOURCE_DIR}/core/psa_crypto_driver_wrappers_no_static.c"
        _IDX)
if (NOT _IDX EQUAL -1)
    list(REMOVE_AT ${LIBRARY_TARGET_NAME}_SOURCES ${_IDX})
endif ()

list(APPEND ${LIBRARY_TARGET_NAME}_SOURCES
        include/psa_crypto_driver_wrappers.h
        src/firmware_driver_entrypoints.c
        src/internal_trusted_storage.c
        src/platform_alt.c
        src/psa_crypto_driver_wrappers_no_static.c
)

if (BUILD_SHARED_LIBS)
    list(APPEND ${LIBRARY_TARGET_NAME}_SOURCES
            exports.def
    )
endif ()

add_library(${LIBRARY_TARGET_NAME} ${${LIBRARY_TARGET_NAME}_SOURCES})

target_include_directories(${LIBRARY_TARGET_NAME}
        PUBLIC
        include
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/drivers/builtin/include"
        PRIVATE
        ${EXTERNAL_SOURCE_DIRS}
)

tf_psa_crypto_set_base_compile_options(${LIBRARY_TARGET_NAME})
tf_psa_crypto_set_extra_compile_options(${LIBRARY_TARGET_NAME})
target_compile_definitions(${LIBRARY_TARGET_NAME}
        PUBLIC
        TF_PSA_CRYPTO_CONFIG_FILE="crypto_config_alt.h")

set_target_properties(${LIBRARY_TARGET_NAME} PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
)

if (BUILD_SHARED_LIBS)
    set_target_properties(${LIBRARY_TARGET_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    # GCC & Clang: Split functions/data into separate addressable segments.
    target_compile_options(${LIBRARY_TARGET_NAME} PRIVATE -ffunction-sections -fdata-sections)

    # Linker: Garbage collect any segment not reached by an exported function.
    if (APPLE)
        target_link_options(${LIBRARY_TARGET_NAME} PRIVATE -Wl,-dead_strip)
    else ()
        target_link_options(${LIBRARY_TARGET_NAME} PRIVATE -Wl,--gc-sections)
    endif ()

elseif (MSVC)
    # Windows/MSVC handles this slightly differently via optimization flags.
    # /Gy activates function-level linking (similar to -ffunction-sections).
    target_compile_options(${LIBRARY_TARGET_NAME} PRIVATE /Gy)

    # /OPT:REF eliminates functions and data that are never referenced.
    target_link_options(${LIBRARY_TARGET_NAME} PRIVATE /OPT:REF)
endif ()