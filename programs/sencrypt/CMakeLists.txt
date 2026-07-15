set(LIBRARY_TARGET_NAME sencrypt)

option(ENABLE_FIRMWARE_DRIVER "Enable the firmware transparent driver." OFF)

if (ENABLE_FIRMWARE_DRIVER)
    add_compile_definitions(FIRMWARE_DRIVER_ENABLED=1)
endif ()

set(CORE_DIR "${PROJECT_SOURCE_DIR}/core")
file(GLOB ${LIBRARY_TARGET_NAME}_SOURCES "${CORE_DIR}/*.c")
list(FIND ${LIBRARY_TARGET_NAME}_SOURCES
        "${CORE_DIR}/psa_crypto_driver_wrappers_no_static.c"
        _IDX)
if (NOT _IDX EQUAL -1)
    list(REMOVE_AT ${LIBRARY_TARGET_NAME}_SOURCES ${_IDX})
endif ()
list(APPEND ${LIBRARY_TARGET_NAME}_SOURCES
        include/psa_crypto_driver_wrappers.h
        src/platform_alt.c
        src/psa_crypto_driver_wrappers_no_static.c
        src/firmware_driver_entrypoints.c
)

if (BUILD_SHARED_LIBS)
    list(APPEND ${LIBRARY_TARGET_NAME}_SOURCES
            exports.def
    )
endif ()

set(DRIVER_TARGETS builtin)

set(TARGET_OBJECTS "")
foreach (TARGET ${TF_PSA_CRYPTO_OBJLIB_TARGETS} ${DRIVER_TARGETS})
    target_include_directories(${TARGET}
            PRIVATE
            include
    )
    target_compile_definitions(${TARGET}
            PUBLIC
            TF_PSA_CRYPTO_CONFIG_FILE="include/crypto_config_alt.h")

    if (BUILD_SHARED_LIBS)
        set_target_properties(${TARGET} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    endif ()

    list(APPEND TARGET_OBJECTS "$<TARGET_OBJECTS:${TARGET}>")
endforeach ()

add_library(${LIBRARY_TARGET_NAME} ${${LIBRARY_TARGET_NAME}_SOURCES} ${TARGET_OBJECTS})

# TODO: Fix.
target_include_directories(${LIBRARY_TARGET_NAME}
        PUBLIC
        ${PROJECT_BINARY_DIR}/include
        ${PROJECT_SOURCE_DIR}/include
        PRIVATE
        include
        ${PROJECT_SOURCE_DIR}/core
        ${TF_PSA_CRYPTO_PRIVATE_INCLUDE_DIRS}
)

#target_include_directories(${LIBRARY_TARGET_NAME} BEFORE
#        PRIVATE
#        include
#)

foreach (DRIVER_TARGET ${DRIVER_TARGETS})
    get_target_property(PUBLIC_INCLUDE_DIRS ${DRIVER_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
    foreach (DIR IN LISTS PUBLIC_INCLUDE_DIRS)
        target_include_directories(${LIBRARY_TARGET_NAME} PUBLIC $<BUILD_INTERFACE:${DIR}>)
    endforeach ()
endforeach ()

tf_psa_crypto_set_base_compile_options(${LIBRARY_TARGET_NAME})
tf_psa_crypto_set_extra_compile_options(${LIBRARY_TARGET_NAME})
target_compile_definitions(${LIBRARY_TARGET_NAME}
        PUBLIC
        TF_PSA_CRYPTO_CONFIG_FILE="include/crypto_config_alt.h")

set_target_properties(${LIBRARY_TARGET_NAME} PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
)

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

if (BUILD_SHARED_LIBS)
    set_target_properties(${LIBRARY_TARGET_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif ()