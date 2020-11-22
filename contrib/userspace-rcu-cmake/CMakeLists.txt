option (ENABLE_USERSPACE_RCU "Enable userspace-rcu" ${ENABLE_LIBRARIES})

if(NOT ENABLE_USERSPACE_RCU)
    if(USE_INTERNAL_USERSPACE_RCU_LIBRARY)
        message (${RECONFIGURE_MESSAGE_LEVEL} "Can't use internal userspace-rcu with ENABLE_USERSPACE_RCU=OFF")
    endif()
    return()
endif()

option(USE_INTERNAL_USERSPACE_RCU_LIBRARY "Set to FALSE to use system userspace-rcu instead of bundled" ${NOT_BUNDLED})

# NOTE: you should use only one of them:
# _bp   - BulletProof - does not require thread registration
# _memb - version using membarrier() (if supported)

if (NOT USE_INTERNAL_USERSPACE_RCU_LIBRARY)
    find_library(USERSPACE_RCU_LIBRARY_BP NAMES urcu-bp REQUIRED)
    find_library(USERSPACE_RCU_LIBRARY_MEMB NAMES urcu-memb REQUIRED)

    find_path(USERSPACE_RCU_INCLUDE_DIR NAMES urcu.h REQUIRED)

    # TODO: add to docker images
else()
    set(SRC_DIR "${ClickHouse_SOURCE_DIR}/contrib/userspace-rcu")
    set(USERSPACE_RCU_INCLUDE_DIR ${SRC_DIR}/include)

    include_directories(BEFORE SYSTEM ${USERSPACE_RCU_INCLUDE_DIR})
    # NOTE: suppress
    #     contrib/userspace-rcu/include/urcu/uatomic.h:22:9: warning: macro name is a reserved identifier [-Wreserved-id-macro]
    #     #define _URCU_UATOMIC_H
    add_definitions(-Wno-reserved-id-macro)

    add_library(urcu-common OBJECT
        ${SRC_DIR}/src/urcu-pointer.c
        ${SRC_DIR}/src/compat_futex.c
    )

    # bp
    add_library(urcu-bp
        ${SRC_DIR}/src/urcu-bp.c
        $<TARGET_OBJECTS:urcu-common>
    )
    target_compile_definitions(urcu-bp PRIVATE -DRCU_MB)
    set(USERSPACE_RCU_LIBRARY_BP urcu-bp)

    # memb
    add_library(urcu-memb
        ${SRC_DIR}/src/urcu.c
        $<TARGET_OBJECTS:urcu-common>
    )
    target_compile_definitions(urcu-memb PRIVATE -DRCU_MEMBARRIER)
    set(USERSPACE_RCU_LIBRARY_MEMB urcu-memb)
    # TODO:
    # - enumerate includes (for some IDE's)
    # - check config.h and similar
endif()

set(USERSPACE_RCU_LIBRARY
    ${USERSPACE_RCU_LIBRARY_BP}
    ${USERSPACE_RCU_LIBRARY_MEMB}
)

add_library(urcu_bp INTERFACE)
target_link_libraries(urcu_bp INTERFACE urcu-bp)

add_library(urcu_memb INTERFACE)
target_link_libraries(urcu_memb INTERFACE urcu-memb)

foreach (target urcu_bp urcu_memb)
    target_include_directories(${target} SYSTEM BEFORE INTERFACE ${USERSPACE_RCU_INCLUDE_DIR})
    target_compile_definitions(${target} INTERFACE
        -D_LGPL_SOURCE
        -DURCU_INLINE_SMALL_FUNCTIONS=1
    )
    target_compile_options(${target} INTERFACE
        -Wno-reserved-id-macro
        -Wno-old-style-cast
        -Wno-deprecated-volatile
    )
endforeach()

add_library(urcu::bp ALIAS urcu_bp)
add_library(urcu::memb ALIAS urcu_memb)

message (STATUS "Using userspace_rcu: ${USERSPACE_RCU_INCLUDE_DIR} : ${USERSPACE_RCU_LIBRARY}")
