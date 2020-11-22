option (ENABLE_BENCHMARK "Enable benchmark" ${ENABLE_LIBRARIES})

if (NOT ENABLE_BENCHMARK)
    if (USE_INTERNAL_BENCHMARK)
        message (${RECONFIGURE_MESSAGE_LEVEL} "Can't use internal benchmark with ENABLE_BENCHMARK=OFF")
    endif()
    return()
endif()

option (USE_INTERNAL_BENCHMARK "Use internal benchmark library" ${NOT_UNBUNDLED})

if (NOT USE_INTERNAL_BENCHMARK)
    find_package (benchmark)
    foreach (target benchmark::benchmark benchmark::benchmark_main)
        if (NOT TARGET ${target})
            message (${RECONFIGURE_MESSAGE_LEVEL} "Can't find system benchmark (no ${target} target)")
        else()
            set (BENCHMARK_FOUND 1)
        endif()
    endforeach()
endif()

if (NOT BENCHMARK_FOUND)
    set (USE_INTERNAL_BENCHMARK 1)
endif ()

message (STATUS "Using benchmark")
