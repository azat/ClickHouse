# Put rust libraries at the end of the list
function(_target_link_libraries_reorder_rust target out_var)
    set(normal_libs "")
    set(rust_libs "")

    foreach(lib IN LISTS ARGN)
        if (lib MATCHES "ch_rust")
            list(APPEND rust_libs "${lib}")
        else()
            list(APPEND normal_libs "${lib}")
        endif()
    endforeach()

    if (rust_libs)
        set(final_libs "${normal_libs};${rust_libs}")
        set(${out_var} "${final_libs}" PARENT_SCOPE)

        if (NOT "${ARGN}" STREQUAL "${final_libs}")
            message(STATUS "Reorder linked libraries for ${target} (rust_libs=${rust_libs}):")
            message(STATUS "- original: ${ARGN}")
            message(STATUS "- updated : ${final_libs}")
        endif()
    else()
        set(${out_var} "${normal_libs}" PARENT_SCOPE)
    endif()
endfunction()

# Same as target_link_libraries(), but, via PROPERTY, to deduplicate
function(_target_link_libraries_deduplicate target property)
    set(new_libs "${ARGN}")

    get_property(existing TARGET ${target} PROPERTY ${property})
    set(all_libs "${existing};${new_libs}")
    list(REMOVE_DUPLICATES all_libs)

    _target_link_libraries_reorder_rust(${target} final_libs ${all_libs})
    set_property(TARGET ${target} PROPERTY ${property} "${final_libs}")
endfunction()

# Reorder linking order to put Rust-related libraries (-rs or *rust*) at the end
# This ensures we prefer our own contrib libs (e.g., zstd) before Rust ones
function(target_link_libraries target)
    if (CLICKHOUSE_DO_NOT_REORDER_RUST_CRATES)
        # Finally call the real target_link_libraries() with reordered arguments
        _target_link_libraries(${target} ${ARGN})
        return()
    endif()

    set(options)
    set(one_value_args)
    set(multi_value_args PRIVATE PUBLIC INTERFACE)
    cmake_parse_arguments(ARG "${options}" "${one_value_args}" "${multi_value_args}" "${ARGN}")

    # Call the original target_link_libraries to handle INTERFACE_INCLUDE_DIRECTORIES and other things.
    # And after we will update LINK_LIBRARIES/INTERFACE_LINK_LIBRARIES to put Rust libraries at the end
    _target_link_libraries(${target} ${ARGN})

    # Default to PRIVATE if no scope specified
    if (NOT ARG_PRIVATE AND NOT ARG_PUBLIC AND NOT ARG_INTERFACE AND ARGN)
        set(ARG_PRIVATE ${ARGN})
    endif()

    # PRIVATE + PUBLIC
    if (ARG_PRIVATE OR ARG_PUBLIC)
        _target_link_libraries_deduplicate(${target} LINK_LIBRARIES ${ARG_PRIVATE} ${ARG_PUBLIC})
    endif()

    if (ARG_INTERFACE OR ARG_PUBLIC)
        _target_link_libraries_deduplicate(${target} INTERFACE_LINK_LIBRARIES ${ARG_PUBLIC} ${ARG_INTERFACE})
    endif()
endfunction()
