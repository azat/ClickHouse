set(ABSL_ROOT_DIR "${ClickHouse_SOURCE_DIR}/contrib/abseil-cpp")
set(BUILD_TESTING OFF)
set(ABSL_PROPAGATE_CXX_STD ON)
add_subdirectory("${ABSL_ROOT_DIR}" "${ClickHouse_BINARY_DIR}/contrib/abseil-cpp")

# ch_contrib::abseil_swiss_tables
add_library(_abseil_swiss_tables INTERFACE)

target_link_libraries(_abseil_swiss_tables INTERFACE
  absl::flat_hash_map
  absl::flat_hash_set
)

get_target_property(FLAT_HASH_MAP_INCLUDE_DIR absl::flat_hash_map INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories (_abseil_swiss_tables SYSTEM BEFORE INTERFACE ${FLAT_HASH_MAP_INCLUDE_DIR})

get_target_property(FLAT_HASH_SET_INCLUDE_DIR absl::flat_hash_set INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories (_abseil_swiss_tables SYSTEM BEFORE INTERFACE ${FLAT_HASH_SET_INCLUDE_DIR})

add_library(ch_contrib::abseil_swiss_tables ALIAS _abseil_swiss_tables)

# ch_contrib::abseil_synchronization
add_library(_abseil_synchronization INTERFACE)
target_link_libraries(_abseil_synchronization INTERFACE absl::synchronization)
get_target_property(SYNCHRONIZATION_INCLUDE_DIR absl::synchronization INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories (_abseil_swiss_tables SYSTEM BEFORE INTERFACE ${SYNCHRONIZATION_INCLUDE_DIR})
add_library(ch_contrib::abseil_synchronization ALIAS _abseil_synchronization)
