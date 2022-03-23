# Spicy needs the full prefix flex and bison while Zeek captures only the paths
# to the executables. Derive the prefixes from the binary paths under the
# assumption that their bindir is under their prefix (which also implies that
# one such prefix even exists).
get_filename_component(dir ${FLEX_EXECUTABLE} DIRECTORY ABSOLUTE)
set(FLEX_ROOT ${dir}/..)

get_filename_component(dir ${BISON_EXECUTABLE} DIRECTORY ABSOLUTE)
set(BISON_ROOT ${dir}/..)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-braces")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-vla")
set(HILTI_DEV_PRECOMPILE_HEADERS "no")

add_subdirectory(spicy)
