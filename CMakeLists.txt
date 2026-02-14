cmake_minimum_required(VERSION 3.24)

project(ProcessHollowingProject VERSION 0.4.33 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(ARCH_SUFFIX "x64")
else()
  set(ARCH_SUFFIX "x86")
endif()


add_subdirectory(ProcessHollowing)   

function(set_output_names target_name)
    set_target_properties(${target_name} PROPERTIES
            OUTPUT_NAME_DEBUG           "${target_name}-${ARCH_SUFFIX}-Debug"
            OUTPUT_NAME_RELEASE         "${target_name}-${ARCH_SUFFIX}"
            OUTPUT_NAME_RELWITHDEBINFO  "${target_name}-${ARCH_SUFFIX}-RelWithDebInfo"
            OUTPUT_NAME_MINSIZEREL      "${target_name}-${ARCH_SUFFIX}-MinSizeRel"
    )
endfunction()

set_output_names(ProcessHollowing)

# --- Install the libraries ---
include(GNUInstallDirs)

# NOTE:
# - ARCHIVE for .lib/.a (static libs)
# - LIBRARY for .so/.dylib (shared libs)
# - RUNTIME for .dll/.exe on Windows
install(TARGETS ProcessHollowing
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)


install(DIRECTORY ProcessHollowing/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ProcessHollowing
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")