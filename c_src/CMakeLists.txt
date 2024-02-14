cmake_minimum_required(VERSION 3.28)

# Turning off extensions avoids an issue with the clang 16 compiler
# clang 17 and greater can avoid this setting
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER /usr/bin/clang)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

project(exwire-pcap)

# Make Clang Debug info compatible with GDB
set(CMAKE_BUILD_TYPE Debug)

file(GLOB_RECURSE main_cpp CONFIGURE_DEPENDS main.cpp)

# Add executable target
add_executable(exwire-exec ${main_cpp})
set_property(TARGET exwire-exec PROPERTY CXX_STANDARD 20)

# Add the C++ modules to the target
target_sources(exwire-exec PUBLIC FILE_SET cxx_modules TYPE CXX_MODULES FILES device.cppm pcap_wrapper.cppm packet.cppm protocol.cppm)

# Link pcap library if needed
target_link_libraries(exwire-exec PRIVATE pcap)