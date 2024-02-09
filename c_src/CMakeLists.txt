cmake_minimum_required(VERSION 3.28)
project(exwire-pcap)

# Turning off extensions avoids an issue with the clang 16 compiler
# clang 17 and greater can avoid this setting
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
# set(CMAKE_CXX_SCAN_FOR_MODULES TRUE)
set(CMAKE_CXX_COMPILER clang++)

# target_sources(pcap PUBLIC FILE_SET CXX_MODULES FILES device.cppm)

add_executable(exwire-exec main.cpp device.cpp)
add_library(exwire SHARED libpcap.cpp device.cpp)

# set include directories
target_include_directories(exwire PRIVATE "/home/thynkon/.asdf/installs/erlang/26.2.1/usr/include")
target_include_directories(exwire-exec PRIVATE pcap)

target_link_libraries(exwire-exec PRIVATE pcap)
target_link_libraries(exwire PRIVATE pcap)
