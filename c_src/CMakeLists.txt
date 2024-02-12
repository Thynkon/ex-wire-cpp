cmake_minimum_required(VERSION 3.28)
project(exwire-pcap)

# Turning off extensions avoids an issue with the clang 16 compiler
# clang 17 and greater can avoid this setting
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)

add_executable(exwire-exec main.cpp device.cpp packets/packet.cpp packets/tcp.cpp packets/udp.cpp protocols/protocol.cpp protocols/http.cpp pcap_wrapper.cpp)
add_library(exwire SHARED libpcap.cpp device.cpp packets/packet.cpp packets/tcp.cpp packets/udp.cpp protocols/http.cpp  pcap_wrapper.cpp)

# set include directories
target_include_directories(exwire PRIVATE "/home/thynkon/.asdf/installs/erlang/26.2.1/usr/include")
target_include_directories(exwire-exec PRIVATE pcap)

target_link_libraries(exwire-exec PRIVATE pcap)
target_link_libraries(exwire PRIVATE pcap)

# add compilation flags to compiler
target_compile_options(exwire PRIVATE -g)
