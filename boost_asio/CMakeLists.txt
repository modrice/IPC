cmake_minimum_required (VERSION 3.6.3)

project(boost_asio_practice)

set(CMAKE_CXX_STANDARD 17)
set(BOOST_ROOT "/root/els1000/epsilon/boost")

find_package(Boost)

if(Boost_FOUND)
	include_directories(${Boost_INCLUDE_DIRS})
endif()

#include_directories(/usr/local/ssl/include/openssl)
#add_executable(client3.out wall_client.cpp)
#add_executable(server2.out wall_server.cpp)
#add_executable(server3.out asio_server.cpp)

add_executable(client.out boost_example_client.cpp)
add_executable(server.out boost_example_server.cpp)
#add_executable(async.out async_test.cpp)

target_link_libraries(server.out /usr/lib/x86_64-linux-gnu/libssl.so /usr/lib/x86_64-linux-gnu/libcrypto.so)
target_link_libraries(client.out /usr/lib/x86_64-linux-gnu/libssl.so /usr/lib/x86_64-linux-gnu/libcrypto.so)
#target_link_libraries(client.out /opt/homebrew/Cellar/openssl@3/3.2.1/lib/libssl.a /opt/homebrew/Cellar/openssl@3/3.2.1/lib/libcrypto.a)
#target_link_libraries(server.out /opt/homebrew/Cellar/openssl@3/3.2.1/lib/libssl.a /opt/homebrew/Cellar/openssl@3/3.2.1/lib/libcrypto.a)
