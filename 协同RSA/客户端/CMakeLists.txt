cmake_minimum_required(VERSION 3.0.0)
project(CLIENT VERSION 0.1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
link_libraries(crypto)
link_libraries(ssl)
link_directories(${PROJECT_SOURCE_DIR}/lib)

add_executable(CLIENT tcp_client.c)
#add_executable(CLIENT CLIENT_.c)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
