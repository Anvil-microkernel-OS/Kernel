cmake_minimum_required(VERSION 3.21)

project(libOs VERSION 0.1.0 LANGUAGES C)

set(SOURCES
	src/stdlib.c
	src/string.c
)


set(CMAKE_C_FLAGS "-ffreestanding -static -nostdlib -fno-stack-protector -Wall -Wextra -fdiagnostics-color ${C_INCLUDES}")

add_library(
	Os
	STATIC
	${SOURCES}
)

target_include_directories(Os PRIVATE ${CMAKE_SOURCE_DIR}/include)