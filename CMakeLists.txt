cmake_minimum_required (VERSION 2.6)

#Clang is our preferred compiler
set (CMAKE_C_COMPILER "/usr/bin/clang")
set (CMAKE_CXX_COMPILER "/usr/bin/clang++")
#having these compiler flags after project causes an infinite loop

project (Cred_Crypt)

include (CheckIncludeFiles)

set (CMAKE_BUILD_TYPE Debug)

#compiler flags
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Wextra -pedantic -O0")
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -pedantic -O0")
set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g")

#libary versions
set (CREDCRYPTVERSION "0.7.6")
set (CREDCRYPTSOVERSION "0.7")
set (CJSONVERSION "1.2.0")
set (CJSONSOVERSION "1.2")
set (SCRYPTVERSION "0.5.0")
set (SCRYPTSOVERSION "0.5")
set (S3FVERSION "0.1.0")
set (S3FSOVERSION "0.1")

#Google test path
if (NOT DEFINED ${GTEST_PATH} OR ${GTEST_PATH} EQUAL "")
    set (GTEST_PATH "/home/k3rb3ros/utilities/google_test/googletest/build/googlemock/gtest")
endif ()

# set true for debugging CMakeLists
#set (CMAKE_VERBOSE_MAKEFILE TRUE)
#debug flags
#add_definitions (-DDBG_CRED)
#add_definitions (-DKEY_DEBUG)
#add_definitions (-DDBG_CRED)
#add_definitions(-DDBG_RBTREE)
#add_definitions (-DVERIFY_RBTREE)

if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
  set (LIBDIRNAME "lib64")
else ()
  set (LIBDIRNAME "lib")
endif ()

find_package (Threads)

check_include_files (stdint.h HAVE_STDIND_H)
check_include_files (stdlib.h HAVE_STDLIB_H)
check_include_files (stddef.h HAVE_STDDEF_H)
check_include_files (string.h HAVE_STRING_H)

add_subdirectory (src)
add_subdirectory (test)
