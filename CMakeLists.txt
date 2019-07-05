cmake_minimum_required (VERSION 3.8)

#Clang is our preferred compiler
set (CMAKE_C_COMPILER "/usr/bin/clang")
set (CMAKE_CXX_COMPILER "/usr/bin/clang++")
#having these compiler flags after project causes an infinite loop

project (Cred_Crypt
         DESCRIPTION "Cred_Crypt password manager top level make list"
         LANGUAGES C CXX
        )

include (CheckIncludeFiles)

set (CMAKE_BUILD_TYPE Debug)
set (CMAKE_VERBOSE_MAKEFILE OFF)

#compiler flags
set (c_compile_options -Wall -Wextra -pedantic)
set (cxx_compile_options -Wall -Wextra -pedantic)

#libary versions
set (CREDCRYPTVERSION "0.9.0")
set (CREDCRYPTSOVERSION "0.7")
set (CJSONVERSION "1.2.0")
set (CJSONSOVERSION "1.2")
set (SCRYPTVERSION "0.5.0")
set (SCRYPTSOVERSION "0.5")
set (S3FVERSION "0.1.0")
set (S3FSOVERSION "0.1")

find_package (Threads)

#Google test path
if (NOT DEFINED ${GTEST_PATH} OR ${GTEST_PATH} EQUAL "")
    set (GTEST_PATH "/home/k3rb3ros/utilities/google_test/googletest/build/googlemock/gtest")
endif ()

add_subdirectory (lib)
add_subdirectory (src)
add_dependencies (CredCrypt CredCrypt scrypt_KDF skein3fish)
add_subdirectory (test)
add_dependencies (${API_TESTS} CredCrypt scrypt_KDF skein3fish)
add_dependencies (${APP_TESTS} CredCrypt scrypt_KDF skein3fish)
