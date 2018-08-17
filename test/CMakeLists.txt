project (Tests)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/../src/include)

#CPP files for tests
set (TEST_SRC
     testCtrMode.cpp
     testOcbMode.cpp
     testRegistry.cpp
     testSecureString.cpp
     testMain.cpp
    )

#CPP files tested
set (APP_CPP_SRC
     src/secureString.cpp
    )

#C files tested
set (APP_C_SRC
     src/ctrMode.c
     src/hash.c
     src/ocbMode.c
     src/util.c
    )

set (S3F_LIB_SRC ${SKEIN_SRC} ${THREEFISH_SRC})

add_custom_command (OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}
    COMMAND ln -s ${GTEST_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME})

add_executable (${PROJECT_NAME} ${TEST_SRC} ${APP_CPP_SRC} ${APP_C_SRC})
target_link_libraries (${PROJECT_NAME}
                       scrypt_KDF
                       skein3fish
                       ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}/libgtest.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}/libgtest_main.a ${CMAKE_THREAD_LIBS_INIT})
