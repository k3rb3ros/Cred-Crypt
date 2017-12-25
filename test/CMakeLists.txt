project (Tests)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

#CPP files for tests
set (TEST_SRC
     mockNodeValue.cpp
     testCtrMode.cpp
     testOcbMode.cpp
     testRedBlackTree.cpp
     testSecureString.cpp
     testMain.cpp
    )

#CPP files tested
set (APP_CPP_SRC
     src/redBlackTree.cpp
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

add_custom_target (GEN_SYM_LINKS
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME})

add_executable (${PROJECT_NAME} ${TEST_SRC} ${APP_CPP_SRC} ${APP_C_SRC})
add_dependencies (${PROJECT_NAME} GEN_SYM_LINKS)
target_link_libraries (${PROJECT_NAME}
                       scrypt_KDF
                       skein3fish
                       ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}/libgtest.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}/libgtest_main.a ${CMAKE_THREAD_LIBS_INIT})
