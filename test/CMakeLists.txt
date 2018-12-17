project (Tests)

#CPP files for tests
set (TEST_SRC
     testCredential.cpp
     testCtrMode.cpp
     testIdentifier.cpp
     testMasterKey.cpp
     testOcbMode.cpp
     testRegistry.cpp
     testSecureString.cpp
     testMain.cpp
    )

set (APP_DIR "../src")

#CPP files tested
set (APP_CPP_SRC
    "${APP_DIR}/credential.cpp"
    "${APP_DIR}/credentialKey.cpp"
    "${APP_DIR}/identifier.cpp"
    "${APP_DIR}/masterKey.cpp"
    "${APP_DIR}/random.cpp"
    "${APP_DIR}/secureString.cpp"
    )

#C files tested
set (APP_C_SRC
    "${APP_DIR}/ctrMode.c"
    "${APP_DIR}/hash.c"
    "${APP_DIR}/ocbMode.c"
    "${APP_DIR}/util.c"
    )

set (S3F_LIB_SRC ${SKEIN_SRC} ${THREEFISH_SRC})

add_custom_command (OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}
    COMMAND ln -s ${GTEST_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME})

add_executable (${PROJECT_NAME} ${TEST_SRC} ${APP_CPP_SRC} ${APP_C_SRC})
target_compile_features (${PROJECT_NAME} PRIVATE ${cxx_compile_features})
target_compile_options (${PROJECT_NAME} PRIVATE ${cxx_compile_options})
target_include_directories (${PROJECT_NAME}
                            PRIVATE
                            ${CMAKE_CURRENT_SOURCE_DIR}/include
                            ${CMAKE_CURRENT_SOURCE_DIR}/../src/include
                           )
target_link_libraries (${PROJECT_NAME}
                       scrypt_KDF
                       skein3fish
                       ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}/libgtest.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/${LIBDIRNAME}/libgtest_main.a ${CMAKE_THREAD_LIBS_INIT})
