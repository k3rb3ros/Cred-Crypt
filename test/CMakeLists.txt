project (Tests)

#CPP files for api tests
set (API_TEST_SRC
  apiTests.cpp)

#CPP files for app tests
set (APP_TEST_SRC
  testCredential.cpp
  testCtrMode.cpp
  testIdentifier.cpp
  testMasterKey.cpp
  testOcbMode.cpp
  testRegistry.cpp
  testSecureString.cpp
  testMain.cpp)

set (S3F_LIB_SRC ${SKEIN_SRC} ${THREEFISH_SRC})
set (API_TESTS API_Tests)
add_executable (${API_TESTS} ${API_TEST_SRC})
target_compile_features (${API_TESTS} PRIVATE c_std_11 cxx_std_14)
target_compile_options (${API_TESTS} PRIVATE ${cxx_compile_options})
target_include_directories (${API_TESTS}
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/include)
target_link_libraries (${API_TESTS}
  CredCrypt
  scrypt_KDF
  skein3fish
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/libgtest.a
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/libgtest_main.a ${CMAKE_THREAD_LIBS_INIT})

set (APP_TESTS CredCrypt_Tests)
add_executable (${APP_TESTS} ${APP_TEST_SRC})
target_compile_features (${APP_TESTS} PRIVATE c_std_11 cxx_std_14)
target_compile_options (${APP_TESTS} PRIVATE ${cxx_compile_options})
target_include_directories (${APP_TESTS}
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/include)
target_link_libraries (${APP_TESTS}
  CredCrypt
  scrypt_KDF
  skein3fish
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/libgtest.a
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/libgtest_main.a ${CMAKE_THREAD_LIBS_INIT})
add_custom_command (TARGET ${APP_TESTS}
  PRE_BUILD
  COMMAND ln -sf ${GTEST_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/lib)
