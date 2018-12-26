cmake_minimum_required (VERSION 3.8)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

#C files for LibCredCrypt
set (CRED_CRYPT_C_SRC
     ctrMode.c
     hash.c
     ocbMode.c
     util.c
    )

#CPP files for LibCredCrypt
set (CRED_CRYPT_CPP_SRC
     api.cpp
     credential.cpp
     credCryptImpl.cpp
     credentialData.cpp
     credentialKey.cpp
     headerReader.cpp
     headerWriter.cpp
     identifier.cpp
     keyChecker.cpp
     parser.cpp
     masterKey.cpp
     random.cpp
     secureString.cpp
     timer.cpp
    )

#C files for Skein
set (SKEIN_SRC
     skeinBlockNo3F.c
     skein.c
     skeinApi.c
    )

#C files for Threefish
set (THREEFISH_SRC
     threefishApi.c
     threefish256Block.c
     threefish512Block.c
     threefish1024Block.c
    )

#C files for LibScrypt_KDF
set (SCRYPT_SRC
     endianConvert.c
     pbkdf2Skein512.c
     scrypt.c
    )

#LibcJSON
set (CJSON_SRC
     cJSON.c)

#LibCredCrypt
set (CREDCRYPT_SRC ${CRED_CRYPT_C_SRC} ${CRED_CRYPT_CPP_SRC})

#LibSkein3Fish
set (S3F_SRC ${SKEIN_SRC} ${THREEFISH_SRC})

#CPP files for executable
set (TEST_SRC
     testMain.cpp
    )

#CPP files for executable
set (CLI_SRC
     cli.cpp
    )

add_library (cJSON SHARED ${CJSON_SRC})
target_compile_features(cJSON PRIVATE ${c_compile_features})
target_compile_options(cJSON PRIVATE ${c_compile_options})
set_target_properties (cJSON PROPERTIES VERSION ${CJSONVERSION}
                       SOVERSION ${CJSONSOVERSION})
add_library (CredCrypt SHARED ${CREDCRYPT_SRC})
target_compile_features(CredCrypt PRIVATE ${cxx_compile_features})
target_compile_options(CredCrypt PRIVATE ${cxx_compile_options})
set_target_properties (CredCrypt PROPERTIES VERSION ${CREDCRYPTVERSION}
                       SOVERSION ${CREDCRYPTSOVERSION})
add_library (scrypt_KDF SHARED ${SCRYPT_SRC})
target_compile_features(scrypt_KDF PRIVATE ${c_compile_features})
target_compile_options(scrypt_KDF PRIVATE ${c_compile_options})
set_target_properties (scrypt_KDF PROPERTIES VERSION ${SCRYPTVERSION}
                       SOVERSION ${SCRYPTSOVERSION})
add_library (skein3fish SHARED ${S3F_SRC})
target_compile_features(skein3fish PRIVATE ${c_compile_features})
target_compile_options(skein3fish PRIVATE ${c_compile_options})
set_target_properties (skein3fish PROPERTIES VERSION ${S3FVERSION}
                       SOVERSION ${S3FSOVERSION})

add_executable (API_Test ${TEST_SRC})
target_compile_features(API_Test PRIVATE ${cxx_compile_features})
target_compile_options(API_Test PRIVATE ${cxx_compile_options})
target_link_libraries (API_Test  cJSON CredCrypt scrypt_KDF skein3fish ${CMAKE_THREAD_LIBS_INIT})
add_executable (${PROJECT_NAME} ${CLI_SRC})
target_compile_features(${PROJECT_NAME} PRIVATE ${cxx_compile_features})
target_compile_options(${PROJECT_NAME} PRIVATE ${cxx_compile_options})
target_link_libraries (${PROJECT_NAME}  cJSON CredCrypt scrypt_KDF skein3fish ${CMAKE_THREAD_LIBS_INIT})
