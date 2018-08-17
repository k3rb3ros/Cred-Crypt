cmake_minimum_required (VERSION 2.6)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

#C files for LibCredCrypt
set (cred_crypt_c_src
     ctrMode.c
     hash.c
     ocbMode.c
     util.c
    )

#CPP files for LibCredCrypt
set (cred_crypt_cpp_src
     api.cpp
     credCryptImpl.cpp
     credential.cpp
     credentialKey.cpp
     headerReader.cpp
     headerWriter.cpp
     keyChecker.cpp
     parser.cpp
     masterKey.cpp
     random.cpp 
     secureString.cpp
     timer.cpp
    )

#C files for Skein
set (skein_src
     skeinBlockNo3F.c
     skein.c
     skeinApi.c
    )

#C files for Threefish
set (threefish_src
     threefishApi.c
     threefish256Block.c
     threefish512Block.c
     threefish1024Block.c
    )

#C files for LibScrypt_KDF
set (scrypt_src
     endianConvert.c
     pbkdf2Skein512.c
     scrypt.c
    )

#LibcJSON
set (cjson_src
     cJSON.c)

#LibCredCrypt
set (credcrypt_src ${cred_crypt_c_src} ${cred_crypt_cpp_src})

#LibSkein3Fish
set (s3f_src ${skein_src} ${threefish_src})

#CPP files for executable
set (test_src
     testMain.cpp
    )

#CPP files for executable
set (cli_src
     cli.cpp
    )

add_library (cJSON SHARED ${cjson_src})
add_library (CredCrypt SHARED ${credcrypt_src})
add_library (scrypt_KDF SHARED ${scrypt_src})
add_library (skein3fish SHARED ${s3f_src})

set_target_properties (cJSON PROPERTIES VERSION ${CJSONVERSION}
                       SOVERSION ${CJSONSOVERSION})

set_target_properties (CredCrypt PROPERTIES VERSION ${CREDCRYPTVERSION}
                       SOVERSION ${CREDCRYPTSOVERSION})

set_target_properties (scrypt_KDF PROPERTIES VERSION ${SCRYPTVERSION}
                       SOVERSION ${SCRYPTSOVERSION})

set_target_properties (skein3fish PROPERTIES VERSION ${S3FVERSION}
                       SOVERSION ${S3FSOVERSION})

add_executable ("API_Test" ${test_src})
add_executable (${PROJECT_NAME} ${cli_src})

target_link_libraries ("API_Test"  cJSON CredCrypt scrypt_KDF skein3fish ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (${PROJECT_NAME}  cJSON CredCrypt scrypt_KDF skein3fish ${CMAKE_THREAD_LIBS_INIT})
