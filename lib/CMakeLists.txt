cmake_minimum_required (VERSION 3.8 FATAL_ERROR)

include_directories (${CMAKE_SOURCE_DIR}/src/include)

set (src_dir ${CMAKE_SOURCE_DIR}/src)

#C files for LibCredCrypt
set (CRED_CRYPT_C_SRC
     ${src_dir}/ctrMode.c
     ${src_dir}/cJSON.c
     ${src_dir}/hash.c
     ${src_dir}/ocbMode.c
     ${src_dir}/util.c)

#CPP files for LibCredCrypt
set (CRED_CRYPT_CPP_SRC
     ${src_dir}/api.cpp
     ${src_dir}/credential.cpp
     ${src_dir}/credCryptImpl.cpp
     ${src_dir}/credentialData.cpp
     ${src_dir}/credentialKey.cpp
     ${src_dir}/headerReader.cpp
     ${src_dir}/headerWriter.cpp
     ${src_dir}/identifier.cpp
     ${src_dir}/keyChecker.cpp
     ${src_dir}/parser.cpp
     ${src_dir}/masterKey.cpp
     ${src_dir}/random.cpp
     ${src_dir}/secureString.cpp
     ${src_dir}/timer.cpp)

#C files for Skein
set (SKEIN_SRC
     ${src_dir}/skeinBlockNo3F.c
     ${src_dir}/skein.c
     ${src_dir}/skeinApi.c)

#C files for Threefish
set (THREEFISH_SRC
     ${src_dir}/threefishApi.c
     ${src_dir}/threefish256Block.c
     ${src_dir}/threefish512Block.c
     ${src_dir}/threefish1024Block.c)

#C files for LibScrypt_KDF
set (SCRYPT_SRC
     ${src_dir}/endianConvert.c
     ${src_dir}/pbkdf2Skein512.c
     ${src_dir}/scrypt.c)

#LibCredCrypt
set (CREDCRYPT_SRC ${CRED_CRYPT_C_SRC} ${CRED_CRYPT_CPP_SRC})

#LibSkein3Fish
set (S3F_SRC ${SKEIN_SRC} ${THREEFISH_SRC})

add_library (CredCrypt SHARED ${CREDCRYPT_SRC})
target_compile_features(CredCrypt PRIVATE c_std_11 cxx_std_17)
target_compile_options(CredCrypt PRIVATE ${cxx_compile_options})
set_target_properties (CredCrypt PROPERTIES VERSION ${CREDCRYPTVERSION}
                       SOVERSION ${CREDCRYPTSOVERSION})
add_library (scrypt_KDF SHARED ${SCRYPT_SRC})
target_compile_features(scrypt_KDF PRIVATE c_std_11)
target_compile_options(scrypt_KDF PRIVATE ${c_compile_options})
set_target_properties (scrypt_KDF PROPERTIES VERSION ${SCRYPTVERSION}
                       SOVERSION ${SCRYPTSOVERSION})
add_library (skein3fish SHARED ${S3F_SRC})
target_compile_features(skein3fish PRIVATE c_std_11)
target_compile_options(skein3fish PRIVATE ${c_compile_options})
set_target_properties (skein3fish PROPERTIES VERSION ${S3FVERSION}
                       SOVERSION ${S3FSOVERSION})
