cmake_minimum_required (VERSION 3.8 FATAL_ERROR)

project (cred_crypt
  DESCRIPTION "Builds CredCrypt libs and tests"
  LANGUAGES C CXX)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

#CPP files for app
set (APP_SRC
     cli.cpp
    )

add_executable (${PROJECT_NAME} ${APP_SRC})
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE ${cxx_compile_options})
target_link_libraries (${PROJECT_NAME} CredCrypt scrypt_KDF skein3fish ${CMAKE_THREAD_LIBS_INIT})
