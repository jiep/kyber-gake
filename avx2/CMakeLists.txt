set(SRCS kem.c indcpa.c polyvec.c poly.c fq.S shuffle.S ntt.S invntt.S basemul.S consts.c rejsample.c cbd.c verify.c)
set(SRCS_QROM kem_qrom.c indcpa.c polyvec.c poly.c fq.S shuffle.S ntt.S invntt.S basemul.S consts.c rejsample.c utils.c randombytes.c cbd.c verify.c)
set(TEST_QROM ${SRCS_QROM} test_kem_qrom.c)
set(TEST_SRCS test_kyber.c randombytes.c)
set(TESTKEX_SRCS test_kex.c randombytes.c kex.c)
set(SPEED_SRCS test_speed.c speed_print.c cpucycles.c randombytes.c kex.c)
set(VECTOR_SRCS test_vectors.c)
set(PQCKAT_SRCS PQCgenKAT_kem.c rng.c)
set(AES_FILES aes256ctr.c)
set(KECCAK_FILES fips202x4.c keccak4x/KeccakP-1600-times4-SIMD256.c)
set(AES_SRCS ${SRCS} symmetric-aes.c)
set(GCM_FILES aes256gcm.c randombytes.c utils.c test_aes256gcm.c)
set(KEM_DET_FILES ${SRCS} kem_det.c randombytes.c utils.c test_kem_det.c)
set(CCA_FILES ${SRCS} indcca.c kem_det.c aes256gcm.c randombytes.c utils.c test_indcca.c)
set(COMMITMENT_FILES ${SRCS} kem_det.c indcca.c commitment.c aes256gcm.c randombytes.c utils.c test_commitment.c)
set(GAKE_FILES ${SRCS} gake.c commitment.c indcca.c kem_det.c aes256gcm.c kex.c randombytes.c utils.c test_gake.c)
set(CCA_QROM_FILES ${SRCS_QROM} indcca_qrom.c kem_qrom.c aes256gcm.c randombytes.c utils.c test_indcca_qrom.c)
set(COMMITMENT_QROM_FILES ${SRCS_QROM} commitment_qrom.c indcca_qrom.c kem_qrom.c aes256gcm.c randombytes.c utils.c test_commitment_qrom.c)
set(KEX_QROM_SRCS ${SRCS_QROM} utils.c indcpa.c kex_qrom.c randombytes.c test_kex_qrom.c)
set(GAKE_QROM_FILES ${SRCS_QROM} gake_qrom.c kex_qrom.c commitment_qrom.c indcca_qrom.c kem_qrom.c aes256gcm.c kex.c randombytes.c utils.c test_gake_qrom.c)


if(CMAKE_C_COMPILER_ID MATCHES "Clang")
	add_compile_options(-O3)
	add_compile_options(-Wall)
	add_compile_options(-Wno-unused-result)
	add_compile_options(-Wextra)
	add_compile_options(-Wpedantic)
	add_compile_options(-Wmissing-prototypes)
	add_compile_options(-Wredundant-decls)
	add_compile_options(-Wshadow)
	add_compile_options(-Wpointer-arith)
	add_compile_options(-mavx2)
	add_compile_options(-mbmi2)
	add_compile_options(-mpopcnt)
	add_compile_options(-maes)
	add_compile_options(-fomit-frame-pointer)

elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
	add_compile_options(-O3)
	add_compile_options(-Wall)
	add_compile_options(-Wextra)
	add_compile_options(-Wno-unused-result)
	add_compile_options(-Wpedantic)
	add_compile_options(-Wmissing-prototypes)
	add_compile_options(-Wredundant-decls)
	add_compile_options(-Wshadow)
	add_compile_options(-Wpointer-arith)
	add_compile_options(-mavx2)
	add_compile_options(-mbmi2)
	add_compile_options(-mpopcnt)
	add_compile_options(-maes)
	add_compile_options(-fomit-frame-pointer)

elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
	# Warning C4146 is raised when a unary minus operator is applied to an
	# unsigned type; this has nonetheless been standard and portable for as
	# long as there has been a C standard, and we need it for constant-time
	# computations. Thus, we disable that spurious warning.
	add_compile_options(/wd4146)
endif()


# First, do libraries:
add_library(kyber_fips_avx2 OBJECT ${KECCAK_FILES} ${AES_FILES})
set(_AVX2_OBJS $<TARGET_OBJECTS:kyber_fips_avx2>)

# Iterate over parameter sets:
foreach(X RANGE 2 4)
   # Plain Kyber
   add_library(kyber${X}lib_avx2 OBJECT ${SRCS} symmetric-shake.c)
   target_compile_options(kyber${X}lib_avx2 PUBLIC -DKYBER_K=${X})
   target_include_directories(kyber${X}lib_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
   set(_AVX2_OBJS ${_AVX2_OBJS} $<TARGET_OBJECTS:kyber${X}lib_avx2>)

   # Plain test
   add_executable(test_kyber${K${X}}_avx2 ${TEST_SRCS})
   target_link_libraries(test_kyber${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
   #add_test(test_kyber${K${X}}_avx2 test_kyber${K${X}}_avx2)

   # Plain KEX
   add_executable(test_kex${K${X}}_avx2 ${TESTKEX_SRCS})
   target_link_libraries(test_kex${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
   #add_test(test_kex${K${{X}}_avx2 test_kex${K${X}}_avx2)

	 # Plain KEM DET
	 add_executable(test_kem_det${K${X}}_avx2 ${KEM_DET_FILES})
	 target_link_libraries(test_kem_det${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_kem_det${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain IND CCA
	 add_executable(test_indcca${K${X}}_avx2 ${CCA_FILES})
	 target_link_libraries(test_indcca${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_indcca${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain Commitment
	 add_executable(test_commitment${K${X}}_avx2 ${COMMITMENT_FILES})
	 target_link_libraries(test_commitment${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_commitment${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain GAKE
	 add_executable(test_gake${K${X}}_avx2 ${GAKE_FILES})
	 target_link_libraries(test_gake${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_gake${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain KEM QROM
	 add_executable(test_kem_qrom${K${X}}_avx2 ${TEST_QROM})
	 target_link_libraries(test_kem_qrom${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_kem_qrom${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain IND-CCA QROM
	 add_executable(test_indcca_qrom${K${X}}_avx2 ${CCA_QROM_FILES})
	 target_link_libraries(test_indcca_qrom${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_indcca_qrom${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain Commitment QROM
	 add_executable(test_commitment_qrom${K${X}}_avx2 ${COMMITMENT_QROM_FILES})
	 target_link_libraries(test_commitment_qrom${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_commitment_qrom${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain KEX QROM
	 add_executable(test_kex_qrom${K${X}}_avx2 ${KEX_QROM_SRCS})
	 target_link_libraries(test_kex_qrom${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_kex_qrom${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain KEX QROM
	 add_executable(test_gake_qrom${K${X}}_avx2 ${GAKE_QROM_FILES})
	 target_link_libraries(test_gake_qrom${K${X}}_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
	 target_include_directories(test_gake_qrom${K${X}}_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

	 # Plain speed
   if(NOT WIN32)
   # Plain speed - not yet supported in Windows: TBD
   add_executable(test_speed${K${X}}_avx2 ${SPEED_SRCS})
   target_compile_options(test_speed${K${X}}_avx2 PUBLIC -DKYBER_K=${X})
   target_link_libraries(test_speed${K${X}}_avx2 kyber ${OPENSSL_CRYPTO_LIBRARY})
   #add_test(test_speed${K${X}}_avx2 test_speed${K${X}}_avx2)
   endif()

   # Plain test vectors
   add_executable(test_vectors${K${X}}_avx2 ${VECTOR_SRCS})
   target_compile_options(test_vectors${K${X}}_avx2 PUBLIC -DKYBER_K=${X})
   target_link_libraries(test_vectors${K${X}}_avx2 PRIVATE kyber ${OPENSSL_CRYPTO_LIBRARY})
   if (WIN32)
      add_test(NAME test_vectors${X}_avx2 COMMAND ${CMAKE_COMMAND} -E chdir $<TARGET_FILE_DIR:test_vectors${K${X}}_avx2> $ENV{ComSpec} /c "$<TARGET_FILE_NAME:test_vectors${K${X}}_avx2> | dos2unix > ../tvecs${K${X}}")
   else()
      add_test(NAME test_vectors${K${X}}_avx2 COMMAND sh -c "$<TARGET_FILE:test_vectors${K${X}}_avx2> > tvecs${K${X}}")
   endif()

   # AES Kyber ('90s')
   add_library(kyber${X}aeslib_avx2 OBJECT ${SRCS})
   target_include_directories(kyber${X}aeslib_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
   target_compile_options(kyber${X}aeslib_avx2 PUBLIC -DKYBER_K=${X} -DKYBER_90S)
   set(_AVX2_OBJS ${_AVX2_OBJS} $<TARGET_OBJECTS:kyber${X}aeslib_avx2>)

   # AES test
   add_executable(test_kyber${K${X}}-90s_avx2 ${TEST_SRCS})
   target_link_libraries(test_kyber${K${X}}-90s_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})
   #add_test(test_kyber${K${X}}-90s_avx2 test_kyber${K${X}}-90s_avx2)

   # AES KEX
   add_executable(test_kex${K${X}}-90s_avx2 ${TESTKEX_SRCS})
   target_link_libraries(test_kex${K${X}}-90s_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY} )
   #add_test(test_kex${K${{X}}-90s_avx2 test_kex${K${X}}-90s_avx2)

   # AES speed
   if(NOT WIN32)
   # Plain speed - not yet supported in Windows: TBD
   add_executable(test_speed${K${X}}-90s_avx2 ${SPEED_SRCS})
   target_compile_options(test_speed${K${X}}-90s_avx2 PUBLIC -DKYBER_K=${X} -DKYBER_90S)
   target_link_libraries(test_speed${K${X}}-90s_avx2 kyber ${OPENSSL_CRYPTO_LIBRARY})
   #add_test(test_speed${K${X}}-90s_avx2 test_speed${K${X}}-90s_avx2)
   endif()

   # AES test vectors
   add_executable(test_vectors${K${X}}-90s_avx2 ${VECTOR_SRCS})
   target_compile_options(test_vectors${K${X}}-90s_avx2 PUBLIC -DKYBER_K=${X} -DKYBER_90S)
   target_link_libraries(test_vectors${K${X}}-90s_avx2 PRIVATE kyber ${OPENSSL_CRYPTO_LIBRARY})
   if (WIN32)
      add_test(NAME test_vectors${X}-90s_avx2 COMMAND ${CMAKE_COMMAND} -E chdir $<TARGET_FILE_DIR:test_vectors${K${X}}-90s_avx2> $ENV{ComSpec} /c "$<TARGET_FILE_NAME:test_vectors${K${X}}-90s_avx2> | dos2unix > ../tvecs${K${X}}-90s")
   else()
      add_test(NAME test_vectors${K${X}}-90s_avx2 COMMAND sh -c "$<TARGET_FILE:test_vectors${K${X}}-90s_avx2> > tvecs${K${X}}-90s")
   endif()

endforeach()

# Plain AES 256 GCM
add_executable(test_aes256gcm_avx2 ${GCM_FILES})
target_link_libraries(test_aes256gcm_avx2 PUBLIC kyber ${OPENSSL_CRYPTO_LIBRARY})

# PQCKATs
add_executable(PQCgenKAT_kem_avx2 ${PQCKAT_SRCS})
target_compile_options(PQCgenKAT_kem_avx2 PUBLIC)
target_link_libraries(PQCgenKAT_kem_avx2 PRIVATE kyber ${OPENSSL_CRYPTO_LIBRARY})
if (WIN32)
      # Necessary cludge to make hashes be ignorant of Windows CRLF file formatting:
      add_test(NAME PQCgenKAT_kem_avx2 COMMAND ${CMAKE_COMMAND} -E chdir $<TARGET_FILE_DIR:PQCgenKAT_kem_avx2> $ENV{ComSpec} /c "$<TARGET_FILE_NAME:PQCgenKAT_kem_avx2> && dos2unix -n PQCsignKAT_KEM.rsp ../PQCsignKAT_KEM.rsp && dos2unix -n PQCsignKAT_KEM.req ../PQCsignKAT_KEM.req")
else()
      add_test(PQCgenKAT_kem_avx2 PQCgenKAT_kem_avx2)
endif()

add_test(Hashes_test_avx2 sha256sum -c ../../SHA256SUMS)

set(AVX2_OBJS ${_AVX2_OBJS} PARENT_SCOPE)
