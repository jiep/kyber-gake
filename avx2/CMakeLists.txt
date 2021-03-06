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
set(GAKE_SPEED_FILES ${SRCS} gake.c commitment.c indcca.c kem_det.c aes256gcm.c kex.c randombytes.c utils.c test_gake_speed.c)
set(CCA_QROM_FILES ${SRCS_QROM} indcca_qrom.c kem_qrom.c aes256gcm.c randombytes.c utils.c test_indcca_qrom.c)
set(COMMITMENT_QROM_FILES ${SRCS_QROM} commitment_qrom.c indcca_qrom.c kem_qrom.c aes256gcm.c randombytes.c utils.c test_commitment_qrom.c)
set(KEX_QROM_SRCS ${SRCS_QROM} utils.c indcpa.c kex_qrom.c randombytes.c test_kex_qrom.c)
set(GAKE_QROM_FILES ${SRCS_QROM} kem.c gake_qrom.c kex_qrom.c commitment_qrom.c indcca_qrom.c kem_qrom.c aes256gcm.c kex.c randombytes.c utils.c test_gake_qrom.c)
set(GAKE_QROM_SPEED_FILES ${SRCS_QROM} kem.c gake_qrom.c kex_qrom.c commitment_qrom.c indcca_qrom.c kem_qrom.c aes256gcm.c kex.c randombytes.c utils.c test_gake_qrom_speed.c)

set(KYBER_FIPS202_SRCS ${KYBER_SRCS} symmetric-shake.c)
set(KYBER_QROM_FIPS202_SRCS ${KYBER_QROM_SRCS} symmetric-shake.c)
set(FIPS202_SRCS fips202.c fips202x4.c keccak4x/KeccakP-1600-times4-SIMD256.c)
set(AES256CTR_SRCS aes256ctr.c)
set(SHA2_SRCS sha256.c sha512.c)

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

add_library(fips202_avx2 ${FIPS202_SRCS})
add_library(aes256ctr_avx2 ${AES256CTR_SRCS})

# Kyber 512
add_library(kyber512_avx2 ${KYBER_FIPS202_SRCS})
target_compile_definitions(kyber512_avx2 PUBLIC KYBER_K=2)
target_link_libraries(kyber512_avx2 INTERFACE fips202_avx2)

add_library(kyber_qrom512_avx2 ${KYBER_QROM_FIPS202_SRCS})
target_compile_definitions(kyber_qrom512_avx2 PUBLIC KYBER_K=2)
target_link_libraries(kyber_qrom512_avx2 INTERFACE fips202_avx2)

add_executable(test_gake512_avx2 ${GAKE_FILES})
add_executable(test_gake_qrom512_avx2 ${GAKE_QROM_FILES})
add_executable(test_gake_speed512_avx2 ${GAKE_SPEED_FILES})
add_executable(test_gake_qrom_speed512_avx2 ${GAKE_QROM_SPEED_FILES})

target_include_directories(test_gake512_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_qrom512_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_speed512_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_qrom_speed512_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

target_link_libraries(test_gake512_avx2 kyber512_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_qrom512_avx2 kyber_qrom512_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_speed512_avx2 kyber512_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_qrom_speed512_avx2 kyber_qrom512_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})

# Kyber 768
add_library(kyber768_avx2 ${KYBER_FIPS202_SRCS})
target_compile_definitions(kyber768_avx2 PUBLIC KYBER_K=3)
target_link_libraries(kyber768_avx2 INTERFACE fips202_avx2)

add_library(kyber_qrom768_avx2 ${KYBER_QROM_FIPS202_SRCS})
target_compile_definitions(kyber_qrom768_avx2 PUBLIC KYBER_K=3)
target_link_libraries(kyber_qrom768_avx2 INTERFACE fips202_avx2)

add_executable(test_gake768_avx2 ${GAKE_FILES})
add_executable(test_gake_qrom768_avx2 ${GAKE_QROM_FILES})
add_executable(test_gake_speed768_avx2 ${GAKE_SPEED_FILES})
add_executable(test_gake_qrom_speed768_avx2 ${GAKE_QROM_SPEED_FILES})

target_include_directories(test_gake768_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_qrom768_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_speed768_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_qrom_speed768_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

target_link_libraries(test_gake768_avx2 kyber768_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_qrom768_avx2 kyber_qrom768_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_speed768_avx2 kyber768_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_qrom_speed768_avx2 kyber_qrom768_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})


# Kyber 1024
add_library(kyber1024_avx2 ${KYBER_FIPS202_SRCS})
target_compile_definitions(kyber1024_avx2 PUBLIC KYBER_K=4)
target_link_libraries(kyber1024_avx2 INTERFACE fips202_avx2)

add_library(kyber_qrom1024_avx2 ${KYBER_QROM_FIPS202_SRCS})
target_compile_definitions(kyber_qrom1024_avx2 PUBLIC KYBER_K=4)
target_link_libraries(kyber_qrom1024_avx2 INTERFACE fips202_avx2)

add_executable(test_gake1024_avx2 ${GAKE_FILES})
add_executable(test_gake_qrom1024_avx2 ${GAKE_QROM_FILES})
add_executable(test_gake_speed1024_avx2 ${GAKE_SPEED_FILES})
add_executable(test_gake_qrom_speed1024_avx2 ${GAKE_QROM_SPEED_FILES})

target_include_directories(test_gake1024_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_qrom1024_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_speed1024_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)
target_include_directories(test_gake_qrom_speed1024_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/avx2)

target_link_libraries(test_gake1024_avx2 kyber1024_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_qrom1024_avx2 kyber_qrom1024_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_speed1024_avx2 kyber1024_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
target_link_libraries(test_gake_qrom_speed1024_avx2 kyber_qrom1024_avx2 ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
