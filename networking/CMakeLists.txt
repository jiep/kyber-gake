cmake_policy(SET CMP0079 NEW)

add_executable(server server.c io.c ../ref/gake.c ../ref/utils.c ../ref/kex.c ../ref/randombytes.c ../ref/commitment.c ../ref/indcca.c ../ref/aes256gcm.c ../ref/kem.c ../ref/kem_det.c)
target_link_libraries(server kyber_qrom512_ref ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})

add_executable(client client.c io.c ../ref/gake.c ../ref/utils.c ../ref/kex.c ../ref/randombytes.c ../ref/commitment.c ../ref/indcca.c ../ref/aes256gcm.c ../ref/kem.c ../ref/kem_det.c)
target_link_libraries(client kyber_qrom512_ref ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})

add_executable(init init.c io.c ../ref/gake.c ../ref/utils.c ../ref/kex.c ../ref/randombytes.c ../ref/commitment.c ../ref/indcca.c ../ref/aes256gcm.c ../ref/kem.c ../ref/kem_det.c)
target_link_libraries(init kyber_qrom512_ref ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})

add_executable(gake_network gake_network.c io.c ../ref/gake.c ../ref/utils.c ../ref/kex.c ../ref/randombytes.c ../ref/commitment.c ../ref/indcca.c ../ref/aes256gcm.c ../ref/kem.c ../ref/kem_det.c)
target_link_libraries(gake_network kyber_qrom512_ref ${OPENSSL_CRYPTO_LIBRARY} Threads::Threads ${CMAKE_DL_LIBS})
