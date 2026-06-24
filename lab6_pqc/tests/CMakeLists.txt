find_package(GTest REQUIRED)

function(add_pq_test_executable target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE pqtool_core GTest::gtest_main)
endfunction()

add_pq_test_executable(test_encoding test_encoding.cpp)
add_test(NAME encoding_base64_roundtrip COMMAND test_encoding --gtest_filter=Encoding.Base64Roundtrip)
add_test(NAME encoding_hex_roundtrip COMMAND test_encoding --gtest_filter=Encoding.HexRoundtrip)

add_pq_test_executable(test_json_canonical test_json_canonical.cpp)
add_test(NAME json_canonical_stable_order COMMAND test_json_canonical)

add_pq_test_executable(test_mldsa_roundtrip test_mldsa_roundtrip.cpp)
add_test(NAME mldsa44_keygen_sign_verify_roundtrip COMMAND test_mldsa_roundtrip --gtest_filter=MlDsa.Mldsa44Roundtrip)
add_test(NAME mldsa65_keygen_sign_verify_roundtrip COMMAND test_mldsa_roundtrip --gtest_filter=MlDsa.Mldsa65Roundtrip)
add_test(NAME mldsa44_modified_message_fails COMMAND test_mldsa_roundtrip --gtest_filter=MlDsa.ModifiedMessageFails)
add_test(NAME mldsa44_modified_signature_fails COMMAND test_mldsa_roundtrip --gtest_filter=MlDsa.ModifiedSignatureFails)
add_test(NAME mldsa44_wrong_public_key_fails COMMAND test_mldsa_roundtrip --gtest_filter=MlDsa.WrongPublicKeyFails)

add_pq_test_executable(test_mlkem_roundtrip test_mlkem_roundtrip.cpp)
add_test(NAME mlkem512_keygen_encaps_decaps_match COMMAND test_mlkem_roundtrip --gtest_filter=MlKem.Mlkem512Roundtrip)
add_test(NAME mlkem768_keygen_encaps_decaps_match COMMAND test_mlkem_roundtrip --gtest_filter=MlKem.Mlkem768Roundtrip)
add_test(NAME mlkem512_modified_ciphertext_fails_or_mismatch COMMAND test_mlkem_roundtrip --gtest_filter=MlKem.ModifiedCiphertextMismatch)
add_test(NAME mlkem512_wrong_private_key_fails_or_mismatch COMMAND test_mlkem_roundtrip --gtest_filter=MlKem.WrongPrivateKeyMismatch)

add_pq_test_executable(test_pq_cert test_pq_cert.cpp)
add_test(NAME pq_cert_create_verify_success COMMAND test_pq_cert --gtest_filter=PqCert.CreateVerify)
add_test(NAME pq_cert_tampered_subject_fails COMMAND test_pq_cert --gtest_filter=PqCert.TamperedSubject)
add_test(NAME pq_cert_tampered_public_key_fails COMMAND test_pq_cert --gtest_filter=PqCert.TamperedPublicKey)
add_test(NAME pq_cert_tampered_signature_fails COMMAND test_pq_cert --gtest_filter=PqCert.TamperedSignature)

add_pq_test_executable(test_cli_negative test_cli_negative.cpp)
add_test(NAME cli_help_returns_zero COMMAND test_cli_negative --gtest_filter=Cli.Help)
add_test(NAME cli_unsupported_algorithm_fails COMMAND test_cli_negative --gtest_filter=Cli.UnsupportedAlgorithm)
add_test(NAME cli_missing_file_fails COMMAND test_cli_negative --gtest_filter=Cli.MissingFile)
add_test(NAME cli_malformed_key_fails COMMAND test_cli_negative --gtest_filter=Cli.MalformedKey)

