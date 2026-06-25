# Lab 4 Ubuntu capture commands

Run final CTest screenshot:
ctest --test-dir lab4_hash_pki/build-linux --output-on-failure

Run final negative tests screenshot:
./lab4_hash_pki/scripts/negative_tests_linux.sh "$(realpath lab4_hash_pki/build-linux/hashtool)"

Run MD5 collision verification screenshot:
./lab4_hash_pki/scripts/verify_md5_collision.sh lab4_hash_pki/demos/md5_collision
md5sum lab4_hash_pki/demos/md5_collision/collision_a.bin lab4_hash_pki/demos/md5_collision/collision_b.bin
sha256sum lab4_hash_pki/demos/md5_collision/collision_a.bin lab4_hash_pki/demos/md5_collision/collision_b.bin

Run length-extension screenshot:
./lab4_hash_pki/build-linux/hashtool length-extension-demo --out-dir lab4_hash_pki/demos/length_extension
cat lab4_hash_pki/demos/length_extension/verification_result.txt

Run TLS local evidence screenshot:
./lab4_hash_pki/scripts/tls_local_self_signed_demo_linux.sh
cat lab4_hash_pki/demos/tls/tls_test_log.txt
