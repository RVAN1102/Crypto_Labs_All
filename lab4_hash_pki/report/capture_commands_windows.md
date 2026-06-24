# Lab 4 Windows capture commands

Run final CTest screenshot:
ctest --test-dir lab4_hash_pki\build --output-on-failure

Run final negative tests screenshot:
powershell -NoProfile -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\negative_tests_windows.ps1 -Exe "D:\Newfolder\Crypto_Labs_All\lab4_hash_pki\build\hashtool.exe"

Run MD5 collision verification screenshot:
powershell -NoProfile -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\verify_md5_collision_windows.ps1 -Dir lab4_hash_pki\demos\md5_collision
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_a.bin MD5
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_b.bin MD5
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_a.bin SHA256
certutil -hashfile lab4_hash_pki\demos\md5_collision\collision_b.bin SHA256

Run length-extension screenshot:
lab4_hash_pki\build\hashtool.exe length-extension-demo --out-dir lab4_hash_pki\demos\length_extension
type lab4_hash_pki\demos\length_extension\verification_result.txt

Run TLS local evidence screenshot:
powershell -NoProfile -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\tls_local_self_signed_demo_windows.ps1
type lab4_hash_pki\demos\tls\tls_test_log.txt
