# Lab 1 Windows screenshot commands

## W01 - Windows artifacts tree
cd D:\Newfolder\Crypto_Labs_All
tree lab1_aes\artifacts\windows /F

## W02 - Windows aestool help
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
artifacts\windows\binaries\aestool.exe --help

## W03 - Windows CTest evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
type artifacts\windows\logs\ctest_windows.log

## W04 - Windows KAT evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
type artifacts\windows\logs\kat_windows_clean.log

## W05 - Windows negative tests evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
type artifacts\windows\logs\negative_tests_windows.log

## W06 - Windows benchmark files
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
dir artifacts\windows\bench

## W07 - Windows CBC evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\kat_windows_clean.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "CBC|Cbc|cbc"

## W08 - Windows CTR/reuse evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "CTR|Ctr|ctr|reuse|nonce|IV"

## W09 - Windows GCM fail-closed evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "GCM|Gcm|gcm|AAD|aad|tag|tamper|wrong key"

## W10 - Windows CCM fail-closed evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "CCM|Ccm|ccm|tag|tamper|nonce"

## W11 - Windows XTS evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "XTS|Xts|xts|short|tamper"

## W12 - Windows ECB restriction evidence
cd D:\Newfolder\Crypto_Labs_All\lab1_aes
Select-String -Path artifacts\windows\logs\ctest_windows.log,artifacts\windows\logs\negative_tests_windows.log -Pattern "ECB|Ecb|ecb|allow|large"
