# Lab 4 Public Trust TLS capture commands - Windows

openssl s_client -connect 127.0.0.1:443 -servername bavan.infinityfreeapp.com -verify_hostname bavan.infinityfreeapp.com -verify_return_error -partial_chain -CAfile "D:\https-lab\chain\Sectigo_Public_Server_Authentication_Root_E46.crt" -showcerts

openssl s_client -connect 127.0.0.1:443 -servername bavan.infinityfreeapp.com -verify_hostname bavan.infinityfreeapp.com -verify_return_error -partial_chain -CAfile "D:\https-lab\chain\Sectigo_Public_Server_Authentication_Root_E46.crt" -brief

curl.exe -Iv --resolve "bavan.infinityfreeapp.com:443:127.0.0.1" "https://bavan.infinityfreeapp.com/"

D:\Apache24\bin\httpd.exe -t
D:\Apache24\bin\httpd.exe -S
