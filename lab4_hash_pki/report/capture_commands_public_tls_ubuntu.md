# Lab 4 Public Trust TLS capture commands - Ubuntu

openssl s_client -connect 127.0.0.1:443 -servername bavan.infinityfreeapp.com -verify_hostname bavan.infinityfreeapp.com -verify_return_error -partial_chain -CAfile "/home/rvan1102/https-lab/chain/Sectigo_Public_Server_Authentication_Root_E46.crt" -showcerts

openssl s_client -connect 127.0.0.1:443 -servername bavan.infinityfreeapp.com -verify_hostname bavan.infinityfreeapp.com -verify_return_error -partial_chain -CAfile "/home/rvan1102/https-lab/chain/Sectigo_Public_Server_Authentication_Root_E46.crt" -brief

curl -Iv --resolve "bavan.infinityfreeapp.com:443:127.0.0.1" "https://bavan.infinityfreeapp.com/"

sudo apache2ctl configtest
sudo apache2ctl -S
