# Lab 1 Report â€” Symmetric Encryption with Crypto++

## 1. Má»¥c tiÃªu bÃ i lab

BÃ i lab nÃ y xÃ¢y dá»±ng cÃ´ng cá»¥ dÃ²ng lá»‡nh `aestool` sá»­ dá»¥ng thÆ° viá»‡n Crypto++ Ä‘á»ƒ thá»±c hiá»‡n mÃ£ hÃ³a Ä‘á»‘i xá»©ng báº±ng AES. CÃ´ng cá»¥ há»— trá»£ cÃ¡c cháº¿ Ä‘á»™ ECB, CBC, CFB, OFB, CTR, XTS, CCM vÃ  GCM. NgoÃ i chá»©c nÄƒng mÃ£ hÃ³a vÃ  giáº£i mÃ£, chÆ°Æ¡ng trÃ¬nh cÃ²n tÃ­ch há»£p sinh khÃ³a, lÆ°u metadata, kiá»ƒm tra Known Answer Test, negative testing, CTest vÃ  benchmark.

Má»¥c tiÃªu chÃ­nh khÃ´ng chá»‰ lÃ  gá»i Ä‘Ãºng API mÃ£ hÃ³a, mÃ  cÃ²n lÃ  triá»ƒn khai má»™t cÃ´ng cá»¥ cÃ³ tÃ­nh ká»¹ thuáº­t hoÃ n chá»‰nh. VÃ¬ váº­y, chÆ°Æ¡ng trÃ¬nh pháº£i xá»­ lÃ½ dá»¯ liá»‡u nhá»‹ phÃ¢n, há»— trá»£ input/output qua file, xÃ¡c thá»±c tag vá»›i cÃ¡c cháº¿ Ä‘á»™ AEAD, phÃ¡t hiá»‡n má»™t sá»‘ lá»—i sá»­ dá»¥ng sai nhÆ° nonce reuse, Ä‘á»“ng thá»i cung cáº¥p dá»¯ liá»‡u benchmark Ä‘á»ƒ Ä‘Ã¡nh giÃ¡ hiá»‡u nÄƒng.

## 2. MÃ´i trÆ°á»ng triá»ƒn khai

| ThÃ nh pháº§n | ThÃ´ng tin |
|---|---|
| Há»‡ Ä‘iá»u hÃ nh | Windows 11 25H2 |
| Compiler | MinGW64 g++ |
| Build system | CMake |
| Crypto library | Crypto++ 8.9.0 |
| Crypto++ root | D:/Newfolder/Crypto++ |
| CPU | AMD Ryzen 5 7535HS with Radeon Graphics |
| Cores / threads | 6 cores / 12 threads |
| RAM | 8 GB |
| Storage | Samsung MZVL8512HELU-00BTW SSD |
| Power mode | Performance |

Dá»± Ã¡n Ä‘Æ°á»£c build báº±ng CMake theo mÃ´ hÃ¬nh out-of-source build. CÃ¡ch tá»• chá»©c nÃ y giÃºp tÃ¡ch mÃ£ nguá»“n khá»i file sinh ra trong quÃ¡ trÃ¬nh biÃªn dá»‹ch vÃ  thuáº­n lá»£i cho viá»‡c kiá»ƒm thá»­ Ä‘a ná»n táº£ng.

## 3. Thiáº¿t káº¿ tá»•ng quan cÃ´ng cá»¥

CÃ´ng cá»¥ `aestool` Ä‘Æ°á»£c thiáº¿t káº¿ theo dáº¡ng command-line interface vá»›i cÃ¡c nhÃ³m lá»‡nh chÃ­nh gá»“m `keygen`, `encrypt`, `decrypt`, `kat` vÃ  `bench`. Lá»‡nh `keygen` dÃ¹ng Ä‘á»ƒ sinh khÃ³a. Lá»‡nh `encrypt` vÃ  `decrypt` thá»±c hiá»‡n mÃ£ hÃ³a hoáº·c giáº£i mÃ£ theo mode Ä‘Æ°á»£c chá»n táº¡i runtime. Lá»‡nh `kat` cháº¡y Known Answer Test tá»« file JSON. Lá»‡nh `bench` Ä‘o hiá»‡u nÄƒng vÃ  xuáº¥t dá»¯ liá»‡u ra CSV.

MÃ£ nguá»“n Ä‘Æ°á»£c chia thÃ nh nhiá»u module. CÃ¡c file xá»­ lÃ½ AES-GCM, AES-CCM, AES-XTS vÃ  cÃ¡c classic modes Ä‘Æ°á»£c tÃ¡ch riÃªng. CÃ¡c thÃ nh pháº§n phá»¥ trá»£ nhÆ° encoding, file utilities, metadata, nonce registry vÃ  benchmark cÅ©ng Ä‘Æ°á»£c Ä‘áº·t trong module riÃªng. CÃ¡ch chia nÃ y giÃºp chÆ°Æ¡ng trÃ¬nh dá»… kiá»ƒm thá»­, dá»… má»Ÿ rá»™ng vÃ  trÃ¡nh trá»™n logic mÃ£ hÃ³a vá»›i logic nháº­p xuáº¥t hoáº·c kiá»ƒm thá»­.

## 4. Thiáº¿t káº¿ CLI vÃ  Ä‘á»‹nh dáº¡ng dá»¯ liá»‡u

CLI cÃ³ dáº¡ng chung lÃ  `aestool <command> [options]`. Khi mÃ£ hÃ³a, ngÆ°á»i dÃ¹ng chá»‰ Ä‘á»‹nh mode báº±ng `--mode`, khÃ³a báº±ng `--key`, dá»¯ liá»‡u Ä‘áº§u vÃ o báº±ng `--in` hoáº·c `--text`, vÃ  file Ä‘áº§u ra báº±ng `--out`. Vá»›i cÃ¡c cháº¿ Ä‘á»™ AEAD nhÆ° GCM vÃ  CCM, chÆ°Æ¡ng trÃ¬nh há»— trá»£ AAD thÃ´ng qua `--aad-text` hoáº·c `--aad-file`.

ChÆ°Æ¡ng trÃ¬nh xá»­ lÃ½ ciphertext dÆ°á»›i dáº¡ng raw binary thay vÃ¬ text. CÃ¡c tham sá»‘ phá»¥ nhÆ° IV, nonce, tweak vÃ  tag Ä‘Æ°á»£c lÆ°u trong sidecar metadata JSON. VÃ­ dá»¥, náº¿u ciphertext lÃ  `ct.bin`, metadata máº·c Ä‘á»‹nh sáº½ lÃ  `ct.bin.meta.json`. CÃ¡ch lÃ m nÃ y giá»¯ ciphertext á»Ÿ dáº¡ng nhá»‹ phÃ¢n Ä‘Ãºng báº£n cháº¥t, Ä‘á»“ng thá»i váº«n lÆ°u Ä‘á»§ tham sá»‘ cáº§n thiáº¿t Ä‘á»ƒ giáº£i mÃ£.

## 5. Triá»ƒn khai cÃ¡c cháº¿ Ä‘á»™ AES

CÃ¡c cháº¿ Ä‘á»™ ECB, CBC, CFB, OFB vÃ  CTR Ä‘Æ°á»£c triá»ƒn khai trong nhÃ³m classic AES modes. ECB khÃ´ng dÃ¹ng IV vÃ  chá»‰ Ä‘Æ°á»£c giá»¯ láº¡i vÃ¬ yÃªu cáº§u bÃ i lab. CBC, CFB, OFB vÃ  CTR dÃ¹ng IV 16 byte. CBC vÃ  ECB trong luá»“ng CLI thÃ´ng thÆ°á»ng cÃ³ xá»­ lÃ½ padding; CFB, OFB vÃ  CTR hoáº¡t Ä‘á»™ng giá»‘ng stream-like modes nÃªn khÃ´ng cáº§n padding.

GCM vÃ  CCM Ä‘Æ°á»£c triá»ƒn khai nhÆ° cÃ¡c cháº¿ Ä‘á»™ AEAD. Khi mÃ£ hÃ³a, chÆ°Æ¡ng trÃ¬nh táº¡o ciphertext vÃ  authentication tag. Khi giáº£i mÃ£, chÆ°Æ¡ng trÃ¬nh xÃ¡c thá»±c tag trÆ°á»›c khi tráº£ plaintext. Náº¿u ciphertext, AAD hoáº·c tag bá»‹ sá»­a Ä‘á»•i, quÃ¡ trÃ¬nh giáº£i mÃ£ tháº¥t báº¡i vÃ  khÃ´ng cháº¥p nháº­n plaintext.

XTS Ä‘Æ°á»£c triá»ƒn khai cho ngá»¯ cáº£nh mÃ£ hÃ³a data unit kiá»ƒu lÆ°u trá»¯. XTS dÃ¹ng key material cÃ³ Ä‘á»™ dÃ i gáº¥p Ä‘Ã´i khÃ³a AES thÃ´ng thÆ°á»ng vÃ  dÃ¹ng tweak 16 byte. Tuy nhiÃªn, XTS khÃ´ng cung cáº¥p xÃ¡c thá»±c dá»¯ liá»‡u nÃªn ciphertext bá»‹ sá»­a Ä‘á»•i cÃ³ thá»ƒ táº¡o ra plaintext sai mÃ  khÃ´ng bÃ¡o lá»—i xÃ¡c thá»±c.

## 6. Quáº£n lÃ½ key, IV, nonce, tweak vÃ  metadata

KhÃ³a AES Ä‘Æ°á»£c sinh báº±ng nguá»“n ngáº«u nhiÃªn an toÃ n cá»§a Crypto++. ChÆ°Æ¡ng trÃ¬nh há»— trá»£ khÃ³a AES 128, 192 vÃ  256 bit. RiÃªng XTS há»— trá»£ key material 512 bit Ä‘á»ƒ táº¡o hai khÃ³a con 256 bit.

IV, nonce vÃ  tweak Ä‘Æ°á»£c táº¡o tá»± Ä‘á»™ng náº¿u ngÆ°á»i dÃ¹ng khÃ´ng cung cáº¥p. GCM dÃ¹ng nonce máº·c Ä‘á»‹nh 12 byte. CCM dÃ¹ng nonce há»£p lá»‡ theo yÃªu cáº§u cá»§a mode. CBC, CFB, OFB, CTR vÃ  XTS dÃ¹ng IV hoáº·c tweak 16 byte. ChÆ°Æ¡ng trÃ¬nh kiá»ƒm tra Ä‘á»™ dÃ i tham sá»‘ trÆ°á»›c khi mÃ£ hÃ³a hoáº·c giáº£i mÃ£ Ä‘á»ƒ trÃ¡nh lá»—i cáº¥u hÃ¬nh.

Metadata Ä‘Æ°á»£c lÆ°u dÆ°á»›i dáº¡ng JSON. Vá»›i GCM vÃ  CCM, metadata chá»©a nonce vÃ  tag. Vá»›i CBC, CFB, OFB vÃ  CTR, metadata chá»©a IV. Vá»›i XTS, metadata chá»©a tweak. Thiáº¿t káº¿ nÃ y giÃºp quÃ¡ trÃ¬nh giáº£i mÃ£ tÃ¡i sá»­ dá»¥ng Ä‘Ãºng tham sá»‘ mÃ  khÃ´ng cáº§n nhÃºng metadata vÃ o ciphertext.

## 7. CÆ¡ cháº¿ chá»‘ng sá»­ dá»¥ng sai

ECB Ä‘Æ°á»£c cáº£nh bÃ¡o lÃ  khÃ´ng an toÃ n vÃ¬ cÃ¡c block plaintext giá»‘ng nhau táº¡o ra cÃ¡c block ciphertext giá»‘ng nhau. CÃ´ng cá»¥ cháº·n mÃ£ hÃ³a file lá»›n hÆ¡n 16 KiB báº±ng ECB náº¿u ngÆ°á»i dÃ¹ng khÃ´ng chá»§ Ä‘á»™ng báº­t `--allow-ecb`.

CTR, GCM vÃ  CCM yÃªu cáº§u nonce hoáº·c IV khÃ´ng Ä‘Æ°á»£c láº·p láº¡i vá»›i cÃ¹ng khÃ³a. CÃ´ng cá»¥ sá»­ dá»¥ng local nonce registry dá»±a trÃªn tá»• há»£p mode, hash cá»§a khÃ³a vÃ  nonce hoáº·c IV. Náº¿u phÃ¡t hiá»‡n reuse, chÆ°Æ¡ng trÃ¬nh tá»« chá»‘i mÃ£ hÃ³a. ÄÃ¢y lÃ  má»™t cÆ¡ cháº¿ phÃ²ng vá»‡ á»Ÿ táº§ng cÃ´ng cá»¥ Ä‘á»ƒ giáº£m nguy cÆ¡ cáº¥u hÃ¬nh sai.

Vá»›i AEAD, chÆ°Æ¡ng trÃ¬nh Ã¡p dá»¥ng fail-closed. Náº¿u tag khÃ´ng há»£p lá»‡, chÆ°Æ¡ng trÃ¬nh bÃ¡o lá»—i vÃ  khÃ´ng tráº£ plaintext há»£p lá»‡. Äiá»u nÃ y Ä‘áº·c biá»‡t quan trá»ng vÃ¬ bá» qua lá»—i xÃ¡c thá»±c sáº½ lÃ m máº¥t Ã½ nghÄ©a báº£o máº­t cá»§a GCM vÃ  CCM.

## 8. Known Answer Test

Known Answer Test Ä‘Æ°á»£c dÃ¹ng Ä‘á»ƒ kiá»ƒm tra tÃ­nh Ä‘Ãºng Ä‘áº¯n cá»§a thuáº­t toÃ¡n báº±ng cÃ¡ch so sÃ¡nh output vá»›i cÃ¡c vector Ä‘Ã£ biáº¿t. KAT runner Ä‘á»c test case tá»« JSON vÃ  in káº¿t quáº£ PASS hoáº·c FAIL cho tá»«ng case.

Bá»™ KAT hiá»‡n táº¡i kiá»ƒm tra AES-128 ECB, CBC, CFB, OFB, CTR, GCM vÃ  CCM. Káº¿t quáº£ trÃªn Windows cho tháº¥y toÃ n bá»™ test case Ä‘á»u pass. Log KAT Ä‘Æ°á»£c lÆ°u táº¡i `report/assets/kat_windows.log`.

## 9. Negative Testing

Negative testing kiá»ƒm tra kháº£ nÄƒng xá»­ lÃ½ dá»¯ liá»‡u sai hoáº·c dá»¯ liá»‡u bá»‹ giáº£ máº¡o. Script Windows kiá»ƒm tra sai khÃ³a GCM, sai AAD, ciphertext GCM bá»‹ sá»­a, tag GCM bá»‹ sá»­a, metadata sai, khÃ³a sai Ä‘á»™ dÃ i, nonce sai Ä‘á»™ dÃ i, nonce reuse, ciphertext CCM bá»‹ sá»­a, IV reuse trong CTR, IV CBC sai Ä‘á»™ dÃ i, ECB large-file blocking, XTS input quÃ¡ ngáº¯n vÃ  XTS tampering behavior.

Káº¿t quáº£ negative test Ä‘Æ°á»£c lÆ°u táº¡i `report/assets/negative_tests_windows.log`.

## 10. CTest Integration

CTest Ä‘Æ°á»£c dÃ¹ng Ä‘á»ƒ cháº¡y tá»± Ä‘á»™ng cÃ¡c test Ä‘Ã£ cáº¥u hÃ¬nh. TrÃªn Windows, CTest cháº¡y KAT sample vÃ  negative test script. Káº¿t quáº£ CTest Ä‘Æ°á»£c lÆ°u táº¡i `report/assets/ctest_windows.log`.

## 11. PhÆ°Æ¡ng phÃ¡p benchmark

Benchmark Ä‘Æ°á»£c thá»±c hiá»‡n báº±ng lá»‡nh `bench` cá»§a `aestool`. ChÆ°Æ¡ng trÃ¬nh Ä‘o cáº£ mÃ£ hÃ³a vÃ  giáº£i mÃ£ cho ECB, CBC, CFB, OFB, CTR, GCM, CCM vÃ  XTS. CÃ¡c kÃ­ch thÆ°á»›c payload gá»“m 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB vÃ  8 MiB. Má»—i cáº¥u hÃ¬nh Ä‘Æ°á»£c cháº¡y 30 láº§n, má»—i láº§n gá»“m 100 phÃ©p toÃ¡n, cÃ³ warm-up trÆ°á»›c khi Ä‘o.

Dá»¯ liá»‡u benchmark Ä‘Æ°á»£c xuáº¥t thÃ nh raw CSV vÃ  summary CSV. Summary CSV chá»©a mean, median, standard deviation vÃ  khoáº£ng tin cáº­y 95% cho latency vÃ  throughput. File benchmark summary Ä‘Æ°á»£c lÆ°u táº¡i `report/assets/bench_windows_summary.csv`.

## 12. Káº¿t quáº£ benchmark Windows

CÃ¡c biá»ƒu Ä‘á»“ sau thá»ƒ hiá»‡n throughput vÃ  latency trÃªn Windows/MinGW64.

![Windows encryption throughput](assets/windows_encrypt_throughput.png)

![Windows decryption throughput](assets/windows_decrypt_throughput.png)

![Windows encryption latency](assets/windows_encrypt_latency.png)

![Windows decryption latency](assets/windows_decrypt_latency.png)

Báº£ng benchmark rÃºt gá»n Ä‘Æ°á»£c táº¡o tá»« summary CSV vÃ  lÆ°u táº¡i `report/assets/windows_benchmark_tables.md`.

NhÃ¬n chung, cÃ¡c mode khÃ´ng xÃ¡c thá»±c nhÆ° CTR, CFB, OFB vÃ  CBC cÃ³ chi phÃ­ tháº¥p hÆ¡n so vá»›i cÃ¡c mode AEAD trong nhiá»u trÆ°á»ng há»£p. GCM vÃ  CCM cÃ³ thÃªm overhead do authentication tag vÃ  xá»­ lÃ½ xÃ¡c thá»±c. XTS phÃ¹ há»£p vá»›i mÃ£ hÃ³a lÆ°u trá»¯ nhÆ°ng khÃ´ng cung cáº¥p integrity protection.

## 13. PhÃ¢n tÃ­ch báº£o máº­t

ECB khÃ´ng Ä‘áº¡t semantic security vÃ¬ lÃ m lá»™ máº«u plaintext. VÃ¬ váº­y, ECB khÃ´ng nÃªn dÃ¹ng cho dá»¯ liá»‡u thá»±c táº¿.

CBC an toÃ n hÆ¡n ECB náº¿u IV Ä‘Æ°á»£c sinh Ä‘Ãºng cÃ¡ch, nhÆ°ng CBC khÃ´ng xÃ¡c thá»±c ciphertext. Náº¿u pháº£n há»“i lá»—i padding khÃ´ng Ä‘Æ°á»£c xá»­ lÃ½ cáº©n tháº­n, CBC cÃ³ thá»ƒ liÃªn quan Ä‘áº¿n padding oracle attack.

CTR cÃ³ tÃ­nh linh hoáº¡t vÃ  hiá»‡u nÄƒng tá»‘t, nhÆ°ng reuse nonce hoáº·c IV vá»›i cÃ¹ng khÃ³a lÃ  lá»—i nghiÃªm trá»ng. Náº¿u reuse xáº£y ra, attacker cÃ³ thá»ƒ khai thÃ¡c quan há»‡ XOR giá»¯a cÃ¡c ciphertext.

GCM vÃ  CCM cung cáº¥p cáº£ confidentiality vÃ  integrity. Tuy nhiÃªn, hai mode nÃ y váº«n yÃªu cáº§u nonce duy nháº¥t dÆ°á»›i cÃ¹ng má»™t khÃ³a. VÃ¬ váº­y, nonce reuse prevention lÃ  má»™t lá»›p báº£o vá»‡ cáº§n thiáº¿t.

XTS Ä‘Æ°á»£c thiáº¿t káº¿ cho mÃ£ hÃ³a lÆ°u trá»¯ theo data unit. XTS khÃ´ng xÃ¡c thá»±c dá»¯ liá»‡u, do Ä‘Ã³ khÃ´ng nÃªn xem XTS lÃ  cÆ¡ cháº¿ chá»‘ng chá»‰nh sá»­a dá»¯ liá»‡u.

## 14. Giá»›i háº¡n hiá»‡n táº¡i

PhiÃªn báº£n hiá»‡n táº¡i Ä‘Ã£ hoÃ n thÃ nh build, test vÃ  benchmark trÃªn Windows. Pháº§n Linux chÆ°a Ä‘Æ°á»£c thá»±c hiá»‡n nÃªn chÆ°a thá»ƒ káº¿t luáº­n Ä‘áº§y Ä‘á»§ vá» so sÃ¡nh Ä‘a ná»n táº£ng. Bá»™ KAT hiá»‡n táº¡i lÃ  representative sample, chÆ°a bao phá»§ toÃ n bá»™ biáº¿n thá»ƒ khÃ³a, nonce, tag vÃ  payload. Registry chá»‘ng nonce reuse lÃ  cÆ¡ cháº¿ cá»¥c bá»™, khÃ´ng pháº£i cÆ¡ sá»Ÿ dá»¯ liá»‡u chá»‘ng sá»­a Ä‘á»•i trong mÃ´i trÆ°á»ng nhiá»u tiáº¿n trÃ¬nh.

## 15. Káº¿t luáº­n

CÃ´ng cá»¥ `aestool` Ä‘Ã£ triá»ƒn khai thÃ nh cÃ´ng cÃ¡c cháº¿ Ä‘á»™ AES yÃªu cáº§u trong Lab 1 báº±ng Crypto++. ChÆ°Æ¡ng trÃ¬nh há»— trá»£ mÃ£ hÃ³a, giáº£i mÃ£, sinh khÃ³a, metadata, AEAD verification, nonce reuse prevention, Known Answer Test, negative testing, CTest vÃ  benchmark. Káº¿t quáº£ trÃªn Windows cho tháº¥y chÆ°Æ¡ng trÃ¬nh hoáº¡t Ä‘á»™ng Ä‘Ãºng vá»›i cÃ¡c vector kiá»ƒm thá»­, tá»« chá»‘i cÃ¡c trÆ°á»ng há»£p lá»—i quan trá»ng vÃ  táº¡o Ä‘Æ°á»£c dá»¯ liá»‡u hiá»‡u nÄƒng Ä‘á»ƒ phá»¥c vá»¥ phÃ¢n tÃ­ch.

Giai Ä‘oáº¡n tiáº¿p theo lÃ  build vÃ  benchmark trÃªn Linux Ä‘á»ƒ hoÃ n thiá»‡n pháº§n so sÃ¡nh Ä‘a ná»n táº£ng, sau Ä‘Ã³ chuyá»ƒn bÃ¡o cÃ¡o sang Ä‘á»‹nh dáº¡ng DOCX náº¿u cáº§n ná»™p báº£n Word.


# Appendix A - Windows Benchmark Tables

# Windows Benchmark Tables

## Coverage

- Total summary rows: 96
- Modes: cbc, ccm, cfb, ctr, ecb, gcm, ofb, xts
- Operations: decrypt, encrypt
- Payload sizes: 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB, 8 MiB

Coverage check: PASS. Expected 96 rows and got 96 rows.

### Windows encrypt benchmark at 1 KiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ctr | 266.72 | Â±14.21 | 0.003787 | Â±0.000320 |
| ecb | 261.67 | Â±21.17 | 0.004041 | Â±0.000525 |
| cfb | 193.83 | Â±8.55 | 0.005159 | Â±0.000364 |
| gcm | 190.50 | Â±17.84 | 0.005512 | Â±0.000560 |
| cbc | 185.30 | Â±8.61 | 0.005400 | Â±0.000377 |
| ccm | 180.22 | Â±4.96 | 0.005455 | Â±0.000173 |
| xts | 150.08 | Â±7.22 | 0.006629 | Â±0.000341 |
| ofb | 148.81 | Â±14.17 | 0.007221 | Â±0.000961 |

### Windows decrypt benchmark at 1 KiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ctr | 260.07 | Â±19.06 | 0.004023 | Â±0.000492 |
| cbc | 257.26 | Â±13.53 | 0.003921 | Â±0.000320 |
| ecb | 246.79 | Â±20.57 | 0.004199 | Â±0.000388 |
| cfb | 232.21 | Â±17.23 | 0.004466 | Â±0.000484 |
| ofb | 189.23 | Â±7.55 | 0.005250 | Â±0.000300 |
| gcm | 184.24 | Â±6.60 | 0.005375 | Â±0.000275 |
| xts | 158.40 | Â±10.24 | 0.006429 | Â±0.000558 |
| ccm | 143.58 | Â±4.43 | 0.006880 | Â±0.000341 |

### Windows encrypt benchmark at 16 KiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ctr | 1636.00 | Â±82.84 | 0.009827 | Â±0.000729 |
| ecb | 1194.12 | Â±168.80 | 0.015949 | Â±0.002965 |
| gcm | 1070.28 | Â±34.24 | 0.014737 | Â±0.000578 |
| ofb | 446.00 | Â±9.66 | 0.035181 | Â±0.000907 |
| cfb | 441.09 | Â±13.18 | 0.035696 | Â±0.001222 |
| cbc | 435.61 | Â±8.84 | 0.035986 | Â±0.000767 |
| xts | 428.81 | Â±23.08 | 0.037189 | Â±0.001864 |
| ccm | 391.20 | Â±8.11 | 0.040077 | Â±0.000874 |

### Windows decrypt benchmark at 16 KiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ecb | 1828.12 | Â±81.18 | 0.008778 | Â±0.000710 |
| cbc | 1634.81 | Â±63.65 | 0.009690 | Â±0.000451 |
| ctr | 1624.06 | Â±78.75 | 0.009854 | Â±0.000645 |
| cfb | 1157.45 | Â±42.28 | 0.013658 | Â±0.000575 |
| gcm | 981.27 | Â±34.01 | 0.016089 | Â±0.000639 |
| xts | 486.95 | Â±27.04 | 0.032801 | Â±0.001720 |
| ofb | 445.35 | Â±6.90 | 0.035149 | Â±0.000556 |
| ccm | 376.51 | Â±7.50 | 0.041636 | Â±0.000904 |

### Windows encrypt benchmark at 1 MiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ctr | 1054.99 | Â±7.52 | 0.948243 | Â±0.006747 |
| ecb | 792.29 | Â±3.52 | 1.262357 | Â±0.005613 |
| gcm | 592.47 | Â±20.68 | 1.705719 | Â±0.068735 |
| xts | 426.96 | Â±6.97 | 2.346985 | Â±0.039326 |
| ofb | 384.73 | Â±1.04 | 2.599335 | Â±0.006972 |
| cfb | 371.07 | Â±5.32 | 2.699424 | Â±0.041476 |
| cbc | 344.49 | Â±2.01 | 2.903584 | Â±0.016889 |
| ccm | 313.11 | Â±3.02 | 3.196323 | Â±0.034496 |

### Windows decrypt benchmark at 1 MiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ecb | 1076.31 | Â±6.58 | 0.929364 | Â±0.005696 |
| cbc | 1033.04 | Â±16.25 | 0.969911 | Â±0.016078 |
| ctr | 1016.38 | Â±3.63 | 0.983982 | Â±0.003509 |
| cfb | 732.78 | Â±20.96 | 1.373525 | Â±0.041239 |
| gcm | 632.94 | Â±17.90 | 1.590437 | Â±0.049363 |
| xts | 416.99 | Â±6.06 | 2.402007 | Â±0.035280 |
| ofb | 379.08 | Â±1.47 | 2.638238 | Â±0.010201 |
| ccm | 314.05 | Â±1.59 | 3.184812 | Â±0.016708 |

### Windows encrypt benchmark at 8 MiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ctr | 871.30 | Â±6.06 | 9.185119 | Â±0.064718 |
| ecb | 727.95 | Â±2.89 | 10.991121 | Â±0.043752 |
| gcm | 596.63 | Â±5.36 | 13.416894 | Â±0.121313 |
| xts | 390.68 | Â±8.78 | 20.562041 | Â±0.499975 |
| ofb | 365.27 | Â±1.65 | 21.905031 | Â±0.098910 |
| cfb | 365.23 | Â±4.47 | 21.929856 | Â±0.281645 |
| cbc | 332.29 | Â±1.37 | 24.078702 | Â±0.098129 |
| ccm | 277.47 | Â±14.02 | 29.487697 | Â±1.724889 |

### Windows decrypt benchmark at 8 MiB

| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |
|---|---:|---:|---:|---:|
| ecb | 899.03 | Â±6.75 | 8.902465 | Â±0.070191 |
| ctr | 875.29 | Â±5.93 | 9.142963 | Â±0.061278 |
| cbc | 855.57 | Â±6.37 | 9.354398 | Â±0.069119 |
| cfb | 681.32 | Â±7.80 | 11.754139 | Â±0.142174 |
| gcm | 590.55 | Â±15.49 | 13.628785 | Â±0.414977 |
| xts | 399.31 | Â±4.09 | 20.051587 | Â±0.217964 |
| ofb | 359.67 | Â±1.63 | 22.245819 | Â±0.099986 |
| ccm | 242.85 | Â±5.87 | 33.095412 | Â±0.837318 |
