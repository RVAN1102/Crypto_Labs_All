$ReportDir = "report"
$AssetsDir = "report/assets"
$OutFile = "report/Lab1_Report_Windows.md"

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
New-Item -ItemType Directory -Force -Path $AssetsDir | Out-Null

$Content = @'
# Lab 1 Report — Symmetric Encryption with Crypto++

## 1. Mục tiêu bài lab

Bài lab này xây dựng công cụ dòng lệnh `aestool` sử dụng thư viện Crypto++ để thực hiện mã hóa đối xứng bằng AES. Công cụ hỗ trợ các chế độ ECB, CBC, CFB, OFB, CTR, XTS, CCM và GCM. Ngoài chức năng mã hóa và giải mã, chương trình còn tích hợp sinh khóa, lưu metadata, kiểm tra Known Answer Test, negative testing, CTest và benchmark.

Mục tiêu chính không chỉ là gọi đúng API mã hóa, mà còn là triển khai một công cụ có tính kỹ thuật hoàn chỉnh. Vì vậy, chương trình phải xử lý dữ liệu nhị phân, hỗ trợ input/output qua file, xác thực tag với các chế độ AEAD, phát hiện một số lỗi sử dụng sai như nonce reuse, đồng thời cung cấp dữ liệu benchmark để đánh giá hiệu năng.

## 2. Môi trường triển khai

| Thành phần | Thông tin |
|---|---|
| Hệ điều hành | Windows 11 25H2 |
| Compiler | MinGW64 g++ |
| Build system | CMake |
| Crypto library | Crypto++ 8.9.0 |
| Crypto++ root | D:/Newfolder/Crypto++ |
| CPU | AMD Ryzen 5 7535HS with Radeon Graphics |
| Cores / threads | 6 cores / 12 threads |
| RAM | 8 GB |
| Storage | Samsung MZVL8512HELU-00BTW SSD |
| Power mode | Performance |

Dự án được build bằng CMake theo mô hình out-of-source build. Cách tổ chức này giúp tách mã nguồn khỏi file sinh ra trong quá trình biên dịch và thuận lợi cho việc kiểm thử đa nền tảng.

## 3. Thiết kế tổng quan công cụ

Công cụ `aestool` được thiết kế theo dạng command-line interface với các nhóm lệnh chính gồm `keygen`, `encrypt`, `decrypt`, `kat` và `bench`. Lệnh `keygen` dùng để sinh khóa. Lệnh `encrypt` và `decrypt` thực hiện mã hóa hoặc giải mã theo mode được chọn tại runtime. Lệnh `kat` chạy Known Answer Test từ file JSON. Lệnh `bench` đo hiệu năng và xuất dữ liệu ra CSV.

Mã nguồn được chia thành nhiều module. Các file xử lý AES-GCM, AES-CCM, AES-XTS và các classic modes được tách riêng. Các thành phần phụ trợ như encoding, file utilities, metadata, nonce registry và benchmark cũng được đặt trong module riêng. Cách chia này giúp chương trình dễ kiểm thử, dễ mở rộng và tránh trộn logic mã hóa với logic nhập xuất hoặc kiểm thử.

## 4. Thiết kế CLI và định dạng dữ liệu

CLI có dạng chung là `aestool <command> [options]`. Khi mã hóa, người dùng chỉ định mode bằng `--mode`, khóa bằng `--key`, dữ liệu đầu vào bằng `--in` hoặc `--text`, và file đầu ra bằng `--out`. Với các chế độ AEAD như GCM và CCM, chương trình hỗ trợ AAD thông qua `--aad-text` hoặc `--aad-file`.

Chương trình xử lý ciphertext dưới dạng raw binary thay vì text. Các tham số phụ như IV, nonce, tweak và tag được lưu trong sidecar metadata JSON. Ví dụ, nếu ciphertext là `ct.bin`, metadata mặc định sẽ là `ct.bin.meta.json`. Cách làm này giữ ciphertext ở dạng nhị phân đúng bản chất, đồng thời vẫn lưu đủ tham số cần thiết để giải mã.

## 5. Triển khai các chế độ AES

Các chế độ ECB, CBC, CFB, OFB và CTR được triển khai trong nhóm classic AES modes. ECB không dùng IV và chỉ được giữ lại vì yêu cầu bài lab. CBC, CFB, OFB và CTR dùng IV 16 byte. CBC và ECB trong luồng CLI thông thường có xử lý padding; CFB, OFB và CTR hoạt động giống stream-like modes nên không cần padding.

GCM và CCM được triển khai như các chế độ AEAD. Khi mã hóa, chương trình tạo ciphertext và authentication tag. Khi giải mã, chương trình xác thực tag trước khi trả plaintext. Nếu ciphertext, AAD hoặc tag bị sửa đổi, quá trình giải mã thất bại và không chấp nhận plaintext.

XTS được triển khai cho ngữ cảnh mã hóa data unit kiểu lưu trữ. XTS dùng key material có độ dài gấp đôi khóa AES thông thường và dùng tweak 16 byte. Tuy nhiên, XTS không cung cấp xác thực dữ liệu nên ciphertext bị sửa đổi có thể tạo ra plaintext sai mà không báo lỗi xác thực.

## 6. Quản lý key, IV, nonce, tweak và metadata

Khóa AES được sinh bằng nguồn ngẫu nhiên an toàn của Crypto++. Chương trình hỗ trợ khóa AES 128, 192 và 256 bit. Riêng XTS hỗ trợ key material 512 bit để tạo hai khóa con 256 bit.

IV, nonce và tweak được tạo tự động nếu người dùng không cung cấp. GCM dùng nonce mặc định 12 byte. CCM dùng nonce hợp lệ theo yêu cầu của mode. CBC, CFB, OFB, CTR và XTS dùng IV hoặc tweak 16 byte. Chương trình kiểm tra độ dài tham số trước khi mã hóa hoặc giải mã để tránh lỗi cấu hình.

Metadata được lưu dưới dạng JSON. Với GCM và CCM, metadata chứa nonce và tag. Với CBC, CFB, OFB và CTR, metadata chứa IV. Với XTS, metadata chứa tweak. Thiết kế này giúp quá trình giải mã tái sử dụng đúng tham số mà không cần nhúng metadata vào ciphertext.

## 7. Cơ chế chống sử dụng sai

ECB được cảnh báo là không an toàn vì các block plaintext giống nhau tạo ra các block ciphertext giống nhau. Công cụ chặn mã hóa file lớn hơn 16 KiB bằng ECB nếu người dùng không chủ động bật `--allow-ecb`.

CTR, GCM và CCM yêu cầu nonce hoặc IV không được lặp lại với cùng khóa. Công cụ sử dụng local nonce registry dựa trên tổ hợp mode, hash của khóa và nonce hoặc IV. Nếu phát hiện reuse, chương trình từ chối mã hóa. Đây là một cơ chế phòng vệ ở tầng công cụ để giảm nguy cơ cấu hình sai.

Với AEAD, chương trình áp dụng fail-closed. Nếu tag không hợp lệ, chương trình báo lỗi và không trả plaintext hợp lệ. Điều này đặc biệt quan trọng vì bỏ qua lỗi xác thực sẽ làm mất ý nghĩa bảo mật của GCM và CCM.

## 8. Known Answer Test

Known Answer Test được dùng để kiểm tra tính đúng đắn của thuật toán bằng cách so sánh output với các vector đã biết. KAT runner đọc test case từ JSON và in kết quả PASS hoặc FAIL cho từng case.

Bộ KAT hiện tại kiểm tra AES-128 ECB, CBC, CFB, OFB, CTR, GCM và CCM. Kết quả trên Windows cho thấy toàn bộ test case đều pass. Log KAT được lưu tại `report/assets/kat_windows.log`.

## 9. Negative Testing

Negative testing kiểm tra khả năng xử lý dữ liệu sai hoặc dữ liệu bị giả mạo. Script Windows kiểm tra sai khóa GCM, sai AAD, ciphertext GCM bị sửa, tag GCM bị sửa, metadata sai, khóa sai độ dài, nonce sai độ dài, nonce reuse, ciphertext CCM bị sửa, IV reuse trong CTR, IV CBC sai độ dài, ECB large-file blocking, XTS input quá ngắn và XTS tampering behavior.

Kết quả negative test được lưu tại `report/assets/negative_tests_windows.log`.

## 10. CTest Integration

CTest được dùng để chạy tự động các test đã cấu hình. Trên Windows, CTest chạy KAT sample và negative test script. Kết quả CTest được lưu tại `report/assets/ctest_windows.log`.

## 11. Phương pháp benchmark

Benchmark được thực hiện bằng lệnh `bench` của `aestool`. Chương trình đo cả mã hóa và giải mã cho ECB, CBC, CFB, OFB, CTR, GCM, CCM và XTS. Các kích thước payload gồm 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB và 8 MiB. Mỗi cấu hình được chạy 30 lần, mỗi lần gồm 100 phép toán, có warm-up trước khi đo.

Dữ liệu benchmark được xuất thành raw CSV và summary CSV. Summary CSV chứa mean, median, standard deviation và khoảng tin cậy 95% cho latency và throughput. File benchmark summary được lưu tại `report/assets/bench_windows_summary.csv`.

## 12. Kết quả benchmark Windows

Các biểu đồ sau thể hiện throughput và latency trên Windows/MinGW64.

![Windows encryption throughput](assets/windows_encrypt_throughput.png)

![Windows decryption throughput](assets/windows_decrypt_throughput.png)

![Windows encryption latency](assets/windows_encrypt_latency.png)

![Windows decryption latency](assets/windows_decrypt_latency.png)

Bảng benchmark rút gọn được tạo từ summary CSV và lưu tại `report/assets/windows_benchmark_tables.md`.

Nhìn chung, các mode không xác thực như CTR, CFB, OFB và CBC có chi phí thấp hơn so với các mode AEAD trong nhiều trường hợp. GCM và CCM có thêm overhead do authentication tag và xử lý xác thực. XTS phù hợp với mã hóa lưu trữ nhưng không cung cấp integrity protection.

## 13. Phân tích bảo mật

ECB không đạt semantic security vì làm lộ mẫu plaintext. Vì vậy, ECB không nên dùng cho dữ liệu thực tế.

CBC an toàn hơn ECB nếu IV được sinh đúng cách, nhưng CBC không xác thực ciphertext. Nếu phản hồi lỗi padding không được xử lý cẩn thận, CBC có thể liên quan đến padding oracle attack.

CTR có tính linh hoạt và hiệu năng tốt, nhưng reuse nonce hoặc IV với cùng khóa là lỗi nghiêm trọng. Nếu reuse xảy ra, attacker có thể khai thác quan hệ XOR giữa các ciphertext.

GCM và CCM cung cấp cả confidentiality và integrity. Tuy nhiên, hai mode này vẫn yêu cầu nonce duy nhất dưới cùng một khóa. Vì vậy, nonce reuse prevention là một lớp bảo vệ cần thiết.

XTS được thiết kế cho mã hóa lưu trữ theo data unit. XTS không xác thực dữ liệu, do đó không nên xem XTS là cơ chế chống chỉnh sửa dữ liệu.

## 14. Giới hạn hiện tại

Phiên bản hiện tại đã hoàn thành build, test và benchmark trên Windows. Phần Linux chưa được thực hiện nên chưa thể kết luận đầy đủ về so sánh đa nền tảng. Bộ KAT hiện tại là representative sample, chưa bao phủ toàn bộ biến thể khóa, nonce, tag và payload. Registry chống nonce reuse là cơ chế cục bộ, không phải cơ sở dữ liệu chống sửa đổi trong môi trường nhiều tiến trình.

## 15. Kết luận

Công cụ `aestool` đã triển khai thành công các chế độ AES yêu cầu trong Lab 1 bằng Crypto++. Chương trình hỗ trợ mã hóa, giải mã, sinh khóa, metadata, AEAD verification, nonce reuse prevention, Known Answer Test, negative testing, CTest và benchmark. Kết quả trên Windows cho thấy chương trình hoạt động đúng với các vector kiểm thử, từ chối các trường hợp lỗi quan trọng và tạo được dữ liệu hiệu năng để phục vụ phân tích.

Giai đoạn tiếp theo là build và benchmark trên Linux để hoàn thiện phần so sánh đa nền tảng, sau đó chuyển báo cáo sang định dạng DOCX nếu cần nộp bản Word.

'@

Set-Content -Path $OutFile -Value $Content -Encoding UTF8

Add-Content -Path $OutFile -Value ''
Add-Content -Path $OutFile -Value '# Appendix A - Windows Benchmark Tables'
Add-Content -Path $OutFile -Value ''

if (Test-Path 'report/assets/windows_benchmark_tables.md') {
    Get-Content 'report/assets/windows_benchmark_tables.md' | Add-Content -Path $OutFile
} else {
    Add-Content -Path $OutFile -Value 'Benchmark table file not found.'
}

Write-Host 'Report created.'