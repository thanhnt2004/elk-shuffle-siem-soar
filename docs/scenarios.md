# Kịch bản giám sát

Bảng mô tả tín hiệu cần quan sát và nhánh xử lý trong môi trường lab.

| Playbook | Nguồn quan sát | Tín hiệu | Xử lý theo tài liệu |
| --- | --- | --- | --- |
| PB01 | pfSense firewall | Một nguồn chạm nhiều cổng bị chặn ở WAN | Thông báo Telegram |
| PB02 | Nginx | Nhiều phản hồi 404 hoặc user-agent đã được rule nhận diện | Chặn IP tại Nginx có thời hạn; kiểm tra trạng thái chặn |
| PB03 | Log xác thực web | Mẫu đăng nhập thất bại bất thường hoặc đăng nhập thành công sau nhiều lượt sai | Chặn IP tại Nginx theo rule; thông báo và hậu kiểm |
| PB05 | Nginx | Dấu hiệu khai thác ứng dụng web nhìn thấy qua log HTTP | Phê duyệt hoặc chặn tại pfSense tùy rule; hậu kiểm |
| PB15 | Windows và Sysmon | Chuỗi kết nối mạng và tạo file, hoặc hành vi tải file đáng nghi | Phê duyệt, cách ly file và kiểm tra chặn kết nối ra |
| PB18 | Windows Security | Tạo Scheduled Task đáng nghi | Phê duyệt, vô hiệu hóa task và lưu bằng chứng cấu hình |
| PB23 | Windows Event Log và Security | Xóa nhật ký hoặc thay đổi chính sách audit | Cô lập host có phê duyệt hoặc khôi phục audit theo rule |
| PB16 | Linux audit | Dấu hiệu phiên shell bất thường | |
| PB31 | Linux hoặc Windows | Tương quan dấu hiệu đóng gói dữ liệu và kết nối ra | |

Các ô trống biểu thị kết quả ứng phó còn thiếu minh chứng trong bản đóng gói. Xem [kết quả](results.md) và [bảng ATT&CK](mitre-attack-coverage.md).
