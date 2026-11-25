# Luồng ứng phó trong Shuffle

![Các nhánh thông báo, tự động, phê duyệt và hậu kiểm](../../screenshots/architecture/response.svg)

1. Nhận webhook từ forwarder. Kiểm tra đầu vào, trùng lặp và allowlist trước khi xem xét phản ứng.
2. Làm giàu thông tin với cảnh báo và sự kiện liên quan. Kiểm tra cooldown theo thực thể.
3. Phân nhánh thông báo, ứng phó tự động hoặc chờ phê duyệt tùy playbook và rule.
4. Hậu kiểm trạng thái trên thiết bị khi có hành động. Gửi thông báo và ghi kết quả để OPS3 tổng hợp.

PB01 là luồng thông báo với một bước ghi bằng chứng sau Telegram theo biên bản ngày 24/11. Nhánh dừng sớm trong PB01 có phạm vi ghi kết quả riêng. Sơ đồ thể hiện luồng chung của các playbook.

## Tệp cấu hình

- [Compose override](docker-compose.override.yml) bổ sung cho Compose gốc của Shuffle theo phiên bản trong mẫu môi trường.
- [Mẫu biến môi trường](.env.example) giữ trống ID cài đặt và khóa vận hành.
- [Mã dựng workflow](../../scripts/soar/build-workflows.py) cần workflow PB01 làm mẫu metadata, kết nối Shuffle và tài khoản riêng của môi trường lab.
- [Thư mục export](exports/) dành cho bản JSON đã được rà soát thông tin xác thực.
