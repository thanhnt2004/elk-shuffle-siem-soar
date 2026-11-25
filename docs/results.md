# Kết quả đánh giá

Các số liệu PB01 dưới đây được trích từ biên bản kiểm thử ngày 22 và 24/11/2026 của đồ án. Thời gian theo giờ Việt Nam.

## PB01 R01

| Đợt | Đầu vào | Kết quả |
| --- | --- | --- |
| 22/11 · Rule Preview | 370 bản ghi giả lập trong 18 ca | 4 TP, 9 TN, 1 FP, 2 FN và 2 ca thiếu trường dữ liệu |
| 24/11 · Đối chứng đầu cuối | Lưu lượng thật, các bản ghi cùng cổng đích | 1 TN |
| 24/11 · Dương tính đầu cuối | Log firewall giả lập với 21 cổng đích phân biệt | 1 TP, có execution Shuffle, thông báo Telegram và bản ghi kết quả |

Ở ca dương tính đầu cuối, độ trễ từ khi đạt ngưỡng đến lúc có cảnh báo là **11,598 giây**. Từ lúc có cảnh báo đến khi Shuffle bắt đầu là **11,574 giây**. Telegram chấp nhận thông báo sau **34,574 giây** kể từ lúc có cảnh báo. Mỗi phép đo có một mẫu và PB01 chạy ở chế độ thông báo.

Tiêu chí phân loại trong Preview và kiểm thử đầu cuối thuộc hai tập ca riêng. Kết quả 4/6 ca dương tính trong Preview mô tả bộ mẫu đó.

## Các playbook còn lại

| Nhóm | Biên bản và kết quả từng ca |
| --- | --- |
| PB02, PB03, PB05, PB15, PB18, PB23 | |
| PB16, PB31 | |

## Cách đo của OPS3

- Ghép ca thử với cảnh báo qua rule, thực thể và cửa sổ thời gian.
- Tính tỷ lệ phát hiện và cảnh báo sai theo nhóm ca kỳ vọng. Ghi nhận riêng ca chưa đủ thông tin để đối chiếu.
- Dùng thời điểm tạo cảnh báo để đo MTTD. Tính thêm độ trễ thông báo, thời gian chờ phê duyệt và MTTR khi có dữ liệu tương ứng.
- Ghi nhận kết quả ứng phó dựa trên hậu kiểm và tổng hợp theo batch.

Xem [mã OPS3](../scripts/metrics/datn-metrics.py) và [bài kiểm thử hồi quy](../scripts/metrics/test_ops3_metrics.py).
