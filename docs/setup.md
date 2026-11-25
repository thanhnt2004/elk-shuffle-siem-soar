# Cấu hình môi trường lab

## Chuẩn bị

- EC2 chạy Linux có Docker Engine, Docker Compose, Bash, curl và jq. Compose cần hiểu các thẻ `!override` và `!reset` của cấu hình Shuffle.
- Máy lab có tuyến WireGuard đến địa chỉ nhận log. Các cấu hình ví dụ dùng địa chỉ VPN `10.99.0.1`; sửa đồng bộ Compose, SAN chứng chỉ và cấu hình agent khi dùng địa chỉ khác.
- Chuẩn bị CA riêng, các giá trị bí mật cho từng dịch vụ và chứng chỉ máy chủ. Các mẫu `.env.example` để trống những giá trị này. Kibana và giao diện Shuffle mặc định truy cập qua loopback hoặc SSH tunnel.

## Khởi tạo ELK

Từ thư mục gốc trên máy Linux, tạo file cấu hình cục bộ.

```bash
cp configs/elk/.env.example configs/elk/.env
chmod 600 configs/elk/.env
```

Điền phiên bản và các giá trị trống. Có thể dùng `openssl rand -hex 32` để tạo một giá trị ngẫu nhiên riêng cho từng mật khẩu và khóa. Kiểm tra địa chỉ trong [instances.yml](../configs/elk/instances.yml) trước khi sinh chứng chỉ.

```bash
docker compose --env-file configs/elk/.env -f configs/elk/docker-compose.yml config --quiet
docker compose --env-file configs/elk/.env -f configs/elk/docker-compose.yml --profile setup run --rm es-setup
docker compose --env-file configs/elk/.env -f configs/elk/docker-compose.yml up -d elasticsearch
docker compose --env-file configs/elk/.env -f configs/elk/docker-compose.yml ps
```

Khi Elasticsearch đã healthy, cấu hình người dùng dịch vụ, index template và retention. Chạy từ thư mục gốc của repo.

```bash
bash scripts/elk/setup-es.sh
docker compose --env-file configs/elk/.env -f configs/elk/docker-compose.yml up -d kibana logstash
bash scripts/elk/setup-kibana.sh
bash scripts/elk/load-beats-pipelines.sh
```

Cài Filebeat và Winlogbeat theo phiên bản ELK. Dùng [cấu hình Beats](../configs/beats/) và sao chép chứng chỉ CA công khai của lab tới đường dẫn tương ứng của từng agent. Nạp pipeline Winlogbeat vào Elasticsearch trước khi chuyển output của Winlogbeat sang Logstash. Trỏ syslog pfSense tới listener UDP 5514 trên VPN. Kiểm tra log từng nguồn trong Kibana Discover bằng data view `datn-*`.

Các [rule JSON](../configs/elk/rules/) gồm 16 rule của đợt triển khai 24–25/11, trong đó R37 thuộc PB16 và R43, R44 thuộc PB31. File mẫu để `enabled: false` để người vận hành đối chiếu data view, trường log và workflow trước khi bật trong môi trường riêng.

## Kết nối Shuffle và forwarder

1. Đặt [Compose override](../configs/shuffle/docker-compose.override.yml) cạnh Compose gốc của Shuffle theo tag trong [mẫu cấu hình](../configs/shuffle/.env.example), rồi điền những biến phù hợp vào `.env` của Shuffle. Xác nhận tên mạng `shuffle` và quyền kết nối tới máy lab trước khi thêm hành động ứng phó.
2. Tạo workflow nhận webhook trong Shuffle. [Luồng ứng phó](../configs/shuffle/workflow.md) mô tả các nhánh; trình dựng cần PB01 đã có metadata mẫu và các ID do Shuffle cấp cho cài đặt riêng.
3. Tạo API key Elasticsearch có quyền đọc chỉ mục cảnh báo. Sao chép [mẫu forwarder](../scripts/forwarder/.env.example) thành `scripts/forwarder/.env`. Điền `ES_API_KEY`, `WEBHOOK_SECRET` và URL nội bộ cho từng webhook đang dùng. Đặt khóa webhook giống nhau ở forwarder và Shuffle.
4. Khởi động forwarder sau khi hai mạng Docker và chứng chỉ CA đã sẵn sàng. Theo dõi một cảnh báo mẫu trong Kibana và đối chiếu execution tương ứng trong Shuffle.

```bash
docker compose -f scripts/forwarder/docker-compose.yml up -d
docker compose -f scripts/forwarder/docker-compose.yml logs --tail 30
```

Nếu chạy trình dựng workflow, nạp ba ID từ mẫu Shuffle vào môi trường tiến trình và cung cấp URL/API key trong file cục bộ mà [shuffle_lib.py](../scripts/soar/shuffle_lib.py) đọc. Mã workflow và bước ghi kết quả dùng bố cục triển khai `/opt/datn` trên EC2. Xác nhận URL nội bộ của backend, người dùng SSH, quyền thao tác và đường dẫn responder trên mỗi VM trước khi kích hoạt rule.

## Kiểm tra kết quả tại máy

Bài kiểm thử hồi quy sử dụng dữ liệu trong chính bộ kiểm thử và chạy từ thư mục gốc.

```bash
python -B scripts/metrics/test_ops3_metrics.py
```

Xem [kết quả đã ghi nhận](results.md) và các [mục còn trống](pending.md).
