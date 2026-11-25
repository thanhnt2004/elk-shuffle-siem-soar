# Ánh xạ MITRE ATT&CK

| Playbook | Rule | Kỹ thuật ghi trong thiết kế hoặc rule | Trạng thái tài liệu |
| --- | --- | --- | --- |
| PB01 | R01 | T1595 | Có biên bản Preview và đầu cuối |
| PB02 | R02, R03 | T1595.003, T1595.002 | R02 có lượt ứng phó đã hậu kiểm |
| PB03 | R04, R05, R06 | T1110.003, T1110.004, T1110.001 | R04 và R05 có lượt ứng phó đã hậu kiểm |
| PB05 | R07, R08, R09 | T1190 | R07 và R09 có lượt ứng phó đã hậu kiểm |
| PB15 | R13, R14 | T1105 | Đã triển khai, còn thiếu biên bản E2E |
| PB18 | R16 | T1053.005 | R16 có lượt ứng phó đã hậu kiểm |
| PB23 | R67, R68 | T1685.005, T1685.001 | Cả hai rule có lượt ứng phó đã hậu kiểm |
| PB16 | R37 | T1059.004, T1571 | R37 có lượt ứng phó đã hậu kiểm |
| PB31 | R43, R44 | T1560.001, T1048.003, T1041 | R43 Ubuntu và R44 Windows có lượt ứng phó đã hậu kiểm |

Độ bao phủ ở đây gắn với nguồn log và truy vấn của từng rule. Đọc [rule JSON](../configs/elk/rules/) hoặc [trình sinh rule](../scripts/detections/make-rules.py) để đối chiếu metadata. [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/).
