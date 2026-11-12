# Wazuh canh gác endpoint doanh nghiệp nhỏ: hoàn thiện đồ án A21

Nhóm Nguyễn Đăng Khoa, Lê Hữu Hoàng và Chu Quang Cường đã dựng được phần khó nhất của đồ án: một mạng mô phỏng doanh nghiệp nhỏ trải trên hai máy vật lý, năm vùng mạng sau pfSense, một Wazuh all-in-one và hai agent (WEB01, WIN01) gửi dữ liệu về manager qua bridge ZeroTier. Tuy vậy, **chỉ 2 trên 6 use case có bằng chứng bằng output thật**: UC2 (phát hiện SSH brute-force và tự chặn IP bằng active response) và UC4 (VirusTotal phát hiện rồi xóa mẫu EICAR). UC1 (FIM), UC5 (YARA) và UC6 (rootcheck) mới có cấu hình và các bước, chưa có alert nào. UC3 (lỗ hổng) vẫn đang gỡ lỗi. Yêu cầu (3) nguyên tắc hoạt động và (5) hệ sinh thái chưa xuất hiện trong ghi chú. Đối chiếu với tài liệu chính thức còn lộ ra bốn điểm cần sửa. Thứ nhất, WEB01 chạy Ubuntu 26.04, phiên bản nằm ngoài danh sách được hỗ trợ: ma trận tương thích của vulnerability detection chỉ liệt kê Ubuntu đến 24.04, nên UC3 trên WEB01 nhiều khả năng không ra CVE. Thứ hai, bản 4.14.9 nhóm đang dùng đã bị 4.14.10 (5/11/2026) thay thế; bản mới vá một lỗi command injection mức root trong rootcheck. Thứ ba, script YARA chính thức chỉ phát hiện chứ không xóa file. Thứ tư, ảnh dashboard trên slide hiện agent wazuh01 và SNORT-B chứ không phải WEB01/WIN01. Về so sánh, Wazuh là nền tảng SIEM/XDR thiên về phát hiện, Velociraptor là công cụ điều tra số (DFIR) và săn mối đe dọa, còn Apex One là EPP/EDR thương mại thiên về ngăn chặn. Ba sản phẩm bổ trợ cho nhau nhiều hơn là thay thế nhau. Phần cuối báo cáo liệt kê trạng thái từng yêu cầu, từng use case và danh sách việc cần làm theo thứ tự ưu tiên.

> **Cách dùng tài liệu này.** Phần I–V là khung báo cáo đồ án mà nhóm có thể chỉnh sửa và nộp. Phần "Hiện trạng đồ án và việc cần làm" ở cuối là phần làm việc nội bộ, không đưa vào bản nộp. Mọi chỗ `[Chèn ảnh: …]` hoặc `[Chèn output: …]` là bằng chứng nhóm phải tự chụp hoặc dán. Báo cáo không bịa kết quả thay nhóm. Trích dẫn ghi chú lab có dạng "(ghi chú UCx, dòng n)".

---

# PHẦN I. LÝ THUYẾT

## 1. Wazuh là SIEM/XDR mã nguồn mở kế thừa mười năm của OSSEC

Wazuh tự mô tả là nền tảng mã nguồn mở, miễn phí, để phòng ngừa, phát hiện và phản ứng với mối đe dọa trên workload on-premises, ảo hóa, container và cloud. Kho GitHub ghi khẩu hiệu "Unified XDR and SIEM protection for endpoints and cloud workloads" ([GitHub wazuh/wazuh](https://github.com/wazuh/wazuh)). Về giấy phép, **phần lớn mã nguồn theo GPLv2**. Riêng engine (`src/engine/`) theo AGPLv3, và một số thư viện dùng chung có giấy phép kép GPLv2/AGPLv3 ([GitHub wazuh/wazuh](https://github.com/wazuh/wazuh)). Theo công bố của chính Wazuh, nền tảng bảo vệ hơn 15 triệu endpoint, có hơn 100 nghìn người dùng doanh nghiệp và hơn 30 triệu lượt tải mỗi năm ([Wazuh – Who we are](https://wazuh.com/?p=11893)). Đây là số liệu do nhà cung cấp tự công bố, chưa được kiểm toán độc lập.

Wazuh có gốc từ OSSEC HIDS. Daniel B. Cid khởi đầu OSSEC năm 2004 như một hệ thống phát hiện xâm nhập trên máy chủ (HIDS) ([noze.it](https://www.noze.it/en/insights/ossec-open-source)). Năm 2015, nhóm Wazuh fork dự án và mở rộng phần lõi OSSEC gồm phân tích log, giám sát toàn vẹn, cảnh báo thời gian thực và active response. Họ bổ sung RESTful API, đánh giá lỗ hổng, module SCA, bộ rule lớn hơn và dashboard tuân thủ ([Wazuh blog: Migrating from OSSEC](https://wazuh.com/blog/migrating-from-ossec-to-wazuh/)). Có hai mốc phiên bản quan trọng cho phần lý thuyết. **Bản 4.3.0 (5/5/2022)** giới thiệu Wazuh indexer, một bản OpenSearch tùy biến, và Wazuh dashboard, một bản OpenSearch Dashboards có tích hợp plugin Wazuh ([Release notes 4.3.0](https://documentation.wazuh.com/4.3/release-notes/release-4-3-0.html)). **Bản 4.8.0 (12/6/2024)** viết lại module lỗ hổng: thay vì tự tải feed của từng nhà cung cấp, module dùng feed tập trung Wazuh CTI, bắt buộc phải có indexer và đổi tên thành Vulnerability Detection ([Release notes 4.8.0](https://documentation.wazuh.com/4.14/release-notes/release-4-8-0.html)).

Tính đến tháng 11/2026, nhánh ổn định là 4.14.x. Bản 4.14.9 nhóm đang dùng phát hành ngày 14/10/2026. **Bản 4.14.10 ra ngày 5/11/2026 và đã thay thế nó** ([Release notes index 4.x](https://documentation.wazuh.com/current/release-notes/index-4x.html)). Bản 4.14.10 có các bản vá bảo mật, trong đó có lỗi "root-level OS command injection in the rootcheck promiscuous-interface check", cùng các lỗi path traversal và RBAC/`run_as` ([Release notes 4.14.10](https://documentation.wazuh.com/current/release-notes/release-4-14-10.html)). Lỗi rootcheck liên quan trực tiếp tới UC6, vì cấu hình rootcheck của nhóm bật `check_if`. Wazuh 5.0 mới ở mức release candidate. Tài liệu 5.0-rc ghi rõ "upcoming release that is still under development" ([Wazuh 5.0-rc quickstart](https://documentation.wazuh.com/5.0-rc/quickstart.html)). Đây là một lần kiến trúc lại: Filebeat bị thay bằng "Wazuh indexer connector" ([5.0-rc indexer connector](https://documentation.wazuh.com/5.0-rc/user-manual/manager/wazuh-indexer-connector.html)), agent 5.x dùng cổng 1517/TCP và đăng ký bằng token, đường dẫn chuyển sang `/etc/wazuh-manager` ([5.0-rc quickstart](https://documentation.wazuh.com/5.0-rc/quickstart.html)). Một bài hướng dẫn bên thứ ba cho biết không thể nâng cấp tại chỗ từ 4.x lên 5.x ([ComputingForGeeks](https://computingforgeeks.com/install-wazuh-5-ubuntu/)). Vì vậy, chọn 4.14.x cho đồ án là đúng. Báo cáo nên mô tả kiến trúc 4.x và chỉ nhắc 5.0 như hướng phát triển.

## 2. Kiến trúc 4.x gồm một agent đa nền tảng và ba thành phần trung tâm

Tài liệu chính thức mô tả kiến trúc là "a multi-platform agent and three central components: the server, indexer, and dashboard". Agent thu thập dữ liệu và gửi về server. Server phân tích rồi đẩy kết quả sang indexer. Dashboard trực quan hóa dữ liệu. Thiết bị không cài được agent như firewall, switch, router hay access point thì gửi log qua Syslog hoặc được giám sát agentless qua SSH ([Architecture 4.14](https://documentation.wazuh.com/4.14/getting-started/architecture.html)).

| Thành phần | Vai trò | Tiến trình / công nghệ chính |
|---|---|---|
| **Agent** | Chạy trên endpoint (Linux, Windows, macOS, Solaris, AIX…). Thiết kế module: thu log, chạy lệnh, FIM, SCA, inventory hệ thống, phát hiện malware/rootkit, active response, giám sát container và cloud | `wazuh-agentd`, `wazuh-logcollector`, `wazuh-syscheckd` (FIM + rootcheck), `wazuh-modulesd` (SCA, syscollector…), `wazuh-execd` (active response) |
| **Server (manager)** | Đăng ký agent, nhận và giải mã sự kiện, áp decoder và rule, sinh alert, ra lệnh phản ứng, cung cấp API, chạy cluster | `wazuh-authd` (đăng ký, 1515), `wazuh-remoted` (kết nối, 1514), `wazuh-analysisd` (phân tích), `wazuh-integratord`, `wazuh-db`, API (55000), cluster (1516), Filebeat |
| **Indexer** | Lưu trữ và tìm kiếm alert, trạng thái lỗ hổng | OpenSearch tùy biến, 9200 (REST), 9300–9400 (cluster) |
| **Dashboard** | Giao diện web: Threat Hunting, FIM, Vulnerability Detection, IT Hygiene… | OpenSearch Dashboards + plugin Wazuh, 443 |

Nguồn của bảng: phần chức năng server lấy từ [Wazuh server 4.14](https://documentation.wazuh.com/4.14/getting-started/components/wazuh-server.html), các module agent từ [Wazuh agent 4.14](https://documentation.wazuh.com/4.14/getting-started/components/wazuh-agent.html), danh sách daemon từ [Wazuh manager 4.14](https://documentation.wazuh.com/4.14/user-manual/manager/wazuh-manager.html). Cách ghép tên chức năng với tên daemon là suy luận dựa trên danh mục daemon trong tài liệu. Server còn làm giàu alert: gắn mã kỹ thuật MITRE ATT&CK, đối chiếu lỗ hổng qua Wazuh CTI và ánh xạ sang PCI DSS, GDPR, HIPAA, CIS, NIST 800-53 ([Wazuh server 4.14](https://documentation.wazuh.com/4.14/getting-started/components/wazuh-server.html)).

Bảng cổng dưới đây cũng là cơ sở để viết rule pfSense trong mô hình mạng:

| Thành phần | Cổng | Giao thức | Mục đích |
|---|---|---|---|
| Server | 1514 | TCP (mặc định) | Agent gửi sự kiện |
| Server | 1515 | TCP | Đăng ký agent (enrollment) |
| Server | 1516 | TCP | Cluster |
| Server | 514 | UDP/TCP (tắt mặc định) | Nhận syslog |
| Server | 55000 | TCP | RESTful API |
| Indexer | 9200 / 9300–9400 | TCP | REST API / cluster |
| Dashboard | 443 | TCP | Giao diện web |

Nguồn: [Architecture 4.14](https://documentation.wazuh.com/4.14/getting-started/architecture.html).

## 3. Nguyên tắc hoạt động: từ dòng log thô đến alert và hành động tự động

Đây là nội dung trả lời yêu cầu (3) của thầy. Có thể trình bày theo đúng hành trình của một sự kiện.

### 3.1 Agent được tin cậy nhờ khóa riêng, sự kiện được mã hóa AES

Trước khi gửi dữ liệu, agent phải đăng ký (enroll) với manager. Manager sinh một **khóa riêng cho từng agent**. Khóa này vừa dùng để mã hóa kênh truyền, vừa dùng để xác thực danh tính agent. Có bốn cách đăng ký: qua cấu hình agent, qua API, bằng công cụ `agent-auth`, hoặc bằng biến triển khai (cách được khuyến nghị). Có thể tăng cường bằng mật khẩu hoặc xác minh chứng chỉ hai chiều ([Agent enrollment 4.14](https://documentation.wazuh.com/4.14/user-manual/agent/agent-enrollment/index.html)). Khóa nằm trong file `client.keys` (trên Linux là `/var/ossec/etc/client.keys`), mỗi dòng có dạng `<ID> <Tên> <Địa chỉ> <Khóa>`. ID `000` dành riêng cho manager. Xóa dòng tương ứng thì agent bị hủy đăng ký ([Client keys 4.14](https://documentation.wazuh.com/4.14/development/client-keys.html)). Sau khi đăng ký, agent gửi sự kiện qua 1514/TCP, mã hóa **AES với khóa 256 bit** (có thể chọn Blowfish). Server đẩy alert sang indexer qua Filebeat trên kênh TLS ([Architecture 4.14](https://documentation.wazuh.com/4.14/getting-started/architecture.html)). Nhóm đã gặp đúng cơ chế này trong thực tế. Log manager có cảnh báo "Agent key already in use" cho agent 002 và 003, nghĩa là có hơn một kết nối dùng chung một khóa (ghi chú UC2, dòng 120–127).

### 3.2 Phân tích ba pha: pre-decoding, decoding, rule matching

`wazuh-analysisd` xử lý mỗi sự kiện qua ba pha ([Log data analysis 4.14](https://documentation.wazuh.com/4.14/user-manual/capabilities/log-data-collection/log-data-analysis.html)). Ví dụ với dòng log `sshd[25474]: Accepted password for Stephen from 192.168.1.133 port 49765 ssh2`: pha **pre-decoding** tách timestamp, hostname và tên chương trình `sshd`. Pha **decoding** dùng decoder `sshd`, rồi decoder con `sshd-success`, để rút ra user, IP nguồn và cổng. Pha **rule matching** khớp rule 5715 (level 3, "sshd: authentication success"). Mặc định server chỉ sinh alert cho rule có level lớn hơn 2. Rule được viết bằng XML. Mỗi rule có ID từ 1 đến 999999, có level, phải thuộc ít nhất một group và có thể gắn mã MITRE ATT&CK bằng khối `<mitre><id>T1110</id></mitre>`. **Tương quan** là cơ chế giúp Wazuh vượt lên việc đọc từng dòng log riêng lẻ. `frequency` cho biết rule phải khớp bao nhiêu lần, `timeframe` cho biết trong bao nhiêu giây, `if_matched_sid` chỉ rule cha phải đã kích hoạt, và `same_source_ip` buộc các lần khớp phải cùng IP nguồn ([Rules syntax 4.14](https://documentation.wazuh.com/4.14/user-manual/ruleset/ruleset-xml-syntax/rules.html)). UC2 là ví dụ trực tiếp: rule 5712 chỉ kích hoạt khi rule 5710 khớp 8 lần trong 120 giây từ cùng một IP.

Thang level có 16 mức, từ 0 đến 15. Bảng dưới trích một số mức quan trọng ([Rules classification 4.14](https://documentation.wazuh.com/4.14/user-manual/ruleset/rules/rules-classification.html)). Phần cú pháp rule cho phép tới 16, nên khi trình bày nên dùng thang 0–15 và chú thích thêm.

| Level | Ý nghĩa | Ví dụ trong đồ án |
|---|---|---|
| 0 | Bỏ qua | 87100, 108000 (rule nhóm) |
| 3 | Hoạt động thành công / hợp lệ | 651 (chặn IP), 23502 (CVE đã được vá) |
| 5 | Lỗi do người dùng | 5710, 554 |
| 7 | Khớp từ khóa nguy hiểm | 550, 553, 100301 |
| 10 | Nhiều lỗi liên tiếp do người dùng gây ra | **5712** (UC2) |
| 11 | Cảnh báo toàn vẹn (binary bị sửa, rootkit) | **521** (UC6) |
| 12 | Sự kiện mức quan trọng cao | **87105** (UC4), 108001 (UC5) |
| 15 | Tấn công nghiêm trọng | — |

### 3.3 Active response: manager ra lệnh, agent thực thi script

Active response "runs scripts on monitored endpoints when an alert matches a specific rule ID, rule level, or rule group". Phản ứng **stateful** tự hoàn tác sau một khoảng `timeout`. Phản ứng **stateless** chỉ chạy một lần ([Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/)). Cấu hình nằm trong `ossec.conf` của manager và gồm hai khối. Khối `<command>` khai báo script, ví dụ `firewall-drop` với `timeout_allowed=yes`. Khối `<active-response>` gắn command đó với rule, đặt `location` là `local` (chạy trên chính agent sinh sự kiện) và đặt `timeout`. Script nằm ở `/var/ossec/active-response/bin/`. Mọi lần thực thi được ghi vào `/var/ossec/logs/active-responses.log`. File này lại được agent giám sát, nên chính hành động phản ứng cũng sinh ra alert: rule **651** "Host Blocked by firewall-drop" ([Blocking SSH brute-force 4.14](https://documentation.wazuh.com/4.14/user-manual/capabilities/active-response/ar-use-cases/blocking-ssh-brute-force.html)) và **652** khi bỏ chặn ([0015-ossec_rules.xml](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0015-ossec_rules.xml)). Tài liệu cũng cảnh báo rằng rule hoặc phản ứng thiết kế kém có thể làm endpoint dễ bị tấn công hơn ([Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/)).

### 3.4 Cấu hình tập trung theo nhóm agent

Mỗi agent mặc định thuộc nhóm `default`. Manager đẩy mọi file trong `/var/ossec/etc/shared/<nhóm>/` (gồm cả `agent.conf`) xuống các agent của nhóm. Các phần syscheck, rootcheck, localfile, SCA và syscollector đều cấu hình từ xa được ([Centralized configuration 4.14](https://documentation.wazuh.com/4.14/user-manual/reference/centralized-configuration.html)). Hiện nhóm sửa `ossec.conf` trực tiếp trên từng máy. Với doanh nghiệp nhỏ, nên tạo các nhóm như `dmz-linux` và `windows-workstations` để quản lý chính sách một lần trên manager. Đây là điểm cộng nếu đưa vào phần đánh giá.

### 3.5 Mô hình triển khai và kích thước phần cứng

Bản 4.14 hỗ trợ ba mô hình: all-in-one (lab, môi trường nhỏ), single-node và multi-node (cluster, HA) ([Architecture 4.14](https://documentation.wazuh.com/4.14/getting-started/architecture.html)). Có thể cài bằng installation assistant (`wazuh-install.sh -a`), OVA, AMI, Docker, Kubernetes, Ansible, Puppet hoặc từ mã nguồn ([Installation alternatives 4.14](https://documentation.wazuh.com/4.14/deployment-options/index.html)). Bảng cấu hình chính thức cho all-in-one, lưu 90 ngày alert:

| Số agent | CPU | RAM | Lưu trữ |
|---|---|---|---|
| 1–25 | 4 vCPU | 8 GiB | 50 GB |
| 26–50 | 8 vCPU | 8 GiB | 100 GB |
| 51–100 | 8 vCPU | 8 GiB | 200 GB |

Nguồn: [Quickstart](https://documentation.wazuh.com/current/quickstart.html). Hệ điều hành được hỗ trợ cho các thành phần trung tâm gồm Amazon Linux 2/2023, CentOS Stream 10, RHEL 7–10 và **Ubuntu 16.04, 18.04, 20.04, 22.04, 24.04** ([Quickstart](https://documentation.wazuh.com/current/quickstart.html)). Ubuntu 26.04 chỉ xuất hiện trong danh sách khuyến nghị của 5.0-rc ([5.0-rc quickstart](https://documentation.wazuh.com/5.0-rc/quickstart.html)). Điểm này quan trọng cho mục 5.

---

# PHẦN II. MÔ HÌNH MẠNG VÀ TRIỂN KHAI

## 4. Năm vùng mạng trên hai máy vật lý, nối bằng một bridge ZeroTier

Đây là nội dung trả lời yêu cầu (1). Mô hình mô phỏng một doanh nghiệp nhỏ có vùng người dùng (USER), vùng máy chủ công khai (DMZ), vùng quản trị và giám sát an ninh (SOC) và một vùng thử nghiệm đóng vai kẻ tấn công từ bên ngoài (TEST). pfSense đứng giữa các vùng. Do tài nguyên máy cá nhân có hạn, nhóm đặt Wazuh trên máy A (VirtualBox), đặt toàn bộ hạ tầng doanh nghiệp trên máy B (VMware Workstation, 5 VM), rồi nối phân đoạn SOC giữa hai máy bằng một bridge lớp 2 qua ZeroTier. Thông tin sơ đồ lấy từ slide của nhóm.

[Chèn ảnh: sơ đồ mô hình mạng cập nhật, ghi đủ 6 máy, 4 vùng, IP, cổng được phép đi qua pfSense, và đường ZeroTier]

| Máy | Vai trò | Nền tảng | Vùng / địa chỉ | Thông tin đã xác thực trong ghi chú |
|---|---|---|---|---|
| WAZUH01 | Manager + Indexer + Dashboard (all-in-one) | Máy A, VirtualBox, Ubuntu Server | SOC – 192.168.40.10 | Tên manager trong alert là `wazuh01` (ghi chú UC4, dòng 77). Phiên bản và bản Ubuntu chưa được ghi lại |
| ZT-GW01 | Cổng ZeroTier, bridge `br-soc` nối ens37 (phía pfSense) với interface ZeroTier | Máy B, VMware | br-soc 192.168.40.254/24. ens33 (NAT ra Internet) 192.168.164.141/24 | `bridge link`: cả hai interface đều `master br-soc state forwarding` (ghi chú UC1, dòng 231–233) |
| FW01 | pfSense, định tuyến và lọc giữa các vùng | Máy B, VMware | Gateway của USER (192.168.10.1) và DMZ (192.168.30.1) | Chưa có ảnh chụp cấu hình |
| WEB01 | Máy chủ web Apache, agent ID 002 | Máy B, VMware | DMZ – 192.168.30.10 | Ubuntu 26.04.1 LTS, kernel 7.0.0-38, agent v4.14.9 (ghi chú UC3, dòng 496) |
| WIN01 | Máy trạm người dùng, agent ID 003 | Máy B, VMware, Windows | USER – 192.168.10.100 | Kết nối thành công tới 1514 và 1515, service `WazuhSvc` Running (ghi chú UC3, dòng 47–73) |
| KALI01 | Máy tấn công mô phỏng | Máy B, VMware | TEST – 192.168.50.10 | Là IP nguồn trong alert UC2 |

Chính sách tường lửa tuân theo nguyên tắc đặc quyền tối thiểu. Endpoint chỉ được mở đúng hai cổng của Wazuh tới manager, còn kẻ tấn công chỉ được mở một "lỗ" có chủ đích phục vụ demo:

| Rule pfSense | Nguồn → Đích | Cổng | Mục đích | Bằng chứng gián tiếp |
|---|---|---|---|---|
| DMZ → SOC | 192.168.30.10 → 192.168.40.10 | TCP 1514, 1515 | Agent WEB01 | `nc` tới 1514 báo succeeded (ghi chú UC1, dòng 214–215) |
| USER → SOC | 192.168.10.100 → 192.168.40.10 | TCP 1514, 1515 | Agent WIN01 | `TcpTestSucceeded : True` (ghi chú UC3, dòng 59, 65) |
| LAB-SSH-DEMO | 192.168.50.10 → 192.168.30.10 | TCP 22 | Kịch bản UC2. Đặt **trên** rule chặn TEST → DMZ | WEB01 nhận được lưu lượng SSH từ .50.10 (ghi chú UC4, dòng 77) |

[Chèn ảnh: Firewall > Rules của từng interface pfSense (USER, DMZ, TEST, SOC)]

Thiết kế này có lý do rõ ràng và nên viết vào báo cáo. DMZ là vùng dễ bị tấn công nhất, nên WEB01 là nơi chạy phần lớn use case. WIN01 đại diện cho máy trạm nhân viên. Vùng SOC được cô lập: dashboard (443) và API (55000) không mở ra các vùng khác. Cũng nên nói thẳng về điểm yếu của mô hình. Đường ZeroTier là một sản phẩm phụ của việc dựng lab trên hai máy, không phải thiết kế thực tế. Ghi chú cho thấy mạng đứt ít nhất ba lần: ngày 03/11, 05/11 và 07/11 (ghi chú UC1, dòng 67–109; UC3, dòng 93–121, 612–683). Lần đầu là do interface ZeroTier được cấp IP managed `10.99.240.154/24` song song với IP của br-soc. Nhóm sửa bằng cách tắt `allowManaged` (ghi chú UC1, dòng 173–215). Ở doanh nghiệp thật, SOC sẽ nằm cùng site hoặc được nối bằng VPN site-to-site có giám sát.

## 5. Triển khai Wazuh all-in-one: chạy được, nhưng ba lỗi môi trường cần xử lý

Đây là nội dung trả lời yêu cầu (2). Slide ghi "Đã triển khai Wazuh all-in-one / Đã kết nối Agent / Đã kết nối hai phía qua ZeroTier". Ghi chú xác nhận WEB01 và WIN01 từng ở trạng thái online. Ví dụ, WEB01 có log `(4102): Connected to the server` lúc 14:22:56 ngày 07/11 (ghi chú UC3, dòng 758–759). WEB01 cũng thu được log Apache, journald, dpkg và `active-responses.log` (ghi chú UC3, dòng 532–549). Tuy nhiên, **ghi chú không có lệnh cài đặt nào kèm output**. Vì vậy chưa xác định được nhóm cài bằng installation assistant hay cài thủ công, và chưa có phiên bản của manager, indexer và dashboard. Phần triển khai trong báo cáo nên trình bày như sau, rồi điền bằng chứng thật:

```bash
# Trên WAZUH01 – cài all-in-one theo tài liệu chính thức 4.14
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Lệnh trên lấy từ [Quickstart](https://documentation.wazuh.com/current/quickstart.html). Installation assistant in ra URL dashboard và thông tin đăng nhập admin. Toàn bộ mật khẩu được lưu trong `wazuh-passwords.txt` bên trong `wazuh-install-files.tar`. Tài liệu khuyên tắt repo Wazuh sau khi cài để tránh vô tình nâng cấp. Tuyệt đối không dán file mật khẩu này vào báo cáo.

[Chèn output: kết quả cài đặt hoặc trang About trên Dashboard, thể hiện phiên bản manager/indexer/dashboard]
[Chèn output: danh sách agent trên manager (Agents trên Dashboard hoặc `agent_control -l`), thể hiện 002 WEB01 và 003 WIN01 đều Active]

Có ba vấn đề môi trường cần ghi rõ trong báo cáo.

**Thứ nhất, Ubuntu 26.04 không nằm trong danh sách hỗ trợ.** WEB01 chạy Ubuntu 26.04.1 LTS. Danh sách hệ điều hành chính thức cho thành phần trung tâm của 4.14 chỉ đến Ubuntu 24.04 ([Quickstart](https://documentation.wazuh.com/current/quickstart.html)). Ma trận tương thích của vulnerability detection cũng chỉ liệt kê Ubuntu 14.04–24.04 LTS ([VD how it works](https://documentation.wazuh.com/4.14/user-manual/capabilities/vulnerability-detection/how-it-works.html)). Đã có một dấu hiệu thực tế: SCA trên WEB01 bỏ qua policy CIS Ubuntu 22.04 với lý do "Check Ubuntu version" (ghi chú UC1, dòng 64). Nhóm cần kiểm tra WAZUH01 có chạy Ubuntu 26.04 không. Nếu có, phải ghi nhận đây là cấu hình ngoài danh sách hỗ trợ.

**Thứ hai, lỗi trùng khóa agent.** Log manager liên tục báo `Agent key already in use` cho agent 003 và cả 002 (ghi chú UC2, dòng 120–127). Không có bằng chứng lỗi này đã được sửa. Theo kinh nghiệm chung (chưa kiểm chứng trên lab của nhóm), lỗi này thường xuất hiện khi hai máy hoặc hai phiên agent dùng cùng một khóa, ví dụ VM được nhân bản hoặc agent được đăng ký lại mà bản ghi cũ chưa bị xóa. Cách xử lý: xóa agent trùng trên manager, đăng ký lại, rồi xác nhận mỗi ID chỉ có một kết nối.

**Thứ ba, phiên bản và đồng bộ thời gian.** Agent đang ở 4.14.9 trong khi 4.14.10 đã có bản vá bảo mật. Nên nâng manager trước, agent sau. Ngoài ra, log trên WEB01 và timestamp alert trên manager lệch khoảng 30 giây (ghi chú UC2/UC4). Nên bật NTP trên mọi máy để timeline của các alert khớp nhau khi trình bày.

---

# PHẦN III. THỬ NGHIỆM SÁU USE CASE

Đây là nội dung trả lời yêu cầu (4). Bảng tổng quan dưới đây phản ánh đúng những gì ghi chú lab chứng minh được tính đến ngày 07/11/2026:

| UC | Tính năng | Endpoint | Trạng thái | Bằng chứng hiện có |
|---|---|---|---|---|
| UC1 | File Integrity Monitoring | WEB01 (WIN01 dự kiến) | **Chỉ có các bước** | Cấu hình đã nạp (log 6003/6016/6012). Chưa có alert 550/553/554 |
| UC2 | SSH brute-force + active response | KALI01 → WEB01 | **Đã có bằng chứng** | Rule 5712 level 10. `firewall-drop` chặn lúc 14:13:31 và gỡ lúc 14:16:32 |
| UC3 | Vulnerability detection | WEB01 | **Đang gỡ lỗi** | Syscollector 10 phút/lần, `local.db` 408K. Chưa có CVE nào |
| UC4 | VirusTotal + xóa malware | WEB01 | **Đã có bằng chứng** | Rule 87105 level 12, 66/68 engine, "Successfully removed threat" |
| UC5 | YARA | WEB01 | **Chỉ có các bước** (phần chuẩn bị trên agent đã có output) | YARA 4.5.5, thư mục đã được FIM giám sát. Chưa có alert 100301/108001 |
| UC6 | Rootcheck – tiến trình ẩn | WEB01 | **Chỉ có các bước** | Không có output nào |

## 6. UC1 – FIM: cấu hình đã nạp, nhưng chưa có alert nào

**Mục tiêu.** Phát hiện việc tạo, sửa, xóa file website và chứng minh Wazuh báo "đúng file và đúng loại thay đổi" (tiêu chí ghi trên slide).

**Kịch bản.** Làm theo PoC chính thức: chờ log `(6012): Real-time file integrity monitoring started.`, sau đó tạo file, chờ 5 giây, sửa file, chờ 5 giây, xóa file. Lọc kết quả bằng `rule.id: is one of 550,553,554` ([PoC FIM](https://documentation.wazuh.com/4.14/proof-of-concept-guide/poc-file-integrity-monitoring.html)). Trên WIN01, PoC giám sát `C:\Users\<USER>\Desktop` với cùng thuộc tính.

**Cấu hình chính.** Cấu hình dưới đây đã được xác nhận bằng `grep` trên WEB01 (ghi chú UC1, dòng 347–355):

```xml
<syscheck>
  <frequency>43200</frequency>
  <directories check_all="yes" report_changes="yes" realtime="yes">/opt/wazuh-lab/fim</directories>
</syscheck>
```

**Cơ chế.** `wazuh-syscheckd` lập baseline gồm hash và thuộc tính của file trong một SQLite cục bộ (`/var/ossec/queue/fim/db`). Manager giữ một bản sao cho từng agent qua `wazuh-db`, và hai bên được đồng bộ ([FIM how it works](https://documentation.wazuh.com/4.14/user-manual/capabilities/file-integrity/how-it-works.html)). Thay đổi được phát hiện theo ba cách. Quét định kỳ chạy 12 giờ một lần theo mặc định. `realtime` dùng inotify, **chỉ áp dụng cho thư mục**. `whodata` dùng auditd hoặc eBPF trên Linux, SACL trên Windows, và cho biết thêm *ai* đã thay đổi và bằng tiến trình nào ([FIM basic settings](https://github.com/wazuh/wazuh-documentation/blob/4.14/source/user-manual/capabilities/file-integrity/basic-settings.rst); [FIM advanced settings](https://github.com/wazuh/wazuh-documentation/blob/4.14/source/user-manual/capabilities/file-integrity/advanced-settings.rst)). `report_changes` sinh diff nội dung, nhưng chỉ cho file văn bản. Các rule tương ứng ([0015-ossec_rules.xml](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0015-ossec_rules.xml)):

| Rule | Level | Mô tả | MITRE |
|---|---|---|---|
| 550 | 7 | Integrity checksum changed (file bị sửa) | T1565.001 |
| 553 | 7 | File deleted | T1070.004, T1485 |
| 554 | 5 | File added to the system | — |

**Kết quả thực tế của nhóm.** Agent đã nạp cấu hình. Log có `(6003): Monitoring path: '/opt/wazuh-lab/fim' … report_changes | realtime` và `(6016): Directory set for real time monitoring` (ghi chú UC3, dòng 504, 525), cùng dòng `(6012)` (ghi chú UC1, dòng 323). Lần thử đầu thất bại vì thư mục chưa tồn tại (`No such file or directory`), sau đó nhóm đã tạo thư mục (ghi chú UC1, dòng 270–273). Các lần thử sau chỉ có lệnh, **không có dòng alert nào**. Phía WIN01 không có output.

[Chèn ảnh: module File Integrity Monitoring, lọc agent WEB01, thấy đủ 554 → 550 → 553 cho cùng một file, mở chi tiết alert 550 thấy `syscheck.path` và `syscheck.diff`]
[Chèn ảnh: tương tự cho WIN01 – Desktop]

**Nhận xét.** Lần thử thất bại rất có thể vì thư mục được tạo *sau* khi agent khởi động. Theo tài liệu, thư mục tạo sau lần quét đầu chỉ được thêm vào ở lần quét định kỳ tiếp theo ([FIM basic settings](https://github.com/wazuh/wazuh-documentation/blob/4.14/source/user-manual/capabilities/file-integrity/basic-settings.rst)). Log ngày 07/11 cho thấy thư mục đã được đặt chế độ realtime, nên chạy lại kịch bản bây giờ nhiều khả năng sẽ ra alert. Cần nói rõ trong báo cáo rằng nhóm dùng `realtime` chứ không dùng `whodata`. Văn bản PoC 4.14 nhắc "enable who-data", nhưng đoạn XML mẫu của chính PoC lại dùng `realtime`. Với `realtime`, alert không có trường người dùng/tiến trình. Nếu muốn trả lời câu "ai sửa file", nên thử thêm `whodata="yes"`. Về Windows Registry: tài liệu chỉ mô tả quét định kỳ, nên nếu demo registry phải giảm `frequency` ([Windows registry monitoring](https://github.com/wazuh/wazuh-documentation/blob/4.14/source/user-manual/capabilities/file-integrity/windows-registry-monitoring.rst)). Cuối cùng, FIM là kiểm soát **phát hiện**, không ngăn chặn được việc sửa file.

## 7. UC2 – SSH brute-force: tương quan 8 lần thất bại, chặn IP đúng 180 giây

**Mục tiêu.** Phát hiện tấn công dò mật khẩu SSH từ vùng TEST vào máy chủ DMZ và tự động chặn IP tấn công.

**Kịch bản.** KALI01 (192.168.50.10) dùng Hydra với tài khoản **không tồn tại** `badguy` và danh sách 10 mật khẩu giả, tấn công WEB01:22 qua rule `LAB-SSH-DEMO`. Để Hydra có thể thử mật khẩu, WEB01 bật xác thực bằng mật khẩu qua một file drop-in trong `sshd_config.d` (ghi chú UC2, dòng 1–39). Kịch bản này bám sát PoC chính thức, vốn cũng dùng Hydra, user `badguy` và 10 mật khẩu ngẫu nhiên ([PoC brute force](https://documentation.wazuh.com/4.14/proof-of-concept-guide/detect-brute-force-attack.html)).

**Cấu hình chính.** Tài liệu tham chiếu cấu hình trên manager như sau ([Blocking SSH brute-force 4.14](https://documentation.wazuh.com/4.14/user-manual/capabilities/active-response/ar-use-cases/blocking-ssh-brute-force.html)):

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763</rules_id>   <!-- xem nhận xét: lab của nhóm thực tế kích hoạt bằng 5712 -->
  <timeout>180</timeout>
</active-response>
```

[Chèn output: khối `<command>`/`<active-response>` THẬT trong ossec.conf của WAZUH01. Ghi chú hiện không có đoạn XML này]

**Cơ chế.** Đây là chuỗi tương quan trên manager. Mỗi lần đăng nhập bằng user không tồn tại sinh rule 5710 (level 5). Khi 5710 khớp **8 lần trong 120 giây từ cùng IP**, rule 5712 (level 10, MITRE T1110) kích hoạt. Rule 5712 có `ignore=60`, tức không kích hoạt lại trong 60 giây. Nếu user có tồn tại, chuỗi tương ứng là 5760 → 5763 ([0095-sshd_rules.xml](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0095-sshd_rules.xml)). Lỗi PAM đi theo chuỗi 5503 → 5551 ([0085-pam_rules.xml](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0085-pam_rules.xml)). Khi alert khớp, manager gửi lệnh qua kênh mã hóa xuống agent. `wazuh-execd` chạy `firewall-drop` để thêm rule DROP cho `srcip` vào iptables. Hết `timeout`, script được gọi lại với lệnh `delete` để gỡ chặn.

**Kết quả thực tế của nhóm (đã có bằng chứng).** Trích `active-responses.log` trên WEB01 (ghi chú UC4, dòng 76–81):

```text
2026/11/05 14:13:31 active-response/bin/firewall-drop: {..."command":"check_keys","parameters":{"keys":["192.168.50.10"]}}
... "command":"continue" ... "rule":{"level":10,"description":"sshd: brute force trying to get access to the system. Non existent user.","id":"5712","mitre":{"id":["T1110"]...},"frequency":8,"firedtimes":1}
    "agent":{"id":"002","name":"WEB01"},"data":{"srcip":"192.168.50.10","srcport":"35328","srcuser":"badguy"},"location":"journald"
2026/11/05 14:16:32 active-response/bin/firewall-drop: ... "command":"delete"
```

Khoảng cách giữa lúc chặn và lúc gỡ là **181 giây**, khớp với `timeout` 180 giây. Rule 5710 (level 5, srcip 192.168.50.10, user `badguy`) cũng được ghi nhận (ghi chú UC2, dòng 109–118).

[Chèn ảnh: Threat Hunting lọc `agent.name:WEB01 AND rule.id:(5710 OR 5712 OR 651 OR 652)` trong khoảng 14:10–14:20 ngày 05/11]
[Chèn output: `iptables -L INPUT -n` trên WEB01 trong 3 phút bị chặn, thấy DROP 192.168.50.10. Kèm `ping`/`nc` từ KALI01 bị timeout]

**Nhận xét.** Có một sắc thái kỹ thuật nên trình bày như một phát hiện của nhóm. Trang hướng dẫn active response gắn `firewall-drop` vào **rule 5763** và dùng user *có thật*. Còn PoC phát hiện dùng user *không tồn tại* `badguy`, và PoC này không cấu hình chặn. Nếu ghép nguyên hai tài liệu (user `badguy` với `rules_id 5763`), lệnh chặn sẽ không bao giờ chạy, vì `badguy` sinh chuỗi 5710 → 5712 chứ không sinh 5760 → 5763. Log của nhóm cho thấy alert kích hoạt `firewall-drop` là **5712**. Như vậy cấu hình thật của nhóm (gắn theo rule ID hoặc theo level) đã bao trùm 5712. Cần dán XML thật để xác nhận, và viết đúng rule ID vào slide. Ngoài ra cần lưu ý thêm ba điểm. Chặn chỉ tạm thời trong 180 giây, không phải biện pháp khắc phục triệt để. Phải loại các alert có srcip `192.168.40.100` (máy thật B SSH vào WEB01) khỏi bằng chứng (ghi chú UC2, dòng 69–105). Lúc 14:13:31, WEB01 còn ghi cảnh báo `Active response command not present: 'active-response/bin/restart-ossec.sh'` (ghi chú UC3, dòng 585–589). Điều này gợi ý trong `ossec.conf` của manager có một khối active response thừa cần dọn.

## 8. UC3 – Vulnerability detection: kẹt vì hệ điều hành chưa có trong feed

**Mục tiêu.** Đối chiếu inventory gói phần mềm với CVE, rồi cập nhật bản vá và chứng minh trạng thái CVE thay đổi. Tiêu chí trên slide là "Inventory và trạng thái CVE phù hợp".

**Kịch bản chuẩn.** PoC chính thức giảm `interval` của Syscollector từ 1h xuống 10m, cài một gói có lỗ hổng, chờ khoảng 10 phút để thấy CVE ở trạng thái `Active`, gỡ hoặc cập nhật gói, rồi chờ tiếp để thấy `Solved`. Lọc bằng `data.vulnerability.package.name: <gói> AND data.vulnerability.status:Active` (rồi `:Solved`) ([PoC vulnerability detection](https://documentation.wazuh.com/4.14/proof-of-concept-guide/poc-vulnerability-detection.html)).

**Cấu hình chính.** Trên agent (đã có bằng chứng, ghi chú UC3, dòng 416–431):

```xml
<wodle name="syscollector">
  <interval>10m</interval>
  <packages>yes</packages>
  <os>yes</os>
  <hardware>yes</hardware>
</wodle>
```

Trên manager, module bật mặc định với `<vulnerability-detection><enabled>yes</enabled><index-status>yes</index-status><feed-update-interval>60m</feed-update-interval></vulnerability-detection>` và cần kết nối `<indexer>` hợp lệ ([PoC vulnerability detection](https://documentation.wazuh.com/4.14/proof-of-concept-guide/poc-vulnerability-detection.html)).

[Chèn output: khối `<vulnerability-detection>` và `<indexer>` trong ossec.conf của WAZUH01]

**Cơ chế.** Agent thu inventory bằng Syscollector. Module Vulnerability Detection trên manager đối chiếu inventory với Wazuh CTI. CTI tổng hợp dữ liệu từ các hãng hệ điều hành (Canonical, Debian, Red Hat…) và từ NVD, OSV, CISA, MSU, rồi chuẩn hóa về CVE JSON v5 ([VD how it works](https://documentation.wazuh.com/4.14/user-manual/capabilities/vulnerability-detection/how-it-works.html)). Trạng thái hiện tại được ghi vào index `wazuh-states-vulnerabilities-*` và hiển thị ở tab Inventory. Mỗi lần CVE chuyển trạng thái thì sinh alert ở tab Events. Một số điều kiện quan trọng: **lần quét đầu tiên không sinh alert cho OS**. Alert về gói chỉ sinh khi thay đổi được ghi nhận trong một lần quét định kỳ, nên thay đổi xảy ra lúc agent đang dừng sẽ không có alert. Cập nhật feed cũng không sinh alert ([VD how it works](https://documentation.wazuh.com/4.14/user-manual/capabilities/vulnerability-detection/how-it-works.html)). Rule tương ứng ([0520-vulnerability-detector_rules.xml](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0520-vulnerability-detector_rules.xml)):

| Rule | Level | Điều kiện |
|---|---|---|
| 23502 | 3 | CVE đã được giải quyết (Solved) |
| 23503 / 23504 / 23505 / 23506 | 5 / 7 / 10 / 13 | Active, mức Low / Medium / High / Critical |
| 23507 | 3 | Vulnerabilities cleared |

**Kết quả thực tế của nhóm (đang gỡ lỗi).** Syscollector trên WEB01 đã chạy. Ngày 05/11 có cặp log "Starting evaluation"/"Evaluation finished" lúc 16:02 (ghi chú UC3, dòng 455–456), ngày 07/11 lúc 14:25:49 (dòng 818). File `local.db` dung lượng 408K (dòng 846–848). Nhóm tìm dòng "Sending inventory" ở phía agent nhưng không thấy, và phần lớn thời gian còn lại dành cho việc xử lý mất kết nối (dòng 371–398, 751–757). Ghi chú dừng ở lệnh restart agent, không có output tiếp theo (dòng 870–871). **Chưa có CVE nào, chưa kiểm tra phía manager.**

**Nhận xét.** Có hai nguyên nhân khả dĩ, cả hai đều là suy luận cần nhóm kiểm chứng. Thứ nhất, tìm dòng "Sending inventory" ở agent có thể là hướng chẩn đoán sai, vì bản 4.14 có thể không ghi dòng này ở mức INFO. Cách đúng là kiểm tra ở manager: mở Dashboard > IT Hygiene/Inventory và xem WEB01 đã có danh sách gói chưa. Thứ hai, và quan trọng hơn, **Ubuntu 26.04 không có trong ma trận tương thích** (Ubuntu 14.04–24.04 LTS). Kể cả khi inventory đã về manager, WEB01 vẫn có thể không có CVE nào. Có hai hướng xử lý: (a) demo trên WIN01, vì Windows được đối chiếu qua NVD/MSU và Syscollector có tùy chọn `hotfixes`; hoặc (b) thêm một VM Ubuntu 22.04/24.04 vào DMZ. Nếu WEB01 vẫn không ra CVE, nên trình bày điều đó như một **kết quả âm tính có giải thích**, kèm trích dẫn ma trận tương thích. Đây là phát hiện có giá trị về giới hạn của công cụ. Ngoài ra, bản 4.14.10 đổi cách quét lại toàn bộ chỉ áp dụng cho agent đang kết nối ([Release notes 4.14.10](https://documentation.wazuh.com/current/release-notes/release-4-14-10.html)). Vì vậy agent phải giữ online ổn định trong suốt thời gian demo.

[Chèn ảnh: Vulnerability Detection > Inventory của endpoint được chọn]
[Chèn ảnh: Events trước và sau khi cập nhật gói, thấy cùng một CVE chuyển từ Active sang Solved (rule 23502)]

## 9. UC4 – VirusTotal: phát hiện và xóa EICAR trong vài giây

**Mục tiêu.** Đưa mẫu kiểm thử vào thư mục lab, chứng minh Wazuh nhận diện được và file bị loại bỏ.

**Kịch bản.** Tải mẫu EICAR (file kiểm thử chuẩn, vô hại) bằng `curl` từ `secure.eicar.org` vào `/opt/wazuh-lab/virustotal` trên WEB01, làm hai lần với `eicar.com` và `eicar2.com`.

**Cấu hình chính.** Trên agent, nhóm thêm `<directories realtime="yes">/opt/wazuh-lab/virustotal</directories>`, cài `jq` và đặt script `remove-threat.sh` với quyền `root:wazuh 750` (ghi chú UC4, dòng 5–10). Trên manager, theo PoC: rule custom 100200 (if_sid 550) và 100201 (if_sid 554) giới hạn phạm vi theo thư mục; khối `<integration>` tên `virustotal` với `<rule_id>100200,100201</rule_id>`; command `remove-threat` stateless gắn với `rules_id 87105`; và rule 100092/100093 đọc kết quả của active response ([PoC VirusTotal](https://documentation.wazuh.com/4.14/proof-of-concept-guide/detect-remove-malware-virustotal.html)).

[Chèn output: `local_rules.xml` (100200/100201/100092/100093) và khối `<integration>` THẬT. Thay API key bằng `[REDACTED]`]

**Cơ chế.** FIM realtime phát hiện file mới (554), rule 100201 kích hoạt. `wazuh-integratord` gọi script `virustotal.py`, script này **chỉ gửi mã MD5** (`syscheck.md5_after`) tới VirusTotal, không tải file lên. Bản 4.14.10 gọi endpoint **API v2** `https://www.virustotal.com/vtapi/v2/file/report`, chứ không phải v3 ([virustotal.py v4.14.10](https://github.com/wazuh/wazuh/blob/v4.14.10/integrations/virustotal.py)). Khi có engine đánh dấu độc hại, rule 87105 (level 12, MITRE T1203) kích hoạt. Các rule khác trong họ này: 87101 khi vượt hạn mức, 87103 khi hash không có trong cơ sở dữ liệu, 87104 khi không có engine nào phát hiện ([0490-virustotal_rules.xml](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0490-virustotal_rules.xml)). Sau 87105, manager ra lệnh cho agent chạy `remove-threat.sh`. Script đọc đường dẫn file từ alert và xóa file. Chuỗi alert kỳ vọng là 554/100201 → 87105 → 553 → 100092 ([PoC VirusTotal](https://documentation.wazuh.com/4.14/proof-of-concept-guide/detect-remove-malware-virustotal.html)). **API công khai giới hạn 4 request/phút và 500 request/ngày**, đồng thời không được dùng trong sản phẩm hay quy trình kinh doanh thương mại ([Wazuh VT integration](https://documentation.wazuh.com/4.14/user-manual/capabilities/malware-detection/virus-total-integration.html); [VirusTotal Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)).

**Kết quả thực tế của nhóm (đã có bằng chứng).** Lần 1: `2026/11/07 15:02:08 Successfully removed threat: /opt/wazuh-lab/virustotal/eicar.com` (ghi chú UC4, dòng 72, 83). Lần 2 sau khi viết lại script (ghi chú UC4, dòng 165–166):

```text
2026/11/07 15:07:13 active-response/bin/remove-threat.sh: {..."command":"add"...
 "rule":{"level":12,"description":"VirusTotal: Alert - /opt/wazuh-lab/virustotal/eicar2.com - 66 engines detected this file","id":"87105"...},
 "agent":{"id":"002","name":"WEB01"} ... "positives":"66","total":"68" ...} Successfully removed threat
```

[Chèn ảnh: Threat Hunting lọc `rule.id: is one of 554,100201,87105,553,100092`, thấy đủ chuỗi cho eicar2.com]
[Chèn output: `ls -la /opt/wazuh-lab/virustotal` sau khi xóa]

**Nhận xét.** Đây là use case thuyết phục nhất của nhóm, nhưng khi trình bày cần lưu ý bốn điều. Một, đây là **phát hiện và phản ứng sau khi file đã ghi xuống đĩa**, không phải ngăn chặn. Trong khoảng thời gian từ lúc FIM phát hiện, qua lượt gọi VirusTotal, đến lúc active response chạy, file vẫn có thể bị thực thi. Hai, chỉ dựa trên hash nên malware mới hoặc đã đóng gói lại sẽ trả về 87103 và không bị xóa. Ba, hạn mức 4 request/phút khiến không thể giám sát cả hệ thống file rộng; đó là lý do PoC chỉ giới hạn ở một thư mục. Bốn, bản `remove-threat.sh` đầu tiên bị lỗi cú pháp khi dán (ghi chú UC4, dòng 88–129). Nên ghi lại bài học này cùng bước kiểm tra cú pháp script trước khi triển khai.

## 10. UC5 – YARA: chuỗi xử lý đã dựng xong, còn thiếu phép thử

**Mục tiêu.** Dựng pipeline đầy đủ: file xuất hiện → FIM → active response chạy YARA → kết quả về manager → alert.

**Kịch bản.** Nhóm chọn cách an toàn: tự viết một rule YARA `WAZUH_YARA_TEST` khớp một chuỗi đánh dấu, thay vì dùng mẫu mã độc thật như PoC. Phép thử gồm một file chứa chuỗi đánh dấu và một file đối chứng lành tính. File đối chứng phải sinh alert FIM nhưng không sinh alert YARA, để chứng minh không có dương tính giả (ghi chú UC5, dòng 120–216). Nhóm cũng dự định chạy YARA thủ công trước khi thử qua Wazuh.

**Cấu hình chính.** Phía agent đã có bằng chứng: YARA 4.5.5, file rules 1.1M, `yara.sh` có quyền `root:wazuh 0750`, và FIM realtime trên `/opt/wazuh-lab/yara/malware` (log 6003/6016 lúc 15:22:32 ngày 07/11) (ghi chú UC5, dòng 11–39, 59–64, 97–100). Phía manager, theo PoC: decoder `yara_decoder`/`yara_decoder1`, rule 100300/100301 (level 7) kích hoạt command `yara_linux` (với `extra_args` trỏ tới binary YARA và file rules), rule 108000 (level 0) và **108001 (level 12)** ([PoC YARA](https://documentation.wazuh.com/4.14/proof-of-concept-guide/detect-malware-yara-integration.html)). Phiên bản YARA 4.5.5 của nhóm khớp với biến phiên bản trong tài liệu 4.14 ([replacements.py 4.14](https://github.com/wazuh/wazuh-documentation/blob/4.14/source/_variables/replacements.py)).

[Chèn output: `local_decoder.xml`, rule 100301/108001 và khối `<command>`/`<active-response>` yara_linux trên WAZUH01]

**Cơ chế.** YARA không phải module có sẵn của Wazuh, mà được ghép vào qua active response. `yara.sh` lấy đường dẫn file từ alert FIM, chờ đến khi kích thước file ngừng thay đổi, chạy `yara -w -r <rules> <file>`, rồi ghi mỗi kết quả khớp vào `active-responses.log` dưới dạng `wazuh-yara: INFO - Scan result: <rule> <file>`. Agent gửi dòng log đó về manager, decoder tách các trường `yara_rule` và `yara_scanned_file`, và rule 108001 sinh alert ([PoC YARA](https://documentation.wazuh.com/4.14/proof-of-concept-guide/detect-malware-yara-integration.html); [FIM-YARA](https://github.com/wazuh/wazuh-documentation/blob/4.14/source/user-manual/capabilities/malware-detection/fim-yara.rst)). **Script trong tài liệu 4.14 không có lệnh xóa file. YARA trong PoC chỉ phát hiện.** Lệnh `del` duy nhất trong `yara.bat` trên Windows chỉ xóa file tạm của chính script. Lưu ý thêm: PoC "Leveraging LLMs for alert enrichment" (một PoC khác) mô tả biến thể có xóa file tùy chọn ([LLM PoC](https://documentation.wazuh.com/current/proof-of-concept-guide/leveraging-llms-for-alert-enrichment.md)). Nếu nhóm muốn có bước xóa, đó là phần mở rộng tự viết và phải nói rõ như vậy.

**Kết quả thực tế của nhóm.** Phần chuẩn bị trên agent đã được chứng minh. Phép thử đầu-cuối và phép đối chứng **chưa có output**. Mọi dòng alert 100301/108001 trong ghi chú đều là kết quả "kỳ vọng" (ghi chú UC5, dòng 179–216).

[Chèn output: kết quả chạy YARA thủ công trên file đánh dấu]
[Chèn ảnh: Threat Hunting lọc `rule.groups:yara`, thấy 100301 rồi 108001 cho file đánh dấu, và chỉ có 100301 cho file đối chứng]

**Nhận xét.** So với VirusTotal, YARA quét **cục bộ**: không bị giới hạn hạn mức API, nội dung file không rời khỏi máy, và có thể bắt được biến thể mới nếu rule viết theo cấu trúc. Đổi lại, chất lượng phát hiện phụ thuộc hoàn toàn vào bộ rule. Ghi chú không cho biết bộ rule 1.1M lấy từ đâu; PoC dùng bản demo công khai của Valhalla (Nextron Systems). Nên ghi rõ nguồn này. Cũng cần xác nhận lại nhãn "máy ADMIN (máy B)" ở ghi chú UC5, dòng 195, vì ở mọi chỗ khác máy B trong UC5 là WEB01.

## 11. UC6 – Rootcheck phát hiện tiến trình ẩn: mới có runbook

**Mục tiêu.** Chứng minh module rootcheck của agent phát hiện được một tiến trình bị rootkit cấp kernel che giấu.

**Kịch bản (mức khái quát).** Theo PoC chính thức "Detecting hidden processes", nhóm dự định dùng một rootkit kiểm thử dạng kernel module, chính là loại mà PoC sử dụng, để ẩn một tiến trình hệ thống trên một **VM cô lập đã chụp snapshot**. Sau đó kiểm tra xem rootcheck có báo động hay không, rồi khôi phục snapshot ([PoC hidden processes](https://documentation.wazuh.com/4.14/proof-of-concept-guide/poc-detect-hidden-process.html)). Báo cáo không trình bày các bước dựng hay nạp rootkit. Chỉ cần dẫn chiếu PoC và mô tả quy trình an toàn: snapshot trước khi thử, mạng cô lập, khôi phục sau khi thử.

**Cấu hình chính** (trên agent, theo PoC và runbook của nhóm, ghi chú UC6, dòng 27–62):

```xml
<rootcheck>
  <disabled>no</disabled>
  <check_files>yes</check_files>
  <check_trojans>yes</check_trojans>
  <check_dev>yes</check_dev>
  <check_sys>yes</check_sys>
  <check_pids>yes</check_pids>
  <check_ports>yes</check_ports>
  <check_if>yes</check_if>
  <frequency>120</frequency>   <!-- mặc định 12 giờ; giảm để demo -->
  <skip_nfs>yes</skip_nfs>
</rootcheck>
```

**Cơ chế.** Khi bật `check_pids`, rootcheck duyệt mọi PID đến giá trị tối đa của hệ thống. Với mỗi PID, nó so sánh kết quả của `kill(pid,0)`, `getsid()`, `getpgid()`, các thao tác `stat`/`read`/`opendir` trên `/proc/<pid>` và `ps -p`. Một PID vẫn phản hồi syscall nhưng không xuất hiện khi liệt kê `/proc` hay trong `ps` sẽ bị báo "Process 'N' hidden from /proc. Possible kernel level rootkit." Để tránh báo nhầm, rootcheck kiểm tra lại các PID vừa kết thúc, và nếu có hơn 15 PID lỗi thì báo "Excessive number of hidden processes" ([check_rc_pids.c v4.14.10](https://github.com/wazuh/wazuh/blob/v4.14.10/src/rootcheck/check_rc_pids.c)). Rootkit kiểu PoC lọc kết quả liệt kê thư mục `/proc`, nhưng không chặn các syscall trực tiếp. Chính sự chênh lệch đó làm lộ tiến trình. Trên manager, thông điệp này khớp **rule 521** (level 11, "Possible kernel level rootkit", MITRE **T1014**), với rule cha 510 (level 7, "Host-based anomaly detection event (rootcheck)") ([0015-ossec_rules.xml](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0015-ossec_rules.xml); [Rootkits behavior detection](https://documentation.wazuh.com/4.14/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html)). Lưu ý: PoC mô tả cơ chế là "`setsid()`, `getpid()`, và `kill()`", nhưng mã nguồn thực tế dùng các lời gọi đã liệt kê ở trên. Báo cáo nên theo mã nguồn.

**Kết quả thực tế của nhóm.** **Không có output nào**: không có pre-flight, không có xác nhận cấu hình, không có alert. Ghi chú hai lần nhắc tới một mục "Cảnh báo cuối" nhưng mục này không có trong file (ghi chú UC6, dòng 20, 86).

[Chèn ảnh: Threat Hunting lọc `rule.groups:rootcheck AND agent.name:<VM thử nghiệm>`, thấy rule 521 nêu PID bị ẩn]

**Nhận xét.** Runbook của nhóm đặt điều kiện "kernel < 5.7" để đi tiếp, nhưng WEB01 chạy kernel 7.0.0-38 (ghi chú UC3, dòng 496). Như vậy theo chính runbook, WEB01 không đạt điều kiện. Nhóm cần xác minh lại điều kiện này với PoC và với tài liệu của rootkit kiểm thử, thay vì tin theo bản hướng dẫn do AI soạn. Bản thân PoC cũng thừa nhận việc nạp module có thể thất bại và phải thử nhiều lần. Secure Boot hoặc chế độ kernel lockdown trên VM cũng có thể chặn module không ký (đây là kiến thức Linux chung, Wazuh không nêu). Khuyến nghị là **không thử trên WEB01**, vì máy này đang phục vụ năm use case khác. Hãy dùng một VM riêng có snapshot. Cần lưu ý hai giới hạn của rootcheck: phát hiện theo chu kỳ (trễ tới `frequency`), và rootkit hook cả `getsid`/`kill` hoặc dùng kỹ thuật eBPF/ftrace có thể lọt qua. Cuối cùng, vì cấu hình bật `check_if` và bản 4.14.10 vá đúng lỗi command injection trong phần kiểm tra interface promiscuous của rootcheck ([Release notes 4.14.10](https://documentation.wazuh.com/current/release-notes/release-4-14-10.html)), nên nâng agent lên 4.14.10 trước khi demo UC6.

---

# PHẦN IV. HỆ SINH THÁI XUNG QUANH WAZUH

## 12. Wazuh là lớp tương quan; phán quyết và hành động đến từ các công cụ khác

Đây là nội dung trả lời yêu cầu (5). Cách nhìn đúng về hệ sinh thái là: Wazuh làm lớp thu thập và tương quan, còn các công cụ khác cung cấp phán quyết (engine malware, threat intel), dữ liệu sâu hơn (telemetry) hoặc hành động (SOAR, xử lý sự cố). Tài liệu chính thức nói thẳng: "On its own, the FIM module cannot detect malicious files" ([Malware detection](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/index.md)). Hai kiểu tích hợp lặp lại khắp hệ sinh thái. Kiểu thứ nhất là **integratord**: tra cứu API khi có alert. Daemon này có năm đích dựng sẵn (`slack`, `pagerduty`, `virustotal`, `shuffle`, `maltiverse`), và tích hợp tự viết phải có tên bắt đầu bằng `custom-` ([External API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)). Kiểu thứ hai là **CDB list**: đối chiếu IoC ngoại tuyến, không bị giới hạn hạn mức.

| Nhóm | Thành phần | Cách tích hợp | Mức chính thức |
|---|---|---|---|
| Nền tảng | OSSEC (lõi), OpenSearch (indexer/dashboard), Filebeat | Kế thừa và đóng gói sẵn | Chính thức ([Wazuh blog OSSEC](https://wazuh.com/blog/migrating-from-ossec-to-wazuh/); [Release 4.3.0](https://documentation.wazuh.com/4.3/release-notes/release-4-3-0.html)) |
| SIEM bên ngoài | Elastic, Splunk, Amazon Security Lake | Logstash/Splunk Forwarder đọc `alerts.json` hoặc truy vấn indexer. App Kibana/Splunk riêng ngừng phát triển từ 4.6 | Chính thức ([Integrations guide](https://documentation.wazuh.com/current/integrations-guide/index.md)) |
| Phát hiện malware | VirusTotal, YARA, ClamAV, Windows Defender, CDB list | integratord / active response / thu log | Chính thức ([Malware detection](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/index.md)) |
| Threat intel | MISP, AbuseIPDB, AlienVault OTX (qua FireHOL), Maltiverse | Script `custom-*`, CDB list | MISP: phía MISP công bố ([MISP project](https://www.misp-project.org/2025/10/06/wazuh-integration.html)). AbuseIPDB và OTX: blog Wazuh ([AbuseIPDB](https://wazuh.com/blog/detecting-known-bad-actors-with-wazuh-and-abuseipdb/); [CDB OSINT](https://wazuh.com/blog/using-osint-to-create-cdb-lists/)) |
| Telemetry endpoint | Sysmon, osquery, auditd | eventchannel, wodle `osquery`, giám sát system call | Chính thức / blog ([Sysmon](https://wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/); [Osquery](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/osquery.html)) |
| Mạng | Suricata (eve.json), pfSense (syslog), Snort | Agent đọc file JSON / server nhận syslog | Suricata có PoC chính thức ([PoC Suricata](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.md)). pfSense/Snort: hướng dẫn từ cộng đồng ([Google Group](https://groups.google.com/g/wazuh/c/pc4IAOIjW-E)) |
| SOAR / case | Shuffle, TheHive + Cortex, DFIR-IRIS, Slack, PagerDuty, OpenSearch Alerting | integratord, script custom, plugin Notifications | Shuffle là đối tác công nghệ từ 8/10/2025 ([Wazuh–Shuffle](https://wazuh.com/blog/wazuh-and-shuffle-announce-technology-partnership-to-deliver-integrated-security-automation/)). TheHive, IRIS: blog ([TheHive](https://wazuh.com/blog/using-wazuh-and-thehive-for-threat-protection-and-incident-response/); [DFIR-IRIS](https://wazuh.com/blog/enhancing-incident-response-with-wazuh-and-dfir-iris-integration/)) |
| Cloud / container | AWS, Azure, GCP, Office 365, GitHub, Docker | Module/wodle kéo dữ liệu qua API, `docker-listener` | Chính thức ([Docker](https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html); [llms.txt](https://documentation.wazuh.com/llms.txt)) |
| DFIR | Velociraptor, SOCFortress CoPilot | Triển khai client Velociraptor qua active response; giao diện hợp nhất | Cộng đồng ([iSecNG](https://www.isecng.de/post/installing-velociraptor-using-wazuh-active-response-on-windows-endpoints); [CoPilot](https://github.com/socfortress/CoPilot)) |
| AI | AI Analyst (Cloud, Claude qua AWS Bedrock), PoC làm giàu alert bằng LLM, AI Assistant trong dashboard 5.0 | Dịch vụ cloud / active response / dashboard | Chính thức ([AI Analyst](https://documentation.wazuh.com/current/cloud-service/ai-analyst.html); [5.0-rc dashboard](https://documentation.wazuh.com/5.0-rc/getting-started/components/wazuh-dashboard.html)) |

Ngoài phần mềm, Wazuh còn có dịch vụ thương mại. **Wazuh Cloud** có gói Small (tối đa 100 agent) từ **$571/tháng**, Medium (250 agent) từ $923 và Large (500 agent) từ $1.467, kèm 14 ngày dùng thử ([Wazuh Cloud](https://wazuh.com/cloud/)). **Wazuh CTI** là dịch vụ tình báo lỗ hổng công khai, ra mắt cùng bản 4.12 vào tháng 6/2025 ([Introducing Wazuh CTI](https://wazuh.com/?p=26416)). Ngoài ra có dịch vụ hỗ trợ, đào tạo và chương trình ambassador ([Who we are](https://wazuh.com/?p=11893)).

Hệ sinh thái này gắn trực tiếp với lab của nhóm. Lab đã có pfSense, và ảnh dashboard trên slide có một agent tên **SNORT-B**. Vì vậy, tích hợp hệ sinh thái "rẻ" nhất để demo là gửi syslog từ pfSense về manager (bật nhận syslog trên cổng 514 và giới hạn IP được phép). Cộng đồng xác nhận "the simplest option is to configure syslog output on pfSense and collect them with the Wazuh manager" ([Google Group](https://groups.google.com/g/wazuh/c/pc4IAOIjW-E)). Suricata là NIDS có PoC chính thức, nên nếu muốn có alert mạng mà không phải tự viết decoder thì nên chọn Suricata thay cho Snort. Gửi thông báo alert level ≥ 10 sang Slack bằng integratord là một demo khác chỉ mất vài phút. Theo blog các bên, bộ SOC mã nguồn mở thường gặp gồm Wazuh (phát hiện), MISP (IoC), TheHive hoặc DFIR-IRIS (quản lý case), Shuffle (tự động hóa) và Velociraptor (điều tra sâu). Với doanh nghiệp nhỏ, tổ hợp gọn nhất có hướng dẫn chính thức là Wazuh + Shuffle (+ DFIR-IRIS). Lưu ý các bài blog thường được viết cho phiên bản cũ, ví dụ bài TheHive thử trên Wazuh 4.2.5, nên phải kiểm thử lại với 4.14.

---

# PHẦN V. SO SÁNH VÀ ĐÁNH GIÁ

## 13. Ba đề tài của lớp nằm ở ba tầng khác nhau của endpoint security

Cả ba sản phẩm đều có "agent trên endpoint", nên dễ bị so sánh như ba lựa chọn thay thế nhau. Thực tế chúng thuộc ba nhóm sản phẩm khác nhau. PeerSpot xếp Wazuh vào nhóm **SIEM**, còn CrowdStrike vào nhóm **EPP**, và nói rõ hai sản phẩm không cùng nhóm ([PeerSpot](https://peerspot.com/products/comparisons/crowdstrike-falcon_vs_wazuh)). Một bài so sánh của người làm nghề gọi Velociraptor là "the reference" cho threat hunting và thu thập pháp chứng, nhưng là "a hunting tool rather than a continuous alerting engine" ([Ayi NEDJIMI](https://ayinedjimi-consultants.fr/articles/edr-open-source-wazuh-limacharlie-velociraptor-comparatif)). Apex One là bộ chức năng EPP cổ điển: quét malware, chống ransomware, theo dõi hành vi, machine learning, web reputation, firewall, DLP, kiểm soát thiết bị ([Trend docs](https://docs.trendmicro.com/en-us/documentation/article/apex-one-as-a-service-online-help-features-and-benefit)).

| Tiêu chí | **Wazuh** | **Velociraptor** | **Trend Micro / TrendAI Apex One** |
|---|---|---|---|
| Nhóm sản phẩm | SIEM/XDR mở, gốc HIDS | DFIR, threat hunting | EPP + EDR (thành XDR khi nối Vision One) |
| Chủ sở hữu | Wazuh Inc., fork OSSEC năm 2015 | Rapid7 (mua ngày 21/4/2021), tác giả Mike Cohen ([Rapid7 PR](https://investors.rapid7.com/news/news-details/2021/Rapid7-Acquires-Digital-Forensics-and-Incident-Response-Open-Source-Project-Velociraptor-04-21-2021/default.aspx)) | Trend Micro. Mảng doanh nghiệp đổi tên thành **TrendAI** ngày 24/3/2026 ([Trend PR](https://www.trendmicro.com/en/about/newsroom/local-press-releases/au/2026/2026-03-24.html)) |
| Giấy phép / giá | GPLv2 (engine AGPLv3), miễn phí. Cloud từ $571/tháng | Mã nguồn mở, miễn phí (loại giấy phép cần kiểm tra lại trong file LICENSE) | Thương mại, báo giá qua đại lý. Không có giá niêm yết công khai |
| Cơ chế phát hiện | Decoder + rule XML, tương quan frequency/timeframe, FIM, rootcheck, SCA, đối chiếu CVE qua CTI | Truy vấn VQL đóng gói thành "artifact", chạy "hunt" trên nhiều máy, thu sự kiện liên tục ([Rapid7](https://www.rapid7.com/ja/products/velociraptor/)) | Quét chống malware (Smart Scan), theo dõi hành vi, ML dự đoán, sandbox Virtual Analyzer, web reputation |
| Ngăn chặn trước khi chạy | **Không có engine riêng.** Phản ứng sau alert | Không (thu thập và phản ứng theo yêu cầu) | **Có**, đây là vai trò chính |
| Phản ứng | Active response: chặn IP, xóa file, vô hiệu tài khoản | Cô lập máy, gỡ persistence, thu bằng chứng | Chặn, Damage Cleanup, firewall, DLP, device control |
| Hệ điều hành | Linux, Windows, macOS, Solaris, AIX… | Windows, Linux, macOS (theo bài so sánh) | Trang tài liệu đã xem chỉ xác nhận Windows. macOS/Linux cần kiểm tra |
| Triển khai | Tự host (all-in-one/phân tán) hoặc Cloud | Server + client | On-prem (Apex Central) hoặc SaaS. Đang chuyển sang Vision One Endpoint Security ([Trend migrate](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-before-you-migrate)) |
| Tình trạng 11/2026 | 4.14.10. Bản 5.0 mới ở mức RC | Khuyến nghị cập nhật lên 0.77.3 để vá nhiều CVE ([Velociraptor docs](https://docs.velociraptor.app/blog/2025/2025-08-30-release-notes-0.75)) | Thương hiệu đang chuyển tiếp. Console on-prem dính CVE-2025-54948/54987 (RCE, CVSS 9.4), đã bị khai thác thật ([THN](https://thehackernews.com/2025/08/trend-micro-confirms-active.html)) |
| Đánh giá độc lập | G2 4.5/5 (71 review). PeerSpot 7.4 (51 review). Không tham gia MITRE | Chưa có số liệu review | Một trong 11 hãng tham gia MITRE ATT&CK Evaluations 2025 ([SecurityWeek](https://www.securityweek.com/mitre-posts-results-of-2025-attck-enterprise-evaluations/)) |
| Điểm yếu chính | Cài đặt phức tạp, phải tinh chỉnh rule, indexer cần bảo trì | VQL khó học, không phải công cụ cảnh báo liên tục | Chi phí, phụ thuộc nhà cung cấp, ít giá trị SIEM/tuân thủ nếu không có XDR |

Từ bảng trên rút ra ba điểm khi so với hai nhóm còn lại. Một, **Wazuh trả lời câu hỏi "chuyện gì đã xảy ra, ở đâu, có vi phạm tuân thủ không"** trên toàn bộ hệ thống, nhưng không tự chặn được một file độc trước khi nó chạy như Apex One. Ngay cả UC4, trường hợp "xóa malware", cũng chỉ là phản ứng sau khi file đã nằm trên đĩa. Hai, **Velociraptor mạnh nhất sau khi đã có cảnh báo**. Ví dụ, khi Wazuh báo rule 521 trên một máy, Velociraptor có thể quét toàn bộ máy trong mạng tìm cùng dấu hiệu. Đã có hướng dẫn triển khai client Velociraptor bằng chính active response của Wazuh ([iSecNG](https://www.isecng.de/post/installing-velociraptor-using-wazuh-active-response-on-windows-endpoints)). Ba, chính các công cụ bảo mật cũng là bề mặt tấn công: lỗ hổng RCE trên console Apex One, các CVE của Velociraptor trước 0.77.3, và lỗi command injection trong rootcheck của Wazuh trước 4.14.10. Bài học chung là không mở console quản trị ra Internet và phải vá kịp thời. Lab của nhóm đã làm đúng việc giữ dashboard trong vùng SOC.

## 14. Với doanh nghiệp nhỏ, chi phí thật của Wazuh là thời gian của con người

Tự host Wazuh không mất tiền giấy phép, nhưng từ 26 đến 100 agent cần một máy chủ 8 vCPU, 8 GiB RAM và 100–200 GB ổ cứng ([Quickstart](https://documentation.wazuh.com/current/quickstart.html)). Dung lượng lưu trữ ước tính theo tài liệu: khoảng 3,7 GB cho mỗi server, 1,5 GB cho mỗi máy trạm và 7,4 GB cho mỗi thiết bị mạng trong 90 ngày ([Wazuh indexer installation](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html)). Để có mốc so sánh: Microsoft Defender for Business có giá niêm yết $3/người/tháng, và Defender Antivirus có sẵn miễn phí trên Windows 10/11 ([TrustedTech](https://www.trustedtechteam.com/blogs/microsoft-365/microsoft-defender-cost)).

| Phương án cho 50 endpoint (tính minh họa của nhóm tác giả) | Giấy phép / thuê bao mỗi năm | Chi phí khác |
|---|---|---|
| Wazuh tự host | $0 | 1 máy chủ + thời gian quản trị, tinh chỉnh rule, nâng cấp |
| Wazuh Cloud Small | 571 × 12 ≈ $6.852 | Vẫn cần người xử lý alert |
| Defender for Business | 50 × 3 × 12 = $1.800 | Ít tốn công quản trị nếu đã dùng Microsoft 365 |
| Apex One / Vision One | Theo báo giá | — |

Đánh giá của người dùng phản ánh đúng sự đánh đổi này. Trên G2, Wazuh được 4,5/5, nhỉnh hơn Defender for Endpoint (4,4), và nhóm người đánh giá đông nhất là doanh nghiệp nhỏ ([G2](https://www.g2.com/compare/microsoft-defender-for-endpoint-vs-wazuh-the-open-source-security-platform)). Trên PeerSpot, Wazuh chỉ được 7,4 với 81% người dùng sẵn sàng giới thiệu, so với CrowdStrike 8,8 và 98%. Điểm trừ hay gặp là indexer bị timeout, sự cố lưu trữ và không có hỗ trợ trực tiếp từ hãng ([PeerSpot](https://peerspot.com/products/comparisons/crowdstrike-falcon_vs_wazuh)). Ba lần mất kết nối agent và lỗi trùng khóa trong lab của nhóm là minh họa thu nhỏ cho đúng kiểu gánh nặng vận hành này.

## 15. Ưu và nhược điểm của Wazuh qua thực nghiệm

| Ưu điểm | Bằng chứng / nguồn |
|---|---|
| Phạm vi rộng trong một agent: FIM, rootcheck, SCA, inventory, lỗ hổng, log, active response | [Capabilities 4.14](https://documentation.wazuh.com/4.14/user-manual/capabilities/index.html). Lab: một agent WEB01 phục vụ 6 use case |
| Tương quan và tự động phản ứng hoạt động thật | UC2: chặn đúng 180 giây. UC4: xóa file trong vài giây |
| Rule mở, gắn sẵn MITRE ATT&CK và nhóm tuân thủ (PCI DSS…) | 5712 → T1110, 521 → T1014. Group `pci_dss_11.5` trên rule FIM |
| Không tốn giấy phép, cộng đồng lớn (~17,5k sao GitHub) | [GitHub](https://github.com/wazuh/wazuh) |
| Mở rộng dễ bằng integratord và active response | UC4 (VirusTotal), UC5 (YARA) |

| Nhược điểm | Bằng chứng / nguồn |
|---|---|
| Không có engine ngăn chặn. Mọi phản ứng đều diễn ra sau alert | [Malware detection](https://documentation.wazuh.com/4.12/compliance/nist/malware-detection.html). UC4 xóa file sau khi file đã ghi xuống đĩa |
| Phụ thuộc ma trận hỗ trợ hệ điều hành và feed | Ubuntu 26.04: SCA bỏ qua policy, UC3 chưa có CVE |
| Vận hành phức tạp: đăng ký khóa, mạng, tinh chỉnh | Lỗi trùng khóa 002/003, ba lần mất kết nối |
| Tích hợp bên ngoài bị giới hạn hạn mức | VirusTotal 4 request/phút, 500/ngày, API v2 |
| Phát hiện theo chu kỳ ở một số module | Rootcheck và quét FIM định kỳ mặc định 12 giờ |
| Chính Wazuh cũng có lỗ hổng phải vá | 4.14.10 vá command injection trong rootcheck |

---

# KẾT LUẬN

Điều đồ án chứng minh được, và nên trở thành thông điệp chính khi bảo vệ, là Wazuh biến một máy chủ web trong DMZ thành một cảm biến có khả năng tự phản ứng. Hai chuỗi đã được chứng minh đầu-cuối bằng log thật. Ở UC2, 8 lần đăng nhập thất bại sinh rule 5712, rồi IP bị chặn trong 180 giây. Ở UC4, một file mới được FIM phát hiện, VirusTotal xác nhận 66/68 engine, rồi file bị xóa. Chuỗi thứ hai bị giới hạn bởi API v2 và hạn mức miễn phí, và cả hai đều là phát hiện rồi phản ứng chứ không phải ngăn chặn. Điểm có giá trị học thuật nhất lại nằm ở những chỗ chưa chạy được. Một hệ điều hành mới hơn ma trận hỗ trợ đủ để vô hiệu hóa SCA và rất có thể cả UC3. Ghép nguyên văn hai trang tài liệu chính thức (dùng `badguy` với rule 5763) sẽ cho ra một cấu hình không bao giờ chặn. Còn điều kiện kernel trong runbook UC6 do AI soạn thì mâu thuẫn với chính máy WEB01. Nếu trình bày trung thực những điều này, báo cáo sẽ thuyết phục hơn một báo cáo chỉ có ảnh chụp thành công.

Trong bức tranh của lớp, ba đề tài ghép lại thành một kiến trúc phòng thủ nhiều lớp hơn là ba lựa chọn cạnh tranh. Apex One (hoặc Defender) chặn ở điểm cuối. Wazuh thu thập, tương quan, chứng minh tuân thủ và phản ứng tự động ở mức vừa phải. Velociraptor vào cuộc khi cần điều tra sâu. Với doanh nghiệp nhỏ, câu hỏi thực tế không phải "chọn sản phẩm nào" mà là "có người vận hành Wazuh không". Nếu có, Wazuh cùng Defender miễn phí là tổ hợp có chi phí giấy phép gần bằng 0. Nếu không, EPP thương mại có hỗ trợ từ hãng ít rủi ro hơn.

---
---

# HIỆN TRẠNG ĐỒ ÁN VÀ VIỆC CẦN LÀM (phần nội bộ, không đưa vào bản nộp)

Quy ước trạng thái: **Đã có bằng chứng** nghĩa là ghi chú có output hoặc log thật. **Chỉ có các bước** nghĩa là chỉ có lệnh và kết quả "kỳ vọng", phần lớn do trợ lý AI soạn. **Đang gỡ lỗi** nghĩa là ghi chú dừng giữa chừng lúc chẩn đoán. Những câu như "Kỳ vọng…" hay "phải thấy…" trong ghi chú là dự đoán, không được dùng làm kết quả.

## A. Theo năm yêu cầu của thầy

| Yêu cầu | Trạng thái | Đã có | Còn thiếu |
|---|---|---|---|
| (1) Thiết kế mô hình mạng | Đã có bằng chứng một phần | Sơ đồ trên slide. Agent kết nối được qua pfSense và ZeroTier (`nc` succeeded, `TcpTestSucceeded`) | Bảng IP chính thức. Ảnh rule pfSense. Xác nhận file netplan và `05-zerotier-soc.network` (chưa có lệnh `cat`) và thử reboot. Sơ đồ có KALI01 và vùng TEST. Phần lý giải thiết kế |
| (2) Tính năng & triển khai | Đã có bằng chứng một phần | All-in-one đang chạy. Agent 002/003. Agent v4.14.9 | Cách cài và phiên bản manager/indexer/dashboard. Output danh sách agent. Sửa lỗi trùng khóa. Ghi nhận việc dùng hệ điều hành ngoài danh sách hỗ trợ. Kế hoạch nâng lên 4.14.10 |
| (3) Nguyên tắc hoạt động | Chưa có trong ghi chú | — | Viết chương lý thuyết (dùng Phần I) |
| (4) Thử nghiệm tính năng | 2/6 use case có bằng chứng | UC2, UC4 | UC1, UC5, UC6 chưa có alert. UC3 chưa có CVE |
| (5) Hệ sinh thái | Chưa có trong ghi chú | — | Viết Phần IV. Nên demo ít nhất một tích hợp (pfSense syslog hoặc thông báo Slack) |

## B. Theo từng use case

| UC | Trạng thái | Đã có bằng chứng | Bằng chứng còn thiếu để "đóng" use case |
|---|---|---|---|
| UC1 FIM | Chỉ có các bước | `grep` cấu hình. Log 6003/6016/6012 | Alert 554, 550 (có diff) và 553 cho cùng một file trên WEB01. Kết quả trên WIN01 (Desktop). Ảnh module FIM |
| UC2 SSH | **Đã có bằng chứng** | Alert 5710. `firewall-drop` add/delete kèm 5712 | XML active response thật. `iptables` lúc đang chặn. `ping`/`nc` từ KALI01 bị timeout. Alert 651/652 trên dashboard |
| UC3 Lỗ hổng | Đang gỡ lỗi | Syscollector 10m. `local.db` 408K | Inventory hiển thị ở phía manager. Cấu hình `<vulnerability-detection>`. Danh sách CVE. Một CVE chuyển từ Active sang Solved. Ảnh Inventory và Events |
| UC4 VirusTotal | **Đã có bằng chứng** | 87105 (66/68). "Successfully removed threat" ×2 | `local_rules.xml` và `<integration>` (che API key). Chuỗi 554 → 87105 → 553 → 100092 trên dashboard. `ls` sau khi xóa |
| UC5 YARA | Chỉ có các bước (phần chuẩn bị agent đã có output) | YARA 4.5.5. Quyền của `yara.sh`. Thư mục được FIM giám sát | Lần chạy YARA thủ công. Alert 100301 và 108001 cho file đánh dấu. File đối chứng không sinh 108001. Cấu hình phía manager |
| UC6 Rootcheck | Chỉ có các bước | Không có | Phiên bản kernel và kết quả pre-flight. Log rootcheck khởi động. Alert 521 (hoặc kết quả âm tính có giải thích). Bằng chứng đã chụp và khôi phục snapshot |

## C. Việc cần làm theo thứ tự ưu tiên

| Ưu tiên | Việc | Lý do / cách kiểm chứng |
|---|---|---|
| **P0-1** | Dọn thông tin nhạy cảm khỏi Google Doc (xem mục E) | Ghi chú đang chứa chuỗi giống mật khẩu, khóa agent và network ID ZeroTier |
| **P0-2** | Sửa lỗi trùng khóa agent 002/003: xóa bản ghi trùng trên manager, đăng ký lại, xác nhận chỉ còn một kết nối cho mỗi ID | Lỗi này có thể gây mất sự kiện trong mọi use case |
| **P0-3** | Ổn định mạng: `cat` hai file cấu hình bridge, reboot ZT-GW01 rồi kiểm tra `bridge link` và kết nối `nc` tới 1514. Bật NTP trên mọi máy | Mạng đã đứt 3 lần. Đồng hồ hai bên lệch khoảng 30 giây |
| **P0-4** | Chạy lại UC1 trên WEB01 (tạo, sửa, xóa file, mỗi bước cách 5 giây) và trên WIN01. Chụp alert 554/550/553 | Cấu hình đã nạp, chỉ còn thiếu phép thử |
| **P0-5** | UC3: kiểm tra inventory ở phía manager. Nếu WEB01 (Ubuntu 26.04) không có CVE, chuyển sang WIN01 hoặc thêm VM Ubuntu 22.04/24.04. Cài một gói có lỗ hổng trong lúc agent đang chạy, chờ hết interval, cập nhật gói, chờ trạng thái Solved | Ma trận hỗ trợ chỉ đến Ubuntu 24.04. Lần quét đầu không sinh alert OS |
| **P0-6** | UC5: chạy YARA thủ công, sau đó thử file đánh dấu và file đối chứng. Chụp 100301/108001 | Toàn bộ chuỗi đã dựng xong |
| **P0-7** | Chụp lại ảnh dashboard (xem mục D) | Ảnh hiện tại không khớp với lab |
| **P1-1** | UC6 trên **VM riêng có snapshot** (không dùng WEB01). Xác minh lại điều kiện kernel. Nếu không nạp được module thì trình bày kết quả âm tính kèm lý do | Kernel 7.0 mâu thuẫn với điều kiện "< 5.7" trong runbook |
| **P1-2** | Bổ sung bằng chứng cho UC2 và UC4 (XML, iptables, 651/652, chuỗi 553/100092) | Biến bằng chứng log thành bằng chứng trên dashboard |
| **P1-3** | Nâng manager rồi agent lên 4.14.10. Ghi lại phiên bản của cả ba thành phần trung tâm | Bản vá bảo mật, đặc biệt lỗi rootcheck |
| **P1-4** | Dọn khối active response thừa đang gọi `restart-ossec.sh` | Tránh cảnh báo lặp lại "command not present" |
| **P1-5** | Chụp rule pfSense và vẽ lại sơ đồ có đủ địa chỉ IP | Hoàn thiện yêu cầu (1) |
| **P2-1** | Demo hệ sinh thái: pfSense gửi syslog về Wazuh, hoặc integratord gửi Slack cho alert level ≥ 10 | Biến yêu cầu (5) từ lý thuyết thành thực hành |
| **P2-2** | Thử FIM với `whodata` trên WEB01 hoặc thêm Sysmon trên WIN01 | Trả lời được câu "ai đã sửa file" |
| **P2-3** | Phối hợp với hai nhóm Velociraptor và Apex One để có một slide so sánh chung | Yêu cầu so sánh của thầy |

## D. Những chỗ cần sửa trên slide

| Slide | Vấn đề | Sửa thành |
|---|---|---|
| Ảnh dashboard (Threat Hunting) | "Top 5 agents" chỉ có **wazuh01** và **SNORT-B**, không có WEB01/WIN01. SNORT-B không thuộc mô hình. Ảnh hiện "0 Level 12 or above", mâu thuẫn với alert 87105 level 12 ngày 07/11 | Chụp lại với khoảng thời gian 05–07/11, thấy WEB01 (002) và WIN01 (003), có alert level ≥ 12. Nếu SNORT-B là cảm biến thật thì phải đưa vào sơ đồ, nếu không thì gỡ agent đó |
| "Các kịch bản demo tiếp theo" | Vẫn liệt kê FIM, SSH, CVE, VirusTotal, YARA là việc "sắp làm". UC6 chưa có | Thay bằng bảng trạng thái và kết quả. Thêm UC6 nếu giữ use case này |
| Thông tin phiên bản | Chưa ghi phiên bản | Ghi "Wazuh 4.14.9 (agent), đã/sẽ nâng lên 4.14.10" kèm phiên bản thật của manager |
| Sơ đồ mạng | Thiếu KALI01/vùng TEST và IP. Trong ghi chú, trợ lý AI có chỗ gọi máy B là "VirtualBox" | Máy B là **VMware Workstation**. Bổ sung đầy đủ IP và các cổng được phép qua pfSense |
| UC2 | Có nguy cơ ghi rule 5763 theo tài liệu | Ghi **5712** (user không tồn tại), kèm 5710 và 651/652 |
| UC3 | Tiêu chí "trạng thái CVE phù hợp" chưa tính tới việc hệ điều hành không được hỗ trợ | Ghi rõ endpoint dùng để demo và lý do (ma trận Ubuntu 14.04–24.04) |
| UC4 | Có thể ghi "VirusTotal API v3" hoặc "ngăn chặn malware" | Ghi **API v2**, giới hạn 4 request/phút và 500/ngày, và "phát hiện và xóa sau khi file đã ghi xuống đĩa" |
| UC5 | Nếu ghi "phát hiện và xóa" | YARA (PoC 4.14) **chỉ phát hiện** (108001). Xóa file là phần mở rộng tự viết, nếu có |
| UC6 | Không có rule ID | Rule **521** (level 11, T1014), rule cha 510 |
| Mọi ảnh chụp | Có thể lộ network ID ZeroTier, khóa agent hoặc API key | Che trước khi đưa vào slide |

## E. Ghi chú bảo mật: dọn Google Doc trước khi chia sẻ

Ghi chú lab đang chứa thông tin bí mật dạng văn bản thô. Báo cáo này **chỉ nêu vị trí, không chép lại giá trị**. Cần xóa hoặc thay bằng `[REDACTED]` ở các vị trí sau:

| Loại | Vị trí trong ghi chú |
|---|---|
| Chuỗi giống mật khẩu / thông tin đăng nhập | Phần UC3, dòng 1 (dính liền với chữ "Phía máy B"). Phần UC5, dòng 231–232 |
| Khóa agent (output `client.keys` hoặc chuỗi khóa) | Phần UC3, dòng 127 (WIN01/003), 163 và 210 (trong lệnh `grep`), 213 (một đoạn khóa trong thông báo lỗi PowerShell), 362 (WEB01/002) |
| Network ID ZeroTier | Phần UC1, dòng 159–161, 173–175, 177, 192. Phần UC3, dòng 670 |
| Nên xóa thêm | ID node/member ZeroTier ở phần UC1, dòng 208 và 210. Tên mạng ZeroTier ở phần UC1, dòng 177 và 207 |

Nếu Google Doc đã từng được chia sẻ, cần làm thêm ba việc. Một, đăng ký lại hai agent để cấp khóa mới; việc này có thể gộp với bước sửa lỗi trùng khóa (P0-2). Hai, đổi mọi mật khẩu đã lộ. Ba, trên ZeroTier Central, rà danh sách thành viên và gỡ quyền những node lạ. Mạng là PRIVATE nhưng ai có network ID vẫn có thể gửi yêu cầu tham gia. Ngoài ra, không đưa file `wazuh-passwords.txt` hay API key VirusTotal vào báo cáo hoặc slide. Hash và permalink VirusTotal của EICAR (phần UC4, dòng 166) là thông tin công khai, giữ lại được.

## F. Danh mục ảnh và output cần thu thập cho bản nộp

| # | Bằng chứng | Use case / mục |
|---|---|---|
| 1 | Sơ đồ mạng mới, ảnh rule pfSense, kết quả cấu hình bridge sau reboot | Mục 4 |
| 2 | Phiên bản các thành phần, danh sách agent Active | Mục 5 |
| 3 | Alert 554/550/553 (WEB01 và WIN01), chi tiết `syscheck.diff` | UC1 |
| 4 | XML active response, alert 5710/5712/651/652, `iptables`, ping/nc bị chặn | UC2 |
| 5 | Inventory, danh sách CVE, cặp Active → Solved | UC3 |
| 6 | `<integration>` (che key), chuỗi 554 → 87105 → 553 → 100092, `ls` sau khi xóa | UC4 |
| 7 | YARA thủ công, 100301 + 108001 cho file đánh dấu, chỉ 100301 cho file đối chứng | UC5 |
| 8 | Log rootcheck khởi động, alert 521 hoặc giải thích kết quả âm tính, bằng chứng đã khôi phục snapshot | UC6 |
| 9 | Dashboard tổng quan mới (WEB01, WIN01, level ≥ 12) | Slide |
