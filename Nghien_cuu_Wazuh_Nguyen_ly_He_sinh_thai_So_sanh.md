# NGHIÊN CỨU WAZUH: NGUYÊN LÝ HOẠT ĐỘNG, HỆ SINH THÁI VÀ SO SÁNH

**Đề tài:** A21 — Wazuh trong mạng doanh nghiệp nhỏ  
**Ngày đối chiếu tài liệu:** 06/11/2026  
**Bối cảnh:** nhóm đang thực hiện năm demo; hai thành viên phụ trách thực nghiệm, một thành viên phụ trách nghiên cứu và tổng hợp.  
**Phạm vi phiên bản:** lab đã ghi nhận Wazuh 4.14.9; các nguồn `/current/` là tài liệu hiện hành, cần đối chiếu với phiên bản thực tế trước khi áp dụng cấu hình.

Tài liệu này bổ sung phần giải thích và đối chiếu sản phẩm. Không coi thiết kế hoặc mô tả tính năng dưới đây là kết quả thử nghiệm đã hoàn thành. Các nhận xét về sản phẩm khác dựa trên tài liệu nhà cung cấp, chưa phải phép đo so sánh trực tiếp.

## 1. Mục tiêu phần nghiên cứu

Phần này cần trả lời ba câu hỏi:

1. Từ một thay đổi hoặc hành vi trên endpoint, Wazuh thu thập, phân tích và tạo phản ứng như thế nào?
2. Wazuh kết hợp với những công cụ nào để bổ sung dữ liệu, nhận diện và điều phối xử lý?
3. Vì sao nhóm chọn Wazuh cho yêu cầu của đồ án; các giải pháp khác phù hợp với nhu cầu nào?

Sản phẩm bàn giao của thành viên nghiên cứu gồm: sơ đồ xử lý dữ liệu, giải thích cơ chế năm demo, bảng hệ sinh thái, bảng so sánh có nguồn và phần nhận xét liên hệ kết quả nhóm.

## 2. Nguyên lý hoạt động

### 2.1. Vai trò các thành phần

| Thành phần | Vai trò |
| --- | --- |
| Wazuh Agent | Chạy trên endpoint, thu thập dữ liệu cục bộ và gửi về Server |
| Wazuh Server/Manager | Phân tích dữ liệu, áp dụng decoder/rule và điều phối phản ứng |
| Wazuh Indexer | Lập chỉ mục, lưu trữ và phục vụ tìm kiếm |
| Wazuh Dashboard | Giao diện tra cứu; truy vấn Indexer và API Server |
| Filebeat | Chuyển dữ liệu cảnh báo từ Server tới Indexer trong kiến trúc 4.x của lab |

Agent giao tiếp với Server qua TCP 1514 mặc định; enrollment bằng cấu hình Agent sử dụng TCP 1515. Dashboard dùng API Server cho thông tin trạng thái/quản lý. Không mở toàn bộ dịch vụ trung tâm cho endpoint chỉ vì cần truyền log.

Trong đồ án, ba thành phần trung tâm cùng nằm trên WAZUH01: **All-in-one**. WIN01 và WEB01 vẫn cần Agent riêng. Số máy vật lý dùng để chia tài nguyên không quyết định số node của cụm Wazuh.

Nguồn: [Kiến trúc và giao tiếp Wazuh](https://documentation.wazuh.com/current/getting-started/architecture.html).

### 2.2. Từ dữ liệu thô đến cảnh báo

```text
Windows Event Log / log SSH, Apache trên endpoint
                     ↓
                Wazuh Agent
                     ↓
              Wazuh Manager
       Decoder trích trường dữ liệu
       Rule đánh giá và tương quan sự kiện
                     ↓
             Cảnh báo thỏa điều kiện
                     ↓
                  Filebeat
                     ↓
                   Indexer
                     ↑ truy vấn
                  Dashboard
```

**Decoder** trích xuất thông tin từ log, chẳng hạn IP nguồn, tài khoản và kết quả đăng nhập. **Rule** đánh giá điều kiện trên dữ liệu đã phân tích; một rule có thể dựa vào sự kiện trước đó và ngưỡng tương quan. Việc Agent gửi được log không có nghĩa mọi dòng log đều thành cảnh báo.

Ví dụ: một lần đăng nhập sai cung cấp sự kiện xác thực thất bại; chuỗi thất bại thỏa điều kiện tương quan có thể kích hoạt cảnh báo SSH brute-force. Ngưỡng, cửa sổ thời gian và rule ID phải ghi theo cấu hình thật của nhóm.

Nguồn: [Decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/index.html), [Rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/index.html).

### 2.3. FIM: so sánh với trạng thái đã ghi nhận

FIM lưu checksum và thuộc tính tập tin trong cơ sở dữ liệu của endpoint. Theo lịch quét hoặc cơ chế theo dõi thời gian thực, module phát hiện thay đổi trong đường dẫn được cấu hình và gửi thông tin về Server. Dữ liệu trạng thái được đồng bộ giữa Agent và Server.

```text
Đường dẫn giám sát → Lập baseline → Theo dõi/quét lại
→ So sánh checksum, thuộc tính → Phát hiện thay đổi → Cảnh báo
```

Áp dụng: thay đổi file trong thư mục thử nghiệm hoặc thư mục web trên WEB01. Phải chờ baseline trước khi đánh giá thao tác sửa/xóa. FIM xác định thay đổi; muốn đánh giá thay đổi có độc hại cần thêm ngữ cảnh hoặc công cụ nhận diện.

Nguồn: [Cơ chế FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-it-works.html).

### 2.4. SSH brute-force và Active Response

```text
Kali thử đăng nhập → SSH trên WEB01 ghi log → Agent gửi dữ liệu
→ Manager áp dụng rule tương quan → Cảnh báo
→ Active Response trên WEB01 chặn IP → Hết timeout thì hoàn tác
```

Phát hiện và chặn là hai bước riêng. Active Response liên kết điều kiện cảnh báo với script thực thi; phản ứng có trạng thái có thể hoàn tác sau timeout. Trong thiết kế nhóm, vị trí chặn là WEB01. pfSense trước đó phải cho phép kết nối SSH phục vụ thử nghiệm, nếu không hoạt động có thể bị chặn trước khi tới SSH.

Bằng chứng cần phân biệt: log đăng nhập sai, alert, log thực thi, quy tắc chặn thực tế và kết nối mới sau khi hết timeout. Không kết luận đã chặn chỉ từ một alert.

Nguồn: [Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html), [Ví dụ chặn SSH brute-force](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/blocking-ssh-brute-force.html).

### 2.5. Phát hiện lỗ hổng từ inventory và CTI

```text
Syscollector trên endpoint → Thông tin hệ điều hành/phần mềm
→ Server đối chiếu dữ liệu Wazuh CTI → Phát hiện CVE → Inventory lỗ hổng
```

Đây là đối chiếu dữ liệu phần mềm với thông tin lỗ hổng, không phải thử khai thác để xác nhận xâm nhập. Phát hiện cần được xem cùng tên gói, phiên bản và thông tin bản vá của nhà cung cấp. Sau cập nhật, phải chờ thu thập/đồng bộ lại trước khi đánh giá trạng thái mới.

Inventory là dữ liệu trạng thái; không mô tả toàn bộ inventory/CVE như các dòng log ứng dụng cùng đi qua một file alert. Có CVE không đồng nghĩa đã bị khai thác; không có phát hiện cũng không chứng minh hệ thống hoàn toàn an toàn.

Nguồn: [Cơ chế Vulnerability Detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html).

### 2.6. Hai tích hợp phục vụ kiểm tra tập tin

**VirusTotal:** FIM phát hiện sự kiện; tích hợp lấy hash từ alert để truy vấn báo cáo trong cơ sở dữ liệu VirusTotal. Quy trình chuẩn được mô tả ở đây là tra cứu hash, không mặc định tải nội dung file lên dịch vụ. Kết quả nhận diện và script loại file là hai bước phải nối bằng điều kiện phản ứng phù hợp. API không có dữ liệu khác với kết quả không bị đánh dấu; cả hai đều không phải bảo đảm an toàn.

```text
FIM → Hash → VirusTotal API → Kết quả/alert
→ Điều kiện Active Response → Script xử lý file trên WEB01
```

Nguồn: [Tích hợp VirusTotal](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html).

**YARA:** FIM có thể kích hoạt script quét file trên endpoint. YARA kiểm tra file theo bộ rule; kết quả quét được thu lại và phân tích để tạo cảnh báo. YARA là công cụ ngoài được tích hợp, không phải engine có sẵn chỉ cần cài Agent là tự chạy. Khớp rule kiểm thử chỉ chứng minh pipeline và điều kiện rule đó; không chứng minh phát hiện mọi mã độc. Hành động xóa/cô lập phải cấu hình riêng nếu có.

```text
FIM → Lệnh quét → YARA trên WEB01 + bộ rule
→ Log kết quả → Agent → Manager → Cảnh báo
```

Nguồn: [Tích hợp YARA](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html).

### 2.7. Phân biệt xử lý bảo mật và kết nối triển khai

pfSense định tuyến và áp dụng chính sách giữa USER, DMZ, SOC và TEST. ZeroTier cùng ZT-GW01 phục vụ vận chuyển dữ liệu lab giữa hai máy vật lý. Hai thành phần này không phân tích log thay Manager, không thu dữ liệu thay Agent và không phải điều kiện bắt buộc của mọi hệ thống Wazuh.

Sơ đồ mạng doanh nghiệp trình bày các vùng và vai trò nghiệp vụ. Sơ đồ triển khai hai host mới bổ sung ZeroTier/bridge. Snort đã được nhóm loại khỏi phạm vi thiết kế chính.

## 3. Các giải pháp trong hệ sinh thái

### 3.1. Phân loại đúng vai trò

Phần lõi Wazuh gồm Agent, Server, Indexer, Dashboard và cơ chế truyền dữ liệu liên quan. Phần hệ sinh thái trong báo cáo tập trung các giải pháp kết hợp với lõi đó để cung cấp dữ liệu, nhận diện hoặc điều phối công việc.

| Giải pháp | Vai trò khi kết hợp Wazuh | Phạm vi nhóm |
| --- | --- | --- |
| VirusTotal | Bổ sung kết quả tra cứu hash, hỗ trợ nhận diện tập tin | Đang thực hiện trong demo |
| YARA | Quét file bằng bộ quy tắc trên endpoint | Đang thực hiện trong demo |
| Sysmon | Bổ sung sự kiện Windows như tiến trình và kết nối mạng cho Agent thu | Tìm hiểu; không mặc định đã cài |
| Microsoft Defender Antivirus | Cung cấp log phát hiện và hành động xử lý để Wazuh thu thập | Tìm hiểu; không đồng nhất với sản phẩm Defender for Endpoint |
| Shuffle | Nhận cảnh báo qua tích hợp API, hỗ trợ quy trình điều phối bên ngoài | Hướng mở rộng, chưa triển khai |
| Slack/PagerDuty | Nhận thông báo qua tích hợp phù hợp | Hướng mở rộng, chưa triển khai |

Wazuh hỗ trợ thu kênh Sysmon và Windows Defender bằng Windows Event Channel. Khi thu log Defender, phải ghi đúng công cụ nào đã chặn hoặc loại file; việc Wazuh hiển thị log không tự biến hành động đó thành Active Response của Wazuh.

Nguồn: [Các nguồn log Windows](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html), [Integrator và external API](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html).

### 3.2. Cách viết sâu cho mỗi giải pháp

Mỗi giải pháp nên có một đoạn hoặc một tiểu mục trả lời:

1. Công cụ giải quyết nhu cầu gì?
2. Trao đổi loại dữ liệu nào với Wazuh, theo chiều nào?
3. Cần thành phần, cấu hình hoặc quyền gì?
4. Đem lại lợi ích gì cho tình huống của nhóm?
5. Có giới hạn nào và đã triển khai tới đâu?

Với VirusTotal, phân tích phụ thuộc API, kết nối Internet, phạm vi dữ liệu hash và việc bảo vệ API key. Với YARA, phân tích chất lượng/cập nhật rule, phạm vi file được quét và lượng tài nguyên thực tế. Với Sysmon, cân nhắc chính sách thu và khối lượng sự kiện. Với Shuffle hoặc dịch vụ thông báo, mô tả luồng và giới hạn quyền; không ghi đã tự động hóa nếu chưa thử.

Thành viên nghiên cứu phụ trách giải thích và nguồn tham khảo. Hai thành viên thực nghiệm cung cấp cấu hình cuối, log kết quả và giới hạn đã quan sát để cập nhật phần VirusTotal/YARA.

## 4. So sánh với các sản phẩm khác

### 4.1. Phạm vi và phương pháp

Đây là **so sánh chức năng và mô hình theo tài liệu**, không phải benchmark. Chọn ba đối tượng vì chúng có các điểm giao với Wazuh:

- **Elastic Security:** giám sát, phân tích bảo mật và bảo vệ endpoint.
- **Trend Micro Apex One:** bảo vệ endpoint, phù hợp đối chiếu góc nhìn Endpoint Protection của đề tài.
- **Velociraptor:** điều tra số, thu thập bằng chứng và truy vấn endpoint; đồng thời có trong danh sách đề tài của lớp.

Các sản phẩm có phạm vi khác nhau. Không dùng bảng dấu có/không đơn giản để suy ra chúng thay thế hoàn toàn cho nhau. Ghi rõ phiên bản/gói dịch vụ khi bàn tính năng thương mại; không khẳng định tính năng thiếu chỉ vì nguồn đang đọc không đề cập.

### 4.2. Bảng so sánh

| Tiêu chí | Wazuh trong lab | Elastic Security | Trend Micro Apex One | Velociraptor |
| --- | --- | --- | --- | --- |
| Trọng tâm | Giám sát tập trung, FIM, inventory/CVE, phản ứng theo rule | SIEM, phân tích bảo mật và endpoint security | Bảo vệ endpoint, quét và kiểm soát hành vi | DFIR, thu thập và điều tra endpoint |
| Cơ chế nổi bật | Agent → decoder/rule → alert; Active Response | Elastic Agent, Elastic Defend, detection engine | Security Agent và chính sách bảo vệ | Client, VQL và artifact; hunt trên nhiều endpoint |
| Kiểm tra tập tin | FIM; tích hợp VirusTotal/YARA trong đồ án | Elastic Defend cung cấp các khả năng phát hiện/phòng ngừa endpoint | Quét malware và bảo vệ hành vi/ransomware theo cấu hình | Truy vấn/thu thập theo artifact phục vụ điều tra |
| Mô hình quản lý | All-in-one tự vận hành trên VM A | Có cloud và self-managed | Quản lý Security Agent qua console/server theo bản sản phẩm | Client–server, triển khai hunt/collection |
| Tùy chỉnh cần nghiên cứu | Decoder, rule, script và cấu hình Agent | Rule, dữ liệu đầu vào và chính sách Defend | Chính sách bảo vệ và phạm vi module được cấp phép | VQL, artifact, điều kiện hunt |
| Điều cần kiểm tra về chi phí | Hạ tầng, lưu trữ, quản trị, dịch vụ hỗ trợ nếu dùng | Deployment và subscription/tier của tính năng | License, thành phần bổ sung; Endpoint Sensor có yêu cầu riêng | Hạ tầng lưu trữ, vận hành và hỗ trợ theo phương án |
| Giá trị đối với việc học của nhóm | Quan sát được chuỗi thu thập–phân tích–phản ứng của năm demo | Đối chiếu một nền tảng có cả phân tích và bảo vệ endpoint | Đối chiếu một giải pháp tập trung bảo vệ endpoint | Đối chiếu khả năng điều tra và thu bằng chứng |

Nguồn cho cột Wazuh: mục 2 và các tài liệu chính thức đã dẫn.

Nguồn Elastic: [Elastic Security overview](https://www.elastic.co/docs/solutions/security), [Thiết lập bảo vệ](https://www.elastic.co/docs/solutions/security/set-up), [Self-managed plans](https://www.elastic.co/pricing/self-managed). Tài liệu mô tả Elastic Defend trong Elastic Agent và các lựa chọn triển khai; quyền dùng từng chức năng cần đối chiếu đúng tier.

Nguồn Apex One: [Enhanced Protection](https://docs.trendmicro.com/en-us/documentation/article/apex-one-service-pack-1-patch-4-install-guide-enable-enhanced-prot), [Endpoint Sensor và yêu cầu cấp phép](https://docs.trendmicro.com/en-us/documentation/article/apex-central-patch-9-install-help-enabling-endpoint-se). Cột này dựa trên tài liệu Apex One/Apex Central được dẫn, không gán toàn bộ khả năng của bộ sản phẩm khác cho Apex One cơ bản.

Nguồn Velociraptor: [Overview](https://docs.velociraptor.app/docs/overview/), [Hunting](https://docs.velociraptor.app/docs/hunting/), [File acquisition](https://docs.velociraptor.app/docs/file_collection/).

### 4.3. Nhận xét và lý do lựa chọn

**Nhận định cho đồ án:** Wazuh phù hợp với phạm vi đã chọn vì nhóm có thể giải thích và kiểm chứng từng khâu từ Agent, dữ liệu đầu vào, decoder/rule tới cảnh báo và script phản ứng. Nhóm cũng tận dụng được môi trường Windows/Linux và hạ tầng lab đã dựng.

Đổi lại, nhóm phải cấu hình và duy trì nguồn thu, điều kiện phát hiện, script, tài nguyên lưu trữ và các tích hợp. Khả năng loại một mẫu bằng script không chứng minh Wazuh có mức bảo vệ hoặc khả năng chống can thiệp tương đương mọi sản phẩm endpoint thương mại.

Nếu nhu cầu ưu tiên điều tra endpoint theo câu hỏi cụ thể, Velociraptor là đối tượng đáng xem xét. Nếu ưu tiên chính sách phòng ngừa endpoint có engine chuyên dụng, cần đánh giá cấu hình tương ứng của Apex One hoặc Elastic Defend. Nếu ưu tiên nền tảng phân tích dữ liệu bảo mật và endpoint security, Elastic Security là đối tượng so sánh trực tiếp hơn về phạm vi nền tảng.

Đây là suy luận dựa trên vai trò được mô tả trong các nguồn, chưa phải kết luận đo thực nghiệm về sản phẩm tốt nhất. Nhóm chưa đo tỷ lệ phát hiện, báo động giả, độ trễ hoặc RAM/CPU của các đối tượng so sánh.

## 5. Phối hợp với hai thành viên thực nghiệm

### 5.1. Những thông tin cần nhận sau mỗi demo

| Demo | Thông tin thành viên nghiên cứu cần nhận |
| --- | --- |
| FIM | Đường dẫn, chế độ theo dõi, baseline, trường thay đổi và alert thực tế |
| SSH/Active Response | Nguồn log, rule ID, điều kiện tương quan, script, timeout, vị trí chặn và bằng chứng hoàn tác |
| CVE | Inventory, gói/phiên bản, CVE, thông báo nhà cung cấp và trạng thái sau đồng bộ |
| VirusTotal | Hash, kết quả API, điều kiện phản ứng, log script và bằng chứng file bị loại |
| YARA | Phiên bản, bộ rule, cách kích hoạt quét, log kết quả và file đối chứng |

Không yêu cầu đồng đội gửi mật khẩu hoặc API key. Cần nội dung cấu hình đã che bí mật và bằng chứng gắn đúng lần chạy.

### 5.2. Thứ tự thực hiện phần nghiên cứu

1. Hoàn thiện mục 2: giải thích kiến trúc và năm cơ chế bằng ngôn ngữ của mình.
2. Hoàn thiện mục 3: viết sâu VirusTotal/YARA; các công cụ khác ghi là hướng tìm hiểu/mở rộng.
3. Hoàn thiện mục 4: chốt tiêu chí so sánh, kiểm tra nguồn và tên phiên bản/gói nếu cần.
4. Nhận kết quả của đồng đội, thay các mô tả dự kiến bằng cấu hình và kết quả thực tế có căn cứ.
5. Rà tính nhất quán giữa báo cáo, sơ đồ và slide: không còn Snort trong phạm vi chính; ZeroTier chỉ nằm ở phương án triển khai lab.

### 5.3. Điều kiện hoàn thành phần việc

- [ ] Giải thích được chức năng từng thành phần và hai chiều dữ liệu/lệnh phản ứng.
- [ ] Phân biệt decoder, rule, alert và dữ liệu inventory.
- [ ] Giải thích được cơ chế của cả năm demo bằng cấu hình thật của nhóm.
- [ ] Có bảng hệ sinh thái và phân biệt phần đã tích hợp với hướng mở rộng.
- [ ] Có bảng so sánh dẫn nguồn, không có số hiệu năng hoặc kết luận hơn/kém chưa đo.
- [ ] Có lý do chọn Wazuh gắn với mục tiêu, tài nguyên và phạm vi đồ án.
- [ ] Các nguồn được truy cập lại khi chốt báo cáo; ghi rõ hạn chế phiên bản.

## 6. Gợi ý ghép vào báo cáo cuối

Đặt phần nghiên cứu trước chương triển khai và thực nghiệm:

1. Giới thiệu bài toán, mục tiêu và phạm vi.
2. Cơ sở lý thuyết, kiến trúc và nguyên lý hoạt động Wazuh.
3. Hệ sinh thái và so sánh giải pháp; lý do lựa chọn.
4. Thiết kế mạng và triển khai thực tế.
5. Năm kịch bản, kết quả, đối chứng và đánh giá.
6. Hạn chế và hướng phát triển.

Khi rút gọn lên slide bảo vệ, phần nghiên cứu có thể gồm một sơ đồ nguyên lý, một bảng tích hợp và một bảng so sánh ngắn. Đây là bố cục đề xuất cho báo cáo cuối, không thay đổi yêu cầu số slide của giảng viên.
