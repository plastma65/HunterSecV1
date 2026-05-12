# HunterSecV1 — Ethics & Acceptable Use Policy

## 1. Tuyên ngôn

HunterSecV1 là công cụ **tấn công có đạo đức (ethical offensive security)**. Mục đích duy nhất hợp lệ:

- Học tập trong môi trường lab có ủy quyền (HackTheBox, TryHackMe, VulnHub, lab của riêng bạn).
- Tham gia CTF chính thức.
- Bug bounty trong phạm vi (scope) được nhà cung cấp chương trình công khai cho phép.
- Pentest có hợp đồng / Rules of Engagement (RoE) bằng văn bản.
- Đánh giá bảo mật trên hệ thống bạn sở hữu hoặc được uỷ quyền bằng văn bản.

## 2. Sử dụng bị cấm

Tuyệt đối **không** sử dụng HunterSecV1 cho:

- Truy cập trái phép vào bất kỳ hệ thống nào bạn không có quyền.
- DDoS, ransomware, data exfiltration ngoài lab, doxxing.
- Tấn công cơ sở hạ tầng trọng yếu (y tế, năng lượng, giao thông, tài chính, quân sự, chính phủ).
- Tấn công cá nhân, harassment, stalking.
- Trẻ em — bất kỳ liên quan nào đến CSAM.
- Bypass DRM, vi phạm bản quyền có chủ đích.
- Tạo, phát tán malware ngoài mục đích nghiên cứu trong sandbox.

## 3. Cam kết kỹ thuật

Dự án thực thi các biện pháp kỹ thuật để giảm thiểu lạm dụng:

1. **Scope guard mặc định bật.** Không thể chạy bất kỳ tool active nào mà thiếu `scope.yaml` valid.
2. **Blocklist commands phá hoại.** Patterns như `rm -rf /`, fork bomb, mass-DDoS tool flags bị chặn ở sandbox layer.
3. **Rate limit cứng.** Default 10 req/s/target, hard cap 100 req/s tổng — chặn accidental DoS.
4. **Audit log không tắt được.** Mọi action ghi JSONL hash-chained. Forensic-grade.
5. **Dry-run mặc định bật ở Bug Bounty mode.** User phải explicit `--execute`.
6. **Telemetry minimal.** Project KHÔNG gửi data ra ngoài máy user (no phone-home).

## 4. Trách nhiệm của người dùng

Sử dụng tool này, bạn **xác nhận**:

- Bạn đã đọc, hiểu, đồng ý với pháp luật khu vực bạn đang hoạt động (Computer Fraud and Abuse Act tại Mỹ, Luật An ninh mạng tại Việt Nam, Computer Misuse Act tại UK, v.v.).
- Bạn có giấy phép / hợp đồng / RoE / scope hợp lệ trước khi nhắm vào bất kỳ target nào.
- Bạn chịu trách nhiệm hoàn toàn về hậu quả pháp lý của hành động bạn thực hiện thông qua tool.
- Tác giả / contributor **không** chịu trách nhiệm cho việc sử dụng sai mục đích (xem `LICENSE`).

## 5. Báo cáo lạm dụng

Nếu bạn phát hiện ai đó sử dụng HunterSecV1 cho mục đích xấu, hoặc fork dự án thành công cụ có hại:

- Mở issue (public) với tag `abuse-report` nếu công khai.
- Email maintainer (xem `SECURITY.md`) cho báo cáo nhạy cảm.

## 6. Báo cáo lỗ hổng bảo mật của chính tool

Xem `SECURITY.md` cho responsible disclosure process.

## 7. Đóng góp có đạo đức

Pull request thêm capability **tấn công mới** phải đi kèm:

- Use case hợp pháp rõ ràng (CTF category nào, machine type nào, bug class nào).
- Test case trên target lab công khai (không demo trên hệ thống thật).
- Cập nhật scope guard / blocklist tương ứng nếu cần.
- Reviewer kiểm tra "có thể abuse dễ không?" — nếu yes, cần safeguard mạnh hơn hoặc reject.

## 8. Hành vi cộng đồng

Xem `CODE_OF_CONDUCT.md`. Tóm tắt: tôn trọng, học hỏi, không gatekeep.

---

**Vi phạm chính sách này có thể dẫn đến revoke quyền tham gia dự án.**
