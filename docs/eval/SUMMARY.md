# Review VOID DIVER: câu hỏi bản web phải đoán, trả lời bằng `udk`

83 câu `[SUY LUẬN]`/`[CHƯA RÕ]` trích từ bản web (`web_guessed.tsv`). Mỗi vòng do một subagent khác model
(sonnet) làm, chỉ được dùng `bin/udk` và dump `out/vd`. Chi tiết từng câu: `web_guessed_results_*.tsv`.

| Vòng | Kit lúc đó | Trả lời được (cộng dồn) | Ngoài phạm vi | Còn mở | Thiếu năng lực công cụ |
|---|---|---|---|---|---|
| 1 | q, method, type, refs | 25 | 12 | 46 | 6: không tra được người gọi, nối dây prefab, PlayerSettings, shader |
| 2 | + callers, prefab, settings, shader thật | 46 | 12 | 25 | 1: W039 (delegate, thân generic) |
| 3 | + xref mã máy, thân generic | 67 | 12 | 3 | 1: W078 (gọi qua sự kiện UI) |
| sau 3 | + callers: hàm gộp, hàm không tên, listener UnityEvent | | | | |
| 4 (11 câu) | như trên | 3/11 | 0 | 7 | 1: W078 |
| 5 (đủ 83, câu hỏi đã sửa) | + retype, callers giải thích kết quả rỗng, shader cạnh material | 39 | 13 | 27 | 4: W026, W040, W074, W082 |
| sau 5 | + callers qua interface (slot vtable), method chỉ field thật của thân gộp, `udk objects` | | | | |
| 6 (9 câu còn vướng) | như trên | 7/9 | 0 | 2 | 0 (W064 lộ ra field đọc qua `p[2].klass`, đã sửa retype) |
| **7 (đủ 83, 3 reviewer mới)** | + retype nhãn bị cắt / `Object[k]`, `udk asset`, `q -k native` | **51** | **12** | **20** | **0** |

**Vòng 7 sạch: không câu nào thiếu năng lực công cụ.** 20 câu "một phần" thiếu thứ không có trong client (code engine Unity
đóng, thông số chỉ bản web tự đặt) hoặc reviewer chưa nối được ghi chú web với bảng cụ thể. Sau vòng: `method` nhận tên
hàm sinh bởi compiler dạng C (`_OnStageStarted_b__39_1`), `q -k` nhận danh sách, CLI không báo BrokenPipe khi pipe vào `head`.

**Lỗi bộ câu hỏi (phát hiện ở vòng 4).** 53/83 câu trong `web_guessed.tsv` chỉ giữ dòng đầu của mục, có câu
cắt giữa ký tự UTF-8 (W051 chỉ còn "Luật viền."). Vòng 1–4 chấm trên câu cụt nên số liệu của chúng không so
được với vòng 5. Đã trích lại nguyên mục kèm các dòng con.

**Vòng 5.** PARTIAL phần lớn là chỗ reviewer chưa đọc hết thân hàm (công cụ đã chỉ tới) hoặc ghi chú web có
phần là lựa chọn riêng của bản web. Chỗ thiếu năng lực thật đã sửa sau vòng: lời gọi qua interface (W074, W082:
`GameObjectManager.OnStartInteraction` đọc `InteractionSfx` qua slot 5, rỗng thì không phát gì), thân hàm gộp in
nhầm tên (W082), tìm GameObject theo tên (W070). W026 và W040: field chỉ được `Parse`/`ToCsv` chạm tới, công cụ
giờ nói rõ đã tra những đâu.

Sau vòng 3, `udk callers` sửa lỗi reviewer chỉ ra (dòng "binary only" gắn sai tên do hàm gộp và hàm không tên)
và thêm listener UnityEvent trong prefab. W064 và W074 có lời đáp "không dùng": `AnomalyGroupSpawnId` chỉ được
`Parse`/`ToCsv` chạm tới, hằng `LOOTING_COMPLETED` không có tham chiếu nào.

# Review Zing Speed: câu hỏi bản web `games/toc-do` phải đoán, trả lời bằng `udk`

47 câu (`zs_guessed.tsv`). Mỗi vòng do subagent sonnet làm, chỉ dùng `bin/udk` và dump `out/zs`.

| Vòng | Kit lúc đó | Trả lời được | Một phần | Ngoài phạm vi | Thiếu năng lực công cụ |
|---|---|---|---|---|---|
| 1 | decomp lát gameplay trên binary đã gỡ bảo vệ, `native/`, retype | 5 | 27 | 10 | 5: Z002 (shader), Z010 (localization), Z021 (va chạm Havok), Z032 (transform), Z039 (thân method ngoài lát) |
| sau 1 | + shader blob Zstandard → GLSL, `udk asset` (YAML thô, kích thước ảnh), `method`/`q` tìm cả native, export một lệnh → thân hàm qua PLT, decomp toàn bộ NssMain (đang chạy) | | | | |

Nhiều câu "một phần" là dữ liệu server hoặc bank âm thanh không có trong APK; phần còn lại cần thân method ngoài lát
gameplay (NssMain đầy đủ đang dịch). Va chạm Havok (`NssHKXData_V00`, tagfile Havok 2014) chưa có bộ đọc.
