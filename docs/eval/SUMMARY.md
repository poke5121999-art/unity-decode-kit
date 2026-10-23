# Review VOID DIVER: câu hỏi bản web phải đoán, trả lời bằng `udk`

83 câu `[SUY LUẬN]`/`[CHƯA RÕ]` trích từ bản web (`web_guessed.tsv`). Mỗi vòng do một subagent khác model
(sonnet) làm, chỉ được dùng `bin/udk` và dump `out/vd`. Chi tiết từng câu: `web_guessed_results_*.tsv`.

| Vòng | Kit lúc đó | Trả lời được (cộng dồn) | Ngoài phạm vi | Còn mở | Thiếu năng lực công cụ |
|---|---|---|---|---|---|
| 1 | q, method, type, refs | 25 | 12 | 46 | 6: không tra được người gọi, nối dây prefab, PlayerSettings, shader |
| 2 | + callers, prefab, settings, shader thật | 46 | 12 | 25 | 1: W039 (delegate, thân generic) |
| 3 | + xref mã máy, thân generic | 67 | 12 | 3 | 1: W078 (gọi qua sự kiện UI) |
| sau 3 | + callers: hàm gộp, hàm không tên, listener UnityEvent | | | | |

Sau vòng 3, `udk callers` sửa lỗi reviewer chỉ ra (dòng "binary only" gắn sai tên do hàm gộp và hàm không tên)
và thêm listener UnityEvent trong prefab. W064 và W074 có lời đáp "không dùng": `AnomalyGroupSpawnId` chỉ được
`Parse`/`ToCsv` chạm tới, hằng `LOOTING_COMPLETED` không có tham chiếu nào.
