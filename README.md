# unity-decode-kit

Bóc một bản build game Unity IL2CPP thành một bản dump chữ, tra được bằng lệnh, để trả lời câu hỏi về luật chơi, con số, thời gian, asset mà không phải xem clip hay đọc wiki.

Kit không viết lại công cụ đã chạy tốt. Nó ghép chúng lại và lấp chỗ trống:

| Phần | Công cụ có sẵn | Phần kit tự làm |
|---|---|---|
| Kiểu, field, offset, địa chỉ method | Il2CppInspectorRedux (đọc được metadata v39 của Unity 6000.3) | |
| Thân method | Ghidra 12 headless | Nạp header C + tên của Il2CppInspector vào Ghidra, chỉ gán chữ ký đầy đủ cho assembly của game; decompile song song ra một file `.c` mỗi kiểu; đặt tên helper runtime IL2CPP theo dáng lời gọi (`udk/code.py`) |
| Asset, prefab, scene | AssetRipper (xuất Unity project) | Đồ thị tham chiếu `assets/refs.tsv`: asset nào dùng asset nào, qua field nào (`udk/assets.py`) |
| Bảng, script, blob mã hoá | | Dò wrapper XOR 1 byte, XOR khoá lặp lấy từ string literal trong code, gzip/zlib/LZ4 (`udk/data.py`) |
| Truy vấn | ripgrep | `udk q / method / type / refs` |

## Dùng

```sh
./tools/setup.sh                      # tải công cụ vào third_party/ (không commit)
bin/udk build "<thư mục game>" out/<tên>
export UDK_DUMP=$PWD/out/<tên>
bin/udk q 'SkipHold'                  # tìm khắp code, kiểu, data, asset
bin/udk method 'CutscenePanelPresenter.<Start>b__2_0'
bin/udk type CutscenePanelView
bin/udk refs 'Diveloading'
```

Đọc `out/<tên>/INDEX.md` để biết dump có gì.

## Kết quả đo

Xem `docs/RESULTS.md`.
