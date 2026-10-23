# unity-decode-kit

Bóc một bản build game Unity IL2CPP thành một bản dump chữ, tra được bằng lệnh, để trả lời câu hỏi về luật chơi, con số, thời gian, asset mà không phải xem clip hay đọc wiki.

Kit không viết lại công cụ đã chạy tốt. Nó ghép chúng lại và lấp chỗ trống:

| Phần | Công cụ có sẵn | Phần kit tự làm |
|---|---|---|
| Kiểu, field, offset, địa chỉ method | Il2CppInspectorRedux (đọc được metadata v39 của Unity 6000.3) | |
| Thân method | Ghidra 12 headless | Nạp header C + tên của Il2CppInspector vào Ghidra, chỉ gán chữ ký đầy đủ cho assembly của game; decompile song song ra một file `.c` mỗi kiểu; đặt tên helper runtime IL2CPP theo dáng lời gọi (`udk/code.py`) |
| Asset, prefab, scene | AssetRipper (xuất Unity project) | Đồ thị tham chiếu `assets/refs.tsv`: asset nào dùng asset nào, qua field nào (`udk/assets.py`) |
| Bảng, script, blob mã hoá | | Dò wrapper XOR 1 byte, XOR khoá lặp lấy từ string literal trong code, gzip/zlib/LZ4 (`udk/data.py`) |
| Shader | | Blob DXBC (D3D11) và GLES (LZ4 hoặc Zstandard ở engine Tencent đã vá) ra từng chương trình (`udk/shaders.py`) |
| Collision Havok | | Tagfile nhị phân Havok 2014 trong field `HKXData` ra lưới `.obj` (`udk/havok.py`) |
| Behavior tree | | BSON của Tencent behaviac ra XML (`udk/behaviac.py`) |
| Plugin native | Ghidra 12 headless | Chọn `.so` theo tên `extern` trong code C#, decompile, gắn export thunk (`udk/native.py`) |
| Kiểu trả về của code generic dùng chung | | Ghi chú field thật vào chỗ Ghidra gọi nhầm `max_length`, `klass` (`udk/retype.py`) |
| Runtime | Frida gadget | `udk trace` sinh script hook method, log field của `this` ra JSONL; `tools/runtime/wine-run.sh` chạy game Windows dưới wine |
| Truy vấn | ripgrep | `udk q / method / type / refs / callers / prefab / asset / objects` |

## Dùng

```sh
./tools/setup.sh                      # tải công cụ vào third_party/ (không commit)
bin/udk build "<thư mục game>" out/<tên>
export UDK_DUMP=$PWD/out/<tên>
bin/udk q 'SkipHold'                  # tìm khắp code, kiểu, data, asset
bin/udk method 'CutscenePanelPresenter.<Start>b__2_0'
bin/udk type CutscenePanelView
bin/udk refs 'Diveloading'
bin/udk callers UnitModel.GetModifiedBuffDuration   # ai gọi method, ai đọc/ghi field
bin/udk prefab IntroTimelineObject    # cây GameObject, component, field trỏ tới đâu
bin/udk settings PlayerSettings ColorSpace
python -m udk.unity <ExportedProject> <project mới> 6000.3.18f1   # nâng project lên Unity mới
bin/udk trace 'SteamStorage\.' -o /tmp/rt/trace.js --log /tmp/rt/trace.jsonl   # hook lúc chạy
tools/runtime/wine-run.sh <bản sao thư mục game> "Game.exe" /tmp/rt/trace.js 180
```

Đọc `out/<tên>/INDEX.md` để biết dump có gì.

## Kết quả đo

Xem `docs/RESULTS.md`.
