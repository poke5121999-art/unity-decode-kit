# Bàn giao: unity-decode-kit (dừng vì hạn mức phiên 97%, 2026-10-22 ~20:35 +07)

Repo `~/unity-decode-kit`, nhánh `main` (đã push tới commit cuối). Phiếu gốc: `~/handoff/2026-10-22-unity-decode-tool.md`,
nghiệm thu Zing Speed: `~/handoff/2026-10-22-zingspeed-unity.md`. Tiến độ: `~/handoff/unity-decode-kit-STATUS.md`.
Nhật ký: `docs/decisions.tsv`. Việc còn lại: `docs/PLAN.md` mục "Việc còn lại". Session gốc: eb25b789-19e3-4dfe-8fca-261e6301ea3a.

## Job nền đang chạy (không cần token)
- `out/build-vd.log`: `udk build` VOID DIVER đầy đủ; đang ở bước Ghidra decompile (`out/vd/ghidra/decompile.log`, ~2400/4968 kiểu lúc dừng).
  Xong thì có `out/vd/code/methods.tsv`, helper runtime đã đặt tên, `out/vd/INDEX.md`.
- `out/build-zs.log`: Zing Speed bước Il2CppInspector (xếp hàng `heavy.sh` sau Ghidra). Metadata đã được `udk/metadata.py` sửa.

## Bước tiếp theo, theo thứ tự
1. Kiểm hai log trên. VD: `UDK_DUMP=$PWD/out/vd bin/udk method 'CutscenePanelPresenter.<Start>b__2_0'` phải KHÔNG còn thân `GameObject.SetActive` (lỗi tail call đã sửa). Cập nhật ghi chú cho phiên anh em `~/handoff/2026-10-22-decode-kit-notes-for-void-diver-unity.md` dòng "Sẵn sàng".
2. Chấm VD: `python tools/score_vd_data.py out/vd/data/StreamingAssets ~/vd-src/vd-ref` (đường dẫn data giờ có tiền tố StreamingAssets/), `python tools/score_vd_assets.py out/vd`. Rồi subagent (model khác) trả lời `docs/eval/web_guessed.tsv` chỉ bằng `bin/udk`, ghi kết quả, sửa hổng, lặp.
3. Zing Speed: `bin/udk build ~/zingspeed-ref/dl/zingspeed.xapk out/zs` (bước assets cần min-free cao, ~12 GB). Âm thanh đã thử: 1127/1127 wem, mới 235 event có tên (bản tay 1265) → thêm nguồn tên từ asset export. Lua: `udk/luadec.py` giải 19/19 mẫu.
4. Shader: nguyên mẫu DXBC → HLSL qua 3Dmigoto `third_party/cmd_decompiler` dưới wine chạy được; UnityPy `export/ShaderConverter.py` đã có bộ đọc blob subprogram (keyword + bytecode) để dựa vào. Viết `udk/shaders.py`.
5. Project Unity Zing Speed ở `~/zingspeed-unity` (Unity 6000.3.18f1, mọi job Unity qua `~/handoff/heavy.sh`).

## Cách kiểm là xong
Xem "Định nghĩa xong" trong `docs/PLAN.md` và yêu cầu chủ máy trong STATUS (vòng review tới khi sạch, reviewer độc lập cuối).
