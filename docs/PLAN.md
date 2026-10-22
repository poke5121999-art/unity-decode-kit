# unity-decode-kit — khung việc

Yêu cầu của chủ máy: "nghiên cứu làm 1 tool decode hiệu quả hơn, không còn cần phải dùng video + wiki nữa."
Phiếu gốc: `~/handoff/2026-10-22-unity-decode-tool.md`.

## Định nghĩa xong (đo được, sai thì thấy)

1. **Data.** Trên VOID DIVER, tool tự đoán khoá và giải ra mọi bảng và Lua, khớp từng byte với `~/vd-src/vd-ref/tables` và `lua`. Không ghi khoá cứng.
2. **Code.** Thân method của assembly game đọc được dạng pseudocode C có tên field, tên method gọi tới, chuỗi literal. Đo bằng: trong 91 mục `[SUY LUẬN]`/`[CHƯA RÕ]` của bản web (`survivor-web-hub/games/voiddiver/docs`, `tools/*.md`), lấy mẫu và đếm bao nhiêu mục trả lời được bằng output của tool, kèm trích dẫn.
3. **Asset.** Mọi loại asset trong `vd-ref/ASSETS.md` có trong dump, kèm đồ thị tham chiếu trả lời được câu kiểu "prefab nào dùng clip X".
4. **Truy vấn.** Một lệnh `udk q <regex>` tìm cùng lúc trong code, chuỗi, asset, data. Agent trả lời được câu hỏi mà không cần xem video.
5. **Game thứ hai.** Cùng pipeline chạy hết trên `~/sk86-ref` (Android, libil2cpp.so arm64).
6. **Runtime (tuỳ chọn).** Khả thi hay không của hook lúc chạy, nói rõ bằng thử nghiệm thật.

## Thứ tự (rủi ro cao làm trước)

1. Khảo sát công cụ có sẵn trên VOID DIVER: Il2CppInspectorRedux, Cpp2IL, AssetRipper, Ghidra.
2. Code: Il2CppInspector + Ghidra headless → pseudocode cho assembly game.
3. Asset: AssetRipper export → chỉ mục + đồ thị tham chiếu.
4. Data: dò wrapper (XOR 1 byte, LZ4, gzip, AES) tự động.
5. Chỉ mục + lệnh truy vấn.
6. Chấm điểm theo các mục trên, ghi số.
7. Chạy lại trên sk86.
8. Runtime hook: thử, báo khả thi.

Nhật ký quyết định: `docs/decisions.tsv`.

## Việc còn lại (cập nhật 2026-10-22 20:40)

Theo yêu cầu của chủ máy: làm đủ mọi năng lực, vòng đo → sửa → đo lại, reviewer độc lập cuối cùng.

- VOID DIVER: build lại đầy đủ (assembly trả phí, sửa tail call) → chấm 83 mục `[SUY LUẬN]`/`[CHƯA RÕ]` bằng subagent chỉ dùng `udk` → sửa hổng → lặp.
- Shader: AssetRipper Free chỉ ra shader rỗng. VOID DIVER là DXBC (D3D11, platform 4); Zing Speed là GLES. Hướng: DXBC → HLSL (3Dmigoto cmd_Decompiler dưới wine, hoặc vkd3d-shader → SPIR-V → SPIRV-Cross); GLSL → SPIR-V (glslang) → HLSL (SPIRV-Cross); bọc lại thành ShaderLab theo property/binding trong asset Shader.
- Plugin native (`libNssPhysicsPlugin.so` của Zing Speed): Ghidra auto-analysis có symbol export.
- Runtime: chạy thử `udk trace` với game thật (VOID DIVER qua Proton của phiên anh em, `-batchmode -nographics`).
- Zing Speed → project Unity 6000.3.18f1 chơi được: export, bước nâng cấp 2019.4 → 6 tổng quát (API updater, pipeline, package), ghi lại thứ vỡ và cách kit sửa.
- Soul Knight 8.6: chạy toàn bộ pipeline, chấm data với `~/sk86-ref/decoded/config`.
