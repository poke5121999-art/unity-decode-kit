# Dựng lại thân method C# compile được cho game IL2CPP

Bản dump của kit (Ghidra + Il2CppInspector) cho đọc được logic, nhưng không cho chạy được. Il2CppDumper,
AssetRipper và Cpp2IL ra thân method rỗng hoặc `throw null`. il2csharp ra C# có thân nhưng đầy số học con trỏ
nên không compile. Pipeline này đẩy trần đó: mỗi method được dịch lại thành C# managed, rồi bị ba thứ kiểm
độc lập. Thứ nhất là compiler. Thứ hai là danh sách lời gọi đọc từ chính mã máy. Thứ ba là game gốc chạy thật
qua BepInEx.

Mọi con số dưới đây đo bằng các lệnh trong mục "Chạy". Chạy lại các lệnh đó sẽ ra lại số.

## Dữ liệu đi qua các bước

Mỗi bước ghi một file JSONL, các file nối nhau bằng cùng một khoá method:
`Namespace.Type/Nested`N::TênMetadata(KiểuThamSốNgắn,...)`. Đây là dạng mà `Keys.Method` của Oracle viết
cho symbol của skeleton. Producer chỉ cần ra khoá gần đúng, vì Oracle ghép lỏng (`<X>d__3` với `_X_d__3`,
`Action_1` với `Action`).

| File | Nội dung | Do ai ghi |
|---|---|---|
| `skel/<asm>/` | C# của stub DLL (ILSpy), đã repair cho compile sạch | `prep` |
| `keys.<asm>.tsv` | mọi thân method trong skeleton (mẫu số) | `prep` |
| `decls.<asm>.jsonl` | khai báo từng type đã bỏ thân (context cho người dịch) | `prep` |
| `ghidra.jsonl` | pseudo-C của Ghidra cho từng method | `prep` |
| `slots.json` | thứ tự method của mọi interface (để đặt tên lời gọi theo slot) | `prep` |
| `native_calls.jsonl` | lời gọi trực tiếp đọc từ mã máy, cộng lời gọi interface theo slot | `udk.nativecalls` |
| `callees.json` | callee của mọi hàm trong binary (mở inline một tầng) | `udk.nativecalls` |
| `listings.jsonl` | disassembly của method mà Ghidra làm rơi tham số hàm CRT | `udk.nativecalls` |
| `mathnames.json` | tên hàm toán C runtime nhận ra bằng giả lập (`sinf`, `log10f`, `fmodf`...) | `udk.mathnames` |
| `cand.<src>.<asm>.jsonl` | thân C# ứng viên của một producer | `baseline`, `llm`, `testfix` |
| `res.<src>.<asm>.jsonl` | phán quyết của Oracle cho từng ứng viên, kèm tập hàm thân đó gọi tới | Oracle `compile` |
| `emit/best/<asm>.dll` | skeleton cộng mọi thân tốt nhất, DLL thật cắm được vào project Unity | `assemble` |

## Ba lớp kiểm

1. **Compile.** `tools/recompile/Oracle compile` cắm các thân ứng viên vào skeleton, compile cả assembly bằng
   Roslyn với reference của game. Nó quy từng lỗi về method gây ra lỗi, gỡ thân đó, rồi compile lại tới khi
   sạch. Ứng viên còn lại là compile được trong đúng ngữ cảnh của game. Lỗi gắn ở tên method (CS0161) cũng
   được quy về đúng method, vì annotation phủ cả khai báo member.
2. **Trung thực.** Từ mỗi thân compile được, Oracle xuất tập method mà nó gọi (IOperation). `score` so tập này
   với các lời gọi trong mã máy gốc. Một lời gọi C# được tính cho các callee mà C++ đã inline vào nó (một
   tầng). `Start` của async builder được tính cho `MoveNext`. Tên quá phổ biến (`.ctor`, `Add`) không được
   khớp chỉ theo tên. Thân có từ 80% lời gọi native trở lên được tính là trung thực.
3. **Chạy thật.** Plugin `tools/runtime-probe` (BepInEx 6 IL2CPP) gọi method gốc trong game với một bộ input
   rồi ghi kết quả. `difftest` emit DLL đã dựng lại, chạy cùng bộ input trên .NET 8 và so từng kết quả.
   `testfix` đưa các ca lệch cho người dịch sửa, và chỉ giữ bản mới nếu nó khớp nhiều ca hơn.

## Kết quả đo được (2026-10-24)

The Walking Trade v1.1.13 (Unity 6000.0.58f2, x64, metadata v31), năm assembly của studio:

| Đo gì | Kết quả |
|---|---|
| Khai báo: type có tên của metadata có trong skeleton | 100%. Chỉ thiếu 70 type do compiler sinh, như `<PrivateImplementationDetails>` và state machine của lambda async (`udk.declcov`) |
| Asset: tham chiếu `m_Script` resolve được về DLL | 33.466/33.466 |
| il2csharp, thân compile được (managed) | 3.998/14.194 (28,2%) |
| LLM (haiku), mẫu 120 method il2csharp không compile được | 114/120 compile, độ trung thực 87% |
| LLM trên toàn bộ, 1.364 method đầu tiên | 97,4% compile, 92,6% trung thực (đo trước khi sửa lỗi đọc thiếu `.pdata`, xem mục bẫy) |
| 12 method thuần, so với game gốc qua BepInEx | il2csharp 8/12 · LLM 10/12 · thêm tên CRT 239/246 call · sau `testfix` 246/246 call, 12/12 method |
| Native coverage (thân compile được hoặc compiler tự sinh theo khai báo) | cập nhật khi chạy xong `llm_all.sh` |

Tái dùng trên game thứ hai, VOID DIVER demo (Unity 6000.3, metadata v39, dump dựng trên linux): `prep` cho
3 assembly sạch lỗi gốc (`De.Scenes` và `De.Base` 0 lỗi, `De.InGame` 28 lỗi). Mẫu 60 method có 57 compile
được, độ trung thực 22/24. Muốn tới được đó phải vá ba lỗi tổng quát: thứ tự reference, repair lặp vô hạn,
và tên file chứa `|` từ dump linux.

## Chạy

```sh
# 1. config theo game (đường dẫn dump udk, thư mục Plugins của AssetRipper DllExport, binary, Unity, assembly studio)
cat > game.json <<'EOF'
{"name": "...", "work": "D:/x/recompile", "udk_dump": "D:/x/out", "plugins": "D:/x/unity-dll/ExportedProject/Assets/Plugins",
 "unity_data": "C:/Program Files/Unity/Hub/Editor/6000.0.77f1/Editor/Data", "binary": "D:/x/game/GameAssembly.dll",
 "il2csharp": "D:/x/il2csharp-out", "assemblies": ["Runtime", "Assembly-CSharp"]}
EOF
py -3.12 -m udk.recompile game.json prep          # skeleton + repair + index + decls + ghidra + slots + offsets + strings
py -3.12 -m udk.mathnames game.json               # tên hàm toán CRT bằng giả lập
py -3.12 -m udk.nativecalls game.json             # ground truth lời gọi + listing
py -3.12 -m udk.recompile game.json baseline      # (nếu có il2csharp) chấm il2csharp
sh tools/recompile/llm_all.sh game.json haiku Runtime Assembly-CSharp   # dịch mọi method còn thiếu, chạy tiếp được nếu ngắt
py -3.12 -m udk.recompile game.json score il2csharp,llm                 # SCORE.md
py -3.12 -m udk.recompile game.json assemble il2csharp,llm out/dlls     # DLL cắm vào project Unity
# chạy thật: cài BepInEx + tools/runtime-probe (README ở đó), chế độ invoke với một bộ input, rồi
py -3.12 -m udk.recompile game.json difftest Runtime llm inputs.jsonl invoke-out-original.jsonl
py -3.12 -m udk.recompile game.json testfix  Runtime llm inputs.jsonl invoke-out-original.jsonl
```

Người dịch là `claude -p` (CLI đăng nhập sẵn, không dùng tool, prompt hệ thống riêng). Mỗi prompt gom các
method của cùng một type. Vòng 2 và 3 sửa theo lỗi compiler, hoặc theo danh sách lời gọi native còn thiếu.
Chi phí đo được với haiku là khoảng 13k token vào cộng 3k token ra mỗi method, cỡ 0,002 USD theo giá list.

## Bẫy đã gặp

- **`.pdata` của MSVC chia một hàm thành nhiều đoạn.** Lấy biên hàm theo `.pdata` sẽ cắt hàm ở đoạn đầu, làm
  sót 28% lời gọi (40.637 so với 51.988). Ground truth thiếu thì độ trung thực bị đo cao hơn thực tế. Cách
  đúng là đọc tới method kế tiếp, và dừng ở padding `int3` khi đã qua đoạn đầu.
- **Lỗi CS0161 nằm ở tên method chứ không nằm trong thân.** Nếu annotation chỉ phủ khối thân, oracle không quy
  được lỗi này và đếm thân đó là "ok", tới lúc emit mới vỡ. Phải luôn emit DLL thật để kiểm.
- **Game ship `mscorlib` đã bị strip** (thiếu ctor của `StructLayoutAttribute`). Reference BCL đầy đủ phải đứng
  trước DLL của game.
- **Stub DLL làm mất backing field của field-like event,** nhưng accessor vẫn giữ `[CompilerGenerated]`. Repair
  đổi các event đó về `event T X;`. Riêng The Walking Trade được 381 event, tức 762 thân add/remove đúng y gốc.
- **ILSpy bỏ constructor chỉ chứa khởi tạo field.** Oracle chèn lại ctor/cctor khi có ứng viên nhắm tới nó. Mẫu số
  chỉ tính các ctor này khi mã máy có hàm đó.
- **Lời gọi interface trong mã máy là gián tiếp** (`Invoker(slot, TypeInfo_IFace, obj)`). Thứ tự method trong stub
  DLL cho ra tên. Bước này thêm 1.670 lời gọi vào ground truth.
- **Ghidra làm rơi tham số xmm của hàm CRT.** `log10f(max(1, value))` hiện ra thành `FUN_x()`. Prompt phải kèm
  disassembly.
- **il2csharp biến lời gọi base thành đệ quy.** Mã máy gọi `ItemData.OnValidate` không qua virtual, il2csharp viết
  `this.OnValidate()`. Bản này compile được, khớp tên với native, và chỉ lộ khi Unity import asset mới chết vì
  `StackOverflowException`. Luật hiện tại: thân tự gọi mình mà native không gọi thì độ trung thực bằng 0, và
  `assemble` loại thân đó (37 thân, 34 trong số đó của il2csharp).
- **Method gốc có thể lặp vô hạn với input xấu** (`CountBits(-1)` dịch phải số học). Bản dựng lại treo y như gốc,
  nên harness cần timeout cho từng call, và plugin cần danh sách `skip`.

## Chưa làm được

- **3D trong project dựng lại.** AssetRipper bản free xuất shader dummy (88/88 shader của The Walking Trade). Shader
  URP phải trỏ về package URP thật. Shader của asset bên thứ ba (CFXR, Stylized Water 2, VLB) cần nguồn hoặc phải
  giải mã DXBC.
- **Thư viện trả phí chỉ có ở dạng IL2CPP** (Rewired, I2 Localization). Hai thư viện này chưa nằm trong phạm vi dịch.
