"""Give AssetRipper's dummy shaders that have no source a working URP body.

A dummy keeps the real Properties block but draws every pixel white, so a Synty character is a white silhouette and
a full-screen blit whites out the screen. Run `udk.shaderremap` first; whatever dummy is left gets a body chosen by
its role, reading the material's own texture and colour properties so the saved material values still apply:

  lit      main texture x colour, main light with shadows, SH ambient, emission, alpha clip, fog; shadow/depth
           passes borrowed from URP Lit. Default for meshes (Synty, POLYGON, water).
  unlit    texture x colour x vertex colour, transparent, additive when the name says so. Particles, UI, holograms.
  sky      three-colour gradient from the sky/horizon/ground colours. Skybox shaders.
  sdf      text from a signed-distance atlas: face colour x vertex colour, edge at 0.5. TextMeshPro variants.
  blit     copies _MainTex. Hidden image effects that take a source texture.
  blitter  copies _BlitTexture with URP's full-screen triangle. Hidden renderer-feature passes (Blitter API).
  none     draws nothing. Hidden effects without a source texture, decals, volumetric fog.

This is an approximation of the look, not the original shader: the original is compiled DXBC in the game build. It
is marked in the file so a later pass can tell a synthesized body from a real one.

Usage: python -m udk.shadersynth <project Assets dir> [--dry]
"""
import os
import re
import sys
from collections import defaultdict

MARK = "//UdkSynthesizedShader"
PROP = re.compile(r'^\s*((?:\[[^\]]*\]\s*)*)(_?\w+)\s*\("[^"]*",\s*(2D|Color|Vector|Float|Range\([^)]*\)|Int)\)', re.M)
UNLIT = re.compile(r"particle|cartoon fx|ui/|additive|hologram|wipe|puls|noise|glow|tint", re.I)
NONE = re.compile(r"epo/|basicblit|partialblit|finalblit|transparentblit|^hidden/blur$|decal|fog|skyshadow|volumetric|lightbeam|fallbackerror|outline|obstacle|stencil|zprepass|dilate", re.I)
ADD = re.compile(r"add|glow|hologram|puls", re.I)
NORMAL = re.compile(r"normal|bump", re.I)
EMISSION = re.compile(r"emiss", re.I)
NOT_MAIN = re.compile(r"normal|bump|emiss|mask|metal|smooth|occlusion|noise|dissolve|distort|overlay|rust|blood|"
                      r"tats|twinkle|sun|moon|cloud|foam|caustic|lightofsight|lineofsight|texcoord|new", re.I)
MAIN_FIRST = re.compile(r"albedo|base|main|diffuse|leaf|face|tex", re.I)
COLOR_FIRST = re.compile(r"^_(base_?)?colou?r$|^_tint|^_maincolor$|^_leaf_base_color$|^_facecolor$", re.I)


def read(p):
    return open(p, encoding="utf-8", errors="replace").read()


def properties_end(text):
    i = text.index("Properties")
    i = text.index("{", i)
    depth = 0
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return j + 1
    raise ValueError("Properties block not closed")


def material_props(assets):
    """shader guid -> (texture names that hold a texture, colour names) over every material using it."""
    tex, col = defaultdict(set), defaultdict(set)
    for dirpath, _, files in os.walk(assets):
        for f in files:
            if not f.endswith(".mat"):
                continue
            t = read(os.path.join(dirpath, f))
            m = re.search(r"m_Shader: \{fileID: -?\d+, guid: (\w+)", t)
            if not m:
                continue
            g = m.group(1)
            for name, guid in re.findall(r"- (_?\w+):\s*\n\s*m_Texture: \{fileID: -?\d+(?:, guid: (\w+))?", t):
                if guid and guid != "0" * 32:
                    tex[g].add(name)
            colors = t.split("m_Colors:", 1)[1] if "m_Colors:" in t else ""
            col[g].update(re.findall(r"- (_?\w+): \{r:", colors))
    return tex, col


def role(name, props):
    if "TextMeshPro" in name:
        return "sdf"
    if name.startswith("Hidden/"):
        if NONE.search(name):
            return "none"
        return "blit" if "_MainTex" in props else "blitter"
    if NONE.search(name):
        return "none"
    if "sky" in name.lower():
        return "sky"
    if UNLIT.search(name):
        return "unlit"
    return "lit"


def pick(names, prefer, avoid=None):
    names = sorted(names)
    for n in names:
        if prefer.search(n) and not (avoid and avoid.search(n)):
            return n
    return next((n for n in names if not (avoid and avoid.search(n))), None)


HEAD = """			#include "Packages/com.unity.render-pipelines.universal/ShaderLibrary/Core.hlsl"
"""


def body(kind, name, tex, cols):
    main = pick(tex, MAIN_FIRST, NOT_MAIN)
    color = next((c for c in sorted(cols) if COLOR_FIRST.search(c)), None)
    emap = pick([t for t in tex if EMISSION.search(t)], EMISSION)
    ecol = next((c for c in sorted(cols) if EMISSION.search(c)), None)
    decl, cbuf = [], []
    if main:
        decl.append(f"TEXTURE2D({main}); SAMPLER(sampler{main});")
        cbuf.append(f"float4 {main}_ST;")
    if emap:
        decl.append(f"TEXTURE2D({emap}); SAMPLER(sampler{emap});")
    for c in {color, ecol} - {None}:
        cbuf.append(f"float4 {c};")
    if kind in ("lit", "unlit"):
        cbuf.append("float _Cutoff_Udk;")
    sample = f"SAMPLE_TEXTURE2D({main}, sampler{main}, i.uv)" if main else "half4(1, 1, 1, 1)"
    tint = f" * {color}" if color else ""
    uv = f"TRANSFORM_TEX(v.uv, {main})" if main else "v.uv"
    emission = (f"SAMPLE_TEXTURE2D({emap}, sampler{emap}, i.uv).rgb" if emap else "0") + (f" * {ecol}.rgb" if ecol and emap else "")
    if ecol and not emap:
        emission = f"{ecol}.rgb"
    hlsl_vars = "\n".join("\t\t\t" + d for d in decl) + "\n\t\t\tCBUFFER_START(UnityPerMaterial)\n" + \
        "\n".join("\t\t\t\t" + c for c in cbuf) + "\n\t\t\tCBUFFER_END\n"
    if kind == "none":
        return """	SubShader {
		Tags { "RenderType" = "Transparent" "Queue" = "Transparent" "RenderPipeline" = "UniversalPipeline" }
		Pass { ColorMask 0 ZWrite Off ZTest Always Cull Off }
	}
"""
    if kind == "blit":
        return f"""	SubShader {{
		Tags {{ "RenderPipeline" = "UniversalPipeline" }}
		Pass {{
			Cull Off ZWrite Off ZTest Always
			HLSLPROGRAM
			#pragma vertex vert
			#pragma fragment frag
{HEAD}			TEXTURE2D(_MainTex); SAMPLER(sampler_MainTex);
			struct A {{ float4 pos : POSITION; float2 uv : TEXCOORD0; }};
			struct V {{ float4 pos : SV_POSITION; float2 uv : TEXCOORD0; }};
			V vert(A v) {{ V o; o.pos = TransformObjectToHClip(v.pos.xyz); o.uv = v.uv; return o; }}
			half4 frag(V i) : SV_Target {{ return SAMPLE_TEXTURE2D(_MainTex, sampler_MainTex, i.uv); }}
			ENDHLSL
		}}
	}}
"""
    if kind == "blitter":
        return """	SubShader {
		Tags { "RenderPipeline" = "UniversalPipeline" }
		Pass {
			Cull Off ZWrite Off ZTest Always
			HLSLPROGRAM
			#pragma vertex Vert
			#pragma fragment frag
			#include "Packages/com.unity.render-pipelines.universal/ShaderLibrary/Core.hlsl"
			#include "Packages/com.unity.render-pipelines.core/Runtime/Utilities/Blit.hlsl"
			half4 frag(Varyings i) : SV_Target { return SAMPLE_TEXTURE2D_X(_BlitTexture, sampler_LinearClamp, i.texcoord); }
			ENDHLSL
		}
	}
"""
    if kind == "sdf":
        face = next((c for c in sorted(cols) if c.lower() == "_facecolor"), None)
        return f"""	SubShader {{
		Tags {{ "Queue" = "Transparent" "RenderType" = "Transparent" "IgnoreProjector" = "True" "RenderPipeline" = "UniversalPipeline" }}
		Pass {{
			Blend SrcAlpha OneMinusSrcAlpha
			ZWrite Off Cull Off
			HLSLPROGRAM
			#pragma vertex vert
			#pragma fragment frag
{HEAD}			TEXTURE2D(_MainTex); SAMPLER(sampler_MainTex);
			CBUFFER_START(UnityPerMaterial)
				{"float4 " + face + ";" if face else ""}
			CBUFFER_END
			struct A {{ float4 pos : POSITION; float2 uv : TEXCOORD0; float4 col : COLOR; }};
			struct V {{ float4 pos : SV_POSITION; float2 uv : TEXCOORD0; float4 col : COLOR; }};
			V vert(A v) {{ V o; o.pos = TransformObjectToHClip(v.pos.xyz); o.uv = v.uv; o.col = v.col; return o; }}
			half4 frag(V i) : SV_Target {{
				float d = SAMPLE_TEXTURE2D(_MainTex, sampler_MainTex, i.uv).a;
				float w = max(fwidth(d), 1e-4);
				half4 c = i.col{" * " + face if face else ""};
				return half4(c.rgb, c.a * smoothstep(0.5 - w, 0.5 + w, d));
			}}
			ENDHLSL
		}}
	}}
"""
    if kind == "sky":
        sky = next((c for c in sorted(cols) if c.lower() == "_skycolor"), None)
        hor = next((c for c in sorted(cols) if c.lower() == "_horizoncolor"), None)
        gnd = next((c for c in sorted(cols) if c.lower() == "_groundcolor"), None)
        dv = "\n".join(f"\t\t\t\tfloat4 {c};" for c in (sky, hor, gnd) if c)
        s, h, g = (c or d for c, d in ((sky, "float4(0.35, 0.55, 0.85, 1)"), (hor, "float4(0.8, 0.85, 0.9, 1)"),
                                       (gnd, "float4(0.35, 0.33, 0.3, 1)")))
        return f"""	SubShader {{
		Tags {{ "Queue" = "Background" "RenderType" = "Background" "PreviewType" = "Skybox" "RenderPipeline" = "UniversalPipeline" }}
		Pass {{
			Cull Off ZWrite Off
			HLSLPROGRAM
			#pragma vertex vert
			#pragma fragment frag
{HEAD}			CBUFFER_START(UnityPerMaterial)
{dv}
			CBUFFER_END
			struct A {{ float4 pos : POSITION; }};
			struct V {{ float4 pos : SV_POSITION; float3 dir : TEXCOORD0; }};
			V vert(A v) {{ V o; o.pos = TransformObjectToHClip(v.pos.xyz); o.dir = v.pos.xyz; return o; }}
			half4 frag(V i) : SV_Target {{
				float y = normalize(i.dir).y;
				float3 c = y > 0 ? lerp({h}.rgb, {s}.rgb, pow(saturate(y), 0.5)) : lerp({h}.rgb, {g}.rgb, saturate(-y * 4));
				return half4(c, 1);
			}}
			ENDHLSL
		}}
	}}
"""
    if kind == "unlit":
        blend = "Blend SrcAlpha One" if ADD.search(name) else "Blend SrcAlpha OneMinusSrcAlpha"
        return f"""	SubShader {{
		Tags {{ "Queue" = "Transparent" "RenderType" = "Transparent" "IgnoreProjector" = "True" "RenderPipeline" = "UniversalPipeline" }}
		Pass {{
			{blend}
			ZWrite Off Cull Off
			HLSLPROGRAM
			#pragma vertex vert
			#pragma fragment frag
			#pragma multi_compile_fog
{HEAD}{hlsl_vars}			struct A {{ float4 pos : POSITION; float2 uv : TEXCOORD0; float4 col : COLOR; }};
			struct V {{ float4 pos : SV_POSITION; float2 uv : TEXCOORD0; float4 col : COLOR; float fog : TEXCOORD1; }};
			V vert(A v) {{ V o; o.pos = TransformObjectToHClip(v.pos.xyz); o.uv = {uv}; o.col = v.col; o.fog = ComputeFogFactor(o.pos.z); return o; }}
			half4 frag(V i) : SV_Target {{
				half4 c = {sample}{tint} * i.col;
				return half4(MixFog(c.rgb, i.fog), c.a);
			}}
			ENDHLSL
		}}
	}}
"""
    cull = "Off" if re.search(r"foliage|leaf|plant|grass", name, re.I) else "Back"
    return f"""	SubShader {{
		Tags {{ "RenderType" = "Opaque" "Queue" = "Geometry" "RenderPipeline" = "UniversalPipeline" }}
		Pass {{
			Name "ForwardLit"
			Tags {{ "LightMode" = "UniversalForward" }}
			Cull {cull}
			HLSLPROGRAM
			#pragma vertex vert
			#pragma fragment frag
			#pragma multi_compile _ _MAIN_LIGHT_SHADOWS _MAIN_LIGHT_SHADOWS_CASCADE _MAIN_LIGHT_SHADOWS_SCREEN
			#pragma multi_compile_fragment _ _SHADOWS_SOFT
			#pragma multi_compile_fog
{HEAD}			#include "Packages/com.unity.render-pipelines.universal/ShaderLibrary/Lighting.hlsl"
{hlsl_vars}			struct A {{ float4 pos : POSITION; float3 n : NORMAL; float2 uv : TEXCOORD0; }};
			struct V {{ float4 pos : SV_POSITION; float2 uv : TEXCOORD0; float3 n : TEXCOORD1; float3 w : TEXCOORD2; float fog : TEXCOORD3; }};
			V vert(A v) {{
				V o; VertexPositionInputs p = GetVertexPositionInputs(v.pos.xyz);
				o.pos = p.positionCS; o.w = p.positionWS; o.n = TransformObjectToWorldNormal(v.n);
				o.uv = {uv}; o.fog = ComputeFogFactor(p.positionCS.z); return o;
			}}
			half4 frag(V i) : SV_Target {{
				half4 c = {sample}{tint};
				clip(c.a - 0.3);
				float3 n = normalize(i.n);
				Light l = GetMainLight(TransformWorldToShadowCoord(i.w));
				half3 lit = c.rgb * (l.color * saturate(dot(n, l.direction)) * l.shadowAttenuation + SampleSH(n)) + {emission};
				return half4(MixFog(lit, i.fog), 1);
			}}
			ENDHLSL
		}}
		UsePass "Universal Render Pipeline/Lit/ShadowCaster"
		UsePass "Universal Render Pipeline/Lit/DepthOnly"
		UsePass "Universal Render Pipeline/Lit/DepthNormals"
	}}
"""


def main(assets, dry=False):
    mtex, mcol = material_props(assets)
    counts = defaultdict(list)
    for dirpath, _, files in os.walk(assets):
        for f in files:
            p = os.path.join(dirpath, f)
            if not f.endswith(".shader") or not os.path.exists(p + ".meta"):
                continue
            text = read(p)
            if "DummyShaderTextExporter" not in text:
                continue
            name = re.search(r'Shader\s+"([^"]+)"', text).group(1)
            guid = re.search(r"^guid: (\w+)", read(p + ".meta"), re.M).group(1)
            end = properties_end(text)
            props = {m.group(2): m.group(3) for m in PROP.finditer(text[:end])}
            tex = {n for n, t in props.items() if t == "2D"} | mtex[guid]
            cols = {n for n, t in props.items() if t in ("Color", "Vector")} | mcol[guid]
            kind = role(name, props)
            # Names only the materials know must be declared, or the material value is not bound.
            extra = [f'\t\t{n} ("{n}", 2D) = "white" {{}}' for n in sorted(mtex[guid] - props.keys())]
            extra += [f'\t\t{n} ("{n}", Color) = (1,1,1,1)' for n in sorted(mcol[guid] - props.keys())]
            head = text[:end - 1].rstrip() + ("\n" + "\n".join(extra) if extra else "") + "\n\t}\n"
            counts[kind].append(name)
            if not dry:
                open(p, "w", encoding="utf-8", newline="\n").write(f"{head}\t{MARK} role={kind}\n{body(kind, name, tex, cols)}\tFallback Off\n}}\n")
    for k, v in sorted(counts.items()):
        print(f"shadersynth {k}: {len(v)} {sorted(v)}")


if __name__ == "__main__":
    main(sys.argv[1], "--dry" in sys.argv)
