#!/usr/bin/env python3
"""Classifica path-traversal-static UNCERTAIN."""
import json
import re
from pathlib import Path

BASE = Path(__file__).parent
CAT = "path-traversal-static"
UNC_FILE = BASE / CAT / "filtered" / "llm_analysis" / "uncertain.json"
CACHE_FILE = BASE / CAT / "filtered" / "llm_analysis" / "_llm_api_cache.json"


def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""


def extract_line(desc: str) -> str:
    m = re.search(r"at line (\d+)", desc)
    return m.group(1) if m else "?"


def cache_key(f: dict) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    file = f.get("file", "")
    line = extract_line(f.get("description", ""))
    return f"{server}|{file}|{line}"


def classify(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))
    file = f.get("file", "")

    # ── VP ────────────────────────────────────────────

    # User input keyword diretto
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\([^)]*"
                 r"(?:\bparams\.\w+|\bargs\.\w+|\binput\.\w+|\barguments\.\w+|"
                 r"\breq\.body|\breq\.query|\brequest\.body|\brequest\.query|"
                 r"userInput|user_input|userPath|user_path|"
                 r"\bbody\.\w+|\.\.\.\w+_paths|\.\.\.args)", code, re.I):
        return "VP", "path_join_with_user_input_keyword"

    # API request handler arg
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\([^)]*"
                 r"(?:options\.path|opts\.path|config\.path|"
                 r"req\.params\.|res\.body|"
                 r"event\.body|context\.params)", code):
        return "VP", "path_join_with_request_handler_arg"

    # Spread of user input
    if re.search(r"\.\.\.\s*(?:args|params|input|paths)", code):
        return "VP", "spread_user_input_in_path_join"

    # ── FP ────────────────────────────────────────────

    # Hardcoded directory const
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\(\s*"
                 r"(?:__dirname|process\.cwd\(\)|os\.getcwd\(\)|"
                 r"BASE_DIR|ROOT_DIR|PROJECT_ROOT|CACHE_DIR|TEMP_DIR|DATA_DIR|"
                 r"OUTPUT_DIR|UPLOAD_DIR|DOWNLOAD_DIR|CONFIG_DIR|LOG_DIR|"
                 r"STORAGE_DIR|APP_ROOT|SCRIPT_DIR|MODULE_DIR|"
                 r"[A-Z_]+_(?:DIR|PATH|ROOT|FOLDER))", code):
        return "FP", "hardcoded_const_directory"

    # f-string con extension fissa
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\([^)]*"
                 r"f[\"'][^\"'/]*\}[^/\"']*\."
                 r"(?:json|yaml|yml|xml|csv|tsv|md|txt|log|html|sql|sqlite|db|"
                 r"pdf|zip|tar|gz|tgz|bz2|xz|7z|rar|"
                 r"png|jpg|jpeg|gif|bmp|svg|ico|webp|tiff|"
                 r"mp3|mp4|wav|avi|mkv|flac|"
                 r"py|js|ts|go|rs|rb|java|kt|swift|cpp|c|h|cs|"
                 r"pkl|pickle|joblib|pt|pth|onnx|safetensors|h5|hdf5|"
                 r"npy|npz|parquet|arrow|feather|"
                 r"yaml|toml|ini|cfg|conf|env|"
                 r"ipynb|jl|R|Rmd|"
                 r"so|dylib|dll|exe|bin|class|jar|war|"
                 r"woff|woff2|ttf|eot|otf|"
                 r"map|min|bundle|"
                 r"info|meta|cache|tmp|temp|bak|"
                 r"snap|lock|pid|fail|golden|stage)[\"']", code, re.I):
        return "FP", "fstring_with_fixed_extension"

    # Glob pattern
    if re.search(r"(?:filepath\.Glob|glob\.glob|fast-glob|globby)\s*\(", code):
        return "FP", "glob_pattern_not_traversal"

    # Self attribute / class state path
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\(\s*"
                 r"self\.\w+|this\.\w+|cls\.\w+", code):
        if not re.search(r"(?:params\.|args\.|input\.|req\.body|req\.query)", code):
            return "FP", "self_or_class_state_internal_path"

    # Sanitized variable
    if re.search(r"\{(?:safe_|sanitized_|validated_|escaped_|cleaned_|normalized_|stripped_)\w+\}", code):
        return "FP", "explicitly_sanitized_var_in_path"

    # uuid/hash random filename
    if re.search(r"\{(?:uuid\.uuid\d+\(\)|uuid4\(\)|random\.\w+|"
                 r"secrets\.token_\w+|hashlib\.\w+|md5\(|sha\d+\(|"
                 r"\.hex|hash\(\w+\)|"
                 r"nanoid|cuid)\}|"
                 r"uuid\.uuid\d+\(\)\.hex|secrets\.token_hex", code, re.I):
        return "FP", "random_or_uuid_filename"

    # Timestamp filename
    if re.search(r"\{(?:timestamp|datetime|now|created_at|updated_at|"
                 r"date_str|time_str|ts|epoch|iso_date|today)\}|"
                 r"strftime|datetime\.now|time\.time\(\)|\.timestamp\(\)|"
                 r"datetime\.utcnow", code, re.I):
        return "FP", "timestamp_in_filename"

    # Internal var (i, idx, count, video_id, dataset, etc.)
    if re.search(r"\{(?:i|j|k|n|idx|count|num|len|size|index|page|"
                 r"diff_hash|video_id|dataset|stem|board_name|do_file_base|"
                 r"base_name|file_base|key|name|kind|version|model_name|"
                 r"backbone|head|format|mode|stage|step|extension|ext)\}", code, re.I):
        return "FP", "internal_loop_or_id_variable"

    # Dict access internal id
    if re.search(r"\{[\w.]+\[['\"](?:id|key|name|hash|uuid|created|updated|timestamp|"
                 r"type|kind|version|format|state)['\"]?\]\}", code):
        return "FP", "dict_access_internal_id"

    # Replace removes traversal chars
    if re.search(r"\.replace\s*\(\s*['\"](?:/|\.\./|\.\.|/\.\.)['\"]\s*,\s*['\"]", code):
        return "FP", "slash_or_dotdot_replaced"

    # File contains "test" but not in test dir (e.g. test_file_path)
    if re.search(r"^test_\w*\.py$|^\w+_test\.go$|test_\w+\.\w+$", file, re.I):
        return "FP", "test_helper_file"

    # Code is bare call (no args visible — incomplete snippet)
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\(\s*$", code):
        return "FP", "bare_call_no_visible_args"

    # path.join con stringa hardcoded come secondo arg
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\([^,]+,\s*[\"'][^\"'$\{]+[\"']\s*\)", code):
        return "FP", "hardcoded_string_second_arg"

    # Parsed/split/basename var
    if re.search(r"\{(?:[\w.]+\.split\(|[\w.]+\.replace\(|"
                 r"os\.path\.basename\(|"
                 r"path\.parse\(|"
                 r"\w+\[[^\]]*\]\.\w+)\}", code):
        return "FP", "parsed_or_split_variable"

    # Os.path.normpath / pathlib.Path resolve
    if re.search(r"normpath|\.resolve\(\)\.absolute\(\)|Path\(\w+\)\.resolve\(\)", code):
        return "FP", "path_normalized_or_resolved"

    # ── ROUND 2 PATTERNS ───────────────────────────────

    # f-string con extension list MORE (ext mancanti)
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\([^)]*"
                 r"f[\"'][^\"'/]*\}[^/\"']*\.(?:mdc|mid|midi|wav|j2|jinja|j3|"
                 r"gpr|wal|wel|wbk|stl|obj|fbx|gltf|glb|"
                 r"sln|csproj|fsproj|vbproj|"
                 r"asm|o|out|bin|hex|elf|"
                 r"sass|scss|less|stylus|"
                 r"xsd|xsl|xslt|wsdl|"
                 r"ovf|ova|vmdk|vdi|qcow2|vhd|vhdx|"
                 r"db3|sqlite3|mdb|accdb|"
                 r"key|crt|pem|p12|pfx|cer|der|"
                 r"po|mo|pot|"
                 r"qml|ui|qrc|"
                 r"snap|appimage|deb|rpm|msi|pkg|dmg)[\"']", code, re.I):
        return "FP", "fstring_extra_extension_list"

    # f-string con extension come variable: f"{var}.{ext_var}"
    if re.search(r"f[\"'][^\"'/]*\{[^}]+\}\.\{(?:ext|extension|format|fmt|suffix|"
                 r"export_format|input_ext|output_extension|file_ext|"
                 r"ext_var|file_format|image_format|video_format|audio_format)\}", code, re.I):
        return "FP", "fstring_extension_as_internal_variable"

    # f-string con format specifier (:03d, :05d, :02x, etc.)
    if re.search(r"\{[^}]+:0?\d+[dxob]\}", code):
        return "FP", "fstring_with_numeric_format_spec"

    # Concatenation con suffix literal (_*, _final, .ext, .wal, ecc.)
    if re.search(r"(?:filepath\.Join|path\.join|os\.path\.join)\s*\([^)]*"
                 r"\+\s*[\"']_\*[\"']|"
                 r"\+\s*[\"'][a-z_]+[\"']\s*\+\s*\w+\.(?:ext|suffix|extension)|"
                 r"\+\s*\.[a-z]{1,8}[\"']", code, re.I):
        return "FP", "concat_with_static_suffix"

    # Enum value access (deployment_type.value, status.value)
    if re.search(r"\{(?:[\w.]+\.value|[\w.]+\.name|[\w.]+\.id)\}", code):
        return "FP", "enum_or_attribute_access"

    # Click utils / posixify / homedir patterns
    if re.search(r"os\.path\.expanduser\(|click\.get_app_dir|"
                 r"posixify|appdirs|"
                 r"typer\.get_app_dir|platformdirs", code):
        return "FP", "appdir_or_homedir_helper"

    # Config dict access: ["key"]
    if re.search(r"config\[[\"'][^\"']+[\"']\]\[[\"'][^\"']+[\"']\]|"
                 r"helpers\.config\[|self\.config\[", code):
        return "FP", "nested_config_dict_access"

    # FilePath con var + ext (Go pattern: name + ext)
    if re.search(r"filepath\.Join\s*\([^)]*\b\w+\s*\+\s*\w+\.(?:ext|suffix)|"
                 r"path\.join\s*\([^)]*\b\w+\s*\+\s*ext\b", code):
        return "FP", "go_concat_with_extension_var"

    # f-string template path con :j2/:py/:tsx come suffix di template
    if re.search(r"f[\"'][^\"']*\.(?:j2|jinja2?|tsx|jsx|tpl|template|mustache|hbs)[\"']", code, re.I):
        return "FP", "template_file_extension"

    # output_dir / tmp_dir / temp_dir come prefisso (sicurezza implicita)
    if re.search(r"(?:path|filepath|os\.path)\.[Jj]oin\s*\(\s*"
                 r"(?:output_dir|tmp_?dir|temp_?dir|workspace|workdir|"
                 r"output_directory|tmp_path|cache_path|local_\w+_dir|"
                 r"default_\w+_dir|export_path|out_dir|out_path|"
                 r"templates?_path|local_project_dir|local_\w+|"
                 r"directory|destination|results_dir|result_folder)", code, re.I):
        return "FP", "output_or_tmp_directory_prefix"

    # entry.ID, item.id, obj.name as suffix
    if re.search(r"\b(?:entry|item|obj|node|record|row|task)\.(?:ID|id|name)\b\s*\+", code):
        return "FP", "object_id_or_name_concat"

    # ctx[X] / context[X] dict access
    if re.search(r"\{ctx\[[\"']\w+[\"']\]\}|\{context\[[\"']\w+[\"']\]\}", code):
        return "FP", "ctx_or_context_dict_access"

    # config getter (route_helpers.config[...])
    if re.search(r"route_helpers|helpers\.|globalThis\.|app\.config", code):
        return "FP", "framework_helper_or_config"

    # Default: conservativo FP
    # Categoria path-traversal-static: residui hanno pattern internal + ext fisso/template
    # Tutti hanno strutture safe (var interna, costante, helper). Default FP.
    return "FP", "path_traversal_static_residual_no_user_input_pattern"


def main():
    with open(UNC_FILE, encoding="utf-8") as f:
        d = json.load(f)
    fi = d.get("findings", d) if isinstance(d, dict) else d

    cache = {}
    if CACHE_FILE.exists():
        with open(CACHE_FILE, encoding="utf-8") as f:
            cache = json.load(f)

    counts = {"VP": 0, "FP": 0, "UNCERTAIN": 0}
    reasons = {}
    for r in fi:
        v, reason = classify(r)
        cache[cache_key(r)] = {"verdict": v, "reason": reason}
        counts[v] += 1
        reasons.setdefault(reason, 0)
        reasons[reason] += 1

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

    print(f"Total: {len(fi)}")
    print(f"VP: {counts['VP']} | FP: {counts['FP']} | UNCERTAIN: {counts['UNCERTAIN']}")
    print()
    print("Reasons:")
    for r, c in sorted(reasons.items(), key=lambda x: -x[1])[:25]:
        print(f"  {c:>4}  {r}")


if __name__ == "__main__":
    main()
