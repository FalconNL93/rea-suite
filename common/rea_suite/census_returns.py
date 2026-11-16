"""Return kinds for the census tables (docs/census.md, "Return kinds"): what a function or method
returns, in a small fixed vocabulary, so a runtime with no answer for it can return a fitting
failure instead of 0 (S_OK for an HRESULT).

The kind comes from the declaration's return type in the SDK headers, through their typedefs
(`LSTATUS` -> lstatus, `HWND` -> handle, `LPVOID` -> pointer, `NxU32` -> dword). A few kinds the
type cannot tell are rules over names (census_slots.py: CreateFileA's INVALID_HANDLE_VALUE,
the registry's LONG, Winsock's SOCKET_ERROR). What neither tells is "unknown", never a guess.
"""

from __future__ import annotations

import re
from pathlib import Path

# The vocabulary: kind -> (the value a runtime returns for a failure, what it means). The failure
# is the 32-bit EAX value (qword: EDX:EAX, float: ST(0)); None where there is none to return.
KINDS: dict[str, tuple[int | float | None, str]] = {
    "hresult": (0x80004005, "HRESULT: failure E_FAIL; 0 is S_OK"),
    "ntstatus": (0xC0000001, "NTSTATUS: failure STATUS_UNSUCCESSFUL; 0 is STATUS_SUCCESS"),
    "lstatus": (2, ("a Win32 or C error code (LSTATUS, the registry's LONG, errno_t, WSAStartup, "
                 "getaddrinfo): 0 is success, failure ERROR_FILE_NOT_FOUND (2, ENOENT for errno_t)")),
    "mmresult": (1, "MMRESULT or MCIERROR: 0 is MMSYSERR_NOERROR, failure MMSYSERR_ERROR"),
    "bool": (0, "BOOL, BOOLEAN or C++ bool: failure FALSE"),
    "handle": (0, "a handle whose failure is NULL"),
    "handle_invalid": (0xFFFFFFFF, ("a handle whose failure is INVALID_HANDLE_VALUE (-1): "
                        "CreateFile, FindFirstFile, a SOCKET (INVALID_SOCKET), HFILE_ERROR")),
    "socket_error": (0xFFFFFFFF, "Winsock's int: failure SOCKET_ERROR (-1)"),
    "pointer": (0, "a pointer (a string, a function, an object, a reference): failure NULL"),
    "int": (0, "a signed integer; the type alone does not say which value fails"),
    "dword": (0, "an unsigned 32-bit integer; the type alone does not say which value fails"),
    "qword": (0, "a 64-bit integer in EDX:EAX; the type alone does not say which value fails"),
    "float": (0.0, "float or double in ST(0), as returns_float"),
    "void": (None, "nothing returned"),
    "unknown": (None, ("the headers do not say (no declaration, a structure by value, "
                 "declarations that disagree)")),
}  # fmt: skip

# Types the kind is read from before any typedef: HRESULT is a LONG, but not an int.
KNOWN = {
    **dict.fromkeys(("HRESULT", "SCODE"), "hresult"),
    "NTSTATUS": "ntstatus",
    **dict.fromkeys(("LSTATUS", "errno_t"), "lstatus"),
    **dict.fromkeys(("MMRESULT", "MCIERROR"), "mmresult"),
    **dict.fromkeys(("BOOL", "WINBOOL", "BOOLEAN", "bool", "_Bool"), "bool"),
    **dict.fromkeys(("HANDLE", "GLOBALHANDLE", "LOCALHANDLE", "HGDIOBJ"), "handle"),
    **dict.fromkeys(("SOCKET", "HFILE"), "handle_invalid"),
    **dict.fromkeys(("float", "double", "FLOAT", "DOUBLE"), "float"),
    **dict.fromkeys(("void", "VOID"), "void"),
    # pointer-sized and time integers: the headers define them per target (#ifdef _WIN64), the
    # 32-bit one is meant
    **dict.fromkeys(("size_t", "SIZE_T", "ULONG_PTR", "UINT_PTR", "DWORD_PTR", "WPARAM",
                     "wchar_t", "WCHAR"), "dword"),
    **dict.fromkeys(("ssize_t", "INT_PTR", "LONG_PTR", "LPARAM", "LRESULT", "intptr_t",
                     "ptrdiff_t", "time_t", "clock_t", "int", "long", "short", "char", "signed",
                     "__LONG32", "__int32", "__int16", "__int8"),
                    "int"),
    **dict.fromkeys(("__int64", "LONGLONG", "ULONGLONG", "DWORD64", "UINT64", "INT64"), "qword"),
}  # fmt: skip

# Words of a declaration that are no part of its return type.
NOT_TYPE = re.compile(
    r"^(?:extern|static|inline|__inline|__inline__|__forceinline|const|volatile|register|FAR|NEAR"
    r"|far|near|struct|enum|union|class|virtual|typename|C|EXTERN_C|DECLSPEC_\w+|_CRTIMP\w*"
    r"|__MINGW\w*|_CRT\w*|__CRT\w*|_STRSAFE\w*|WIN\w*API\w*|\w+API|\w+_API|\w+_LINKAGE|\w+_DLL\w*"
    r"|__declspec|__attribute__|__nothrow|__restrict\w*)$"
)
CONVENTIONS = (
    "WINAPI|APIENTRY|__stdcall|_stdcall|CALLBACK|WSAAPI|PASCAL|NTAPI|STDAPICALLTYPE"
    "|STDAPIVCALLTYPE|STDMETHODCALLTYPE|__cdecl|_cdecl|CDECL|WINAPIV|__MINGW_CDECL|__CRTDECL"
)
# A declaration starts after a statement, a block or a macro call (`DECL_WINELIB_TYPE_AW(X)`)
DECLARATION = re.compile(rf"(?:^|(?<=[;{{}})]))([^;{{}}()]*?)\b(?:{CONVENTIONS})\s+(\w+)\s*\(")
TYPEDEF = re.compile(r"\btypedef\s+([^;{}()]+);")
DECLARE_HANDLE = re.compile(r"\bDECLARE_HANDLE\s*\(\s*(\w+)\s*\)")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def hresult_macros(texts: list[str]) -> tuple[set[str], set[str]]:
    """The headers' declaration macros: those that declare an HRESULT function (STDAPI,
    WINOLEAPI, SHSTDAPI ...) and those taking the return type (STDAPI_(type) ...)."""
    plain: dict[str, str] = {}
    typed: set[str] = set()
    for text in texts:
        for name, body in re.findall(
            r"^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+([^\n]*)$", text, re.MULTILINE
        ):
            plain.setdefault(name, body.strip())
        typed.update(
            re.findall(r"^[ \t]*#[ \t]*define[ \t]+(\w+)_\(\s*type\s*\)", text, re.MULTILINE)
        )
    found = {n for n, b in plain.items() if re.search(rf"\bHRESULT\s+(?:{CONVENTIONS})$", b)}
    while True:  # WINOLEAPI is STDAPI, SHFOLDERAPI is STDAPI ...
        more = {n for n, b in plain.items() if n not in found and (b.split() or [""])[-1] in found}
        if not more:
            return found, typed
        found |= more


def prepared(text: str, hresults: set[str], typed: set[str]) -> str:
    """A header as one line of declarations: no comments, no preprocessor lines, no strings,
    no attributes, the declaration macros expanded."""
    text = strip_comments(text).replace("\\\n", " ")
    text = re.sub(r"^[ \t]*#[^\n]*$", " ", text, flags=re.MULTILINE)
    text = re.sub(r'"[^"\n]*"', " ", text)
    text = re.sub(r"\b__\w+\s*\(\((?:[^()]|\([^()]*\))*\)\)", " ", text)  # __attribute__((...))
    text = re.sub(
        r"\b(?:__declspec|__MINGW_ATTRIB_\w+|__MINGW_\w+_MSG|_CRT_\w+|DECLSPEC_\w+)\s*\((?:[^()]|\([^()]*\))*\)",
        " ",
        text,
    )
    if typed:
        names = "|".join(sorted(typed, key=len, reverse=True))
        text = re.sub(rf"\b(?:{names})_\s*\(([^()]*)\)", r" \1 STDAPICALLTYPE ", text)
    if hresults:
        names = "|".join(sorted(hresults, key=len, reverse=True))
        text = re.sub(rf"\b(?:{names})\b(?!_)", " HRESULT STDAPICALLTYPE ", text)
    return re.sub(r"\s+", " ", text)


class ReturnKinds:
    """The kind of a return type, through the typedefs of the headers it was declared in."""

    def __init__(self, text: str):
        self.typedefs: dict[str, str] = {}
        for body in TYPEDEF.findall(text):
            parts = body.split(",")
            first = re.findall(r"\w+|\*|&", parts[0])
            at = max((i for i, t in enumerate(first) if t not in ("*", "&")), default=-1)
            if at < 1:
                continue
            base = [t for t in first[:at] if t not in ("*", "&")]  # the later declarators' base
            declared = [(first[at], " ".join(first[:at]))]
            for part in parts[1:]:
                tokens = re.findall(r"\w+|\*|&", part)
                names = [t for t in tokens if t not in ("*", "&")]
                if names:
                    declared.append(
                        (names[-1], " ".join(base + ["*"] * (len(tokens) - len(names))))
                    )
            for name, target in declared:
                if name not in base:  # typedef struct X X
                    self.typedefs.setdefault(name, target)
        self.handles = set(DECLARE_HANDLE.findall(text))
        self.enums = set(re.findall(r"\benum\s+(\w+)\s*\{", text))  # enum X {...} and
        for names in re.findall(r"\btypedef\s+enum\s*\w*\s*\{[^{}]*\}\s*([^;{}()]+);", text):
            self.enums.update(d.strip() for d in names.split(",") if "*" not in d)  # X, not *PX

    def of(self, text: str, depth: int = 0) -> str:
        """The kind of a return type as written (`HRESULT`, `const char *`, `NxActor*`)."""
        tokens = re.findall(r"\w+|\*|&", re.sub(r"=.*$", "", text))
        if "*" in tokens or "&" in tokens:
            return "pointer"
        words = [w for w in tokens if not NOT_TYPE.match(w)]
        if not words:
            return "unknown"
        if words.count("long") >= 2 or "__int64" in words:
            return "qword"
        if "unsigned" in words:
            return "dword"
        if len(words) == 2 and words == ["long", "double"]:
            return "float"
        word = words[-1]
        if word in KNOWN:
            return KNOWN[word]
        if word in self.handles:
            return "handle"
        if word in self.enums:
            return "int"
        if word in self.typedefs and depth < 12:
            kind = self.of(self.typedefs[word], depth + 1)
            if kind == "pointer" and handle_name(word):
                return "handle"
            if kind != "unknown":
                return kind
        if handle_name(word):
            return "handle"
        if re.match(r"^(?:LP|P|NP)[A-Z]", word) or word.endswith("PROC"):
            return "pointer"
        return "unknown"


def handle_name(word: str) -> bool:
    return (
        bool(re.fullmatch(r"H[A-Z0-9_]+", word)) and word != "HRESULT" or word.endswith("_HANDLE")
    )


def header_kinds(include: Path) -> tuple[ReturnKinds, dict[str, str], int]:
    """(the headers' typedefs, function name -> kind of every declaration with a calling
    convention, how many names the headers declare with kinds that disagree: those are
    "unknown") for a directory of headers (MinGW-w64's include)."""
    raw = [p.read_text(encoding="utf-8", errors="replace") for p in sorted(include.rglob("*.h"))]
    hresults, typed = hresult_macros(raw)
    texts = [prepared(t, hresults, typed) for t in raw]
    kinds = ReturnKinds("\n".join(texts))
    seen: dict[str, set[str]] = {}
    for text in texts:
        for prefix, name in DECLARATION.findall(text):
            if re.search(r"\b(?:typedef|virtual)\b", prefix):  # a C++ interface's method
                continue
            seen.setdefault(name, set()).add(kinds.of(prefix))
    found, disagree = {}, 0
    for name, ks in seen.items():
        known = ks - {"unknown"}
        if len(known) > 1:
            disagree += 1
        found[name] = known.pop() if len(known) == 1 else "unknown"
    return kinds, found, disagree


def vocabulary() -> dict[str, dict]:
    """The tables' `return_kinds` member: every kind, its failure value and its meaning."""
    return {k: {"failure": f, "means": m} for k, (f, m) in KINDS.items()}
