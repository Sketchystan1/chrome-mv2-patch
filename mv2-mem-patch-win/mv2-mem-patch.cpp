// mv2-mem-patch.cpp — version.dll proxy that re-enables Manifest V2 in
// Chrome (x64, x86, or ARM64). Build one DLL per architecture (build.bat) and
// place the matching version.dll and signatures.json next to chrome.exe.
//
// Based on chrome_plus (export forwarding + child-process mitigation fix)
// and mv2-launcher (MV2 gate signature scanning).
//
// 1. chrome.exe statically imports version.dll, so this DLL loads before
//    chrome.dll. Its 17 exports are detoured to the real system version.dll.
// 2. UpdateProcThreadAttribute is hooked to strip BlockNonMicrosoftBinaries,
//    which would otherwise kill Chrome's child processes with
//    STATUS_INVALID_IMAGE_HASH while a non-Microsoft DLL is in the process.
// 3. ntdll!LdrLoadDll is hooked. When chrome.dll is mapped, its on-disk
//    .text is scanned against signatures.json and every MV2 gate (jg) is
//    flipped to jmp in the loaded image — synchronously on Chrome's own
//    loading thread, before any chrome.dll code can execute.
// 4. The signatures source can be set by mv2-launcher-config.txt next to
//    chrome.exe (the same TOML file the launcher reads). When it names an https
//    URL and the local signatures.json does not fully match this Chrome, a
//    background thread refreshes signatures.json for the NEXT launch — the fetch
//    never runs under the loader lock.

#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <processthreadsapi.h>
#include <winhttp.h>

#include <intrin.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

#include "detours.h"

#pragma comment(lib, "winhttp.lib")

// Failure traces — visible in a debugger or DebugView, no file I/O.
#define DBG(msg) OutputDebugStringW(L"[mv2patch] " msg)

// ---------------------------------------------------------------------------
// Export forwarding: 17 stub exports, detoured to the real version.dll in
// DllMain. The volatile padding gives Detours room for its hook, and
// __COUNTER__ keeps each body unique so /OPT:ICF cannot merge them.
// <winver.h> prototypes these names with C linkage, so the stubs live in a
// namespace and are exported under their plain names via linker pragmas.
// ---------------------------------------------------------------------------

#define STUB(api)                                                 \
  int __cdecl api() {                                             \
    /* volatile padding gives Detours room for its hook; the      \
       differing __COUNTER__ seed keeps each body distinct so      \
       /OPT:ICF cannot merge them. Arch-neutral — the x86/x64-only \
       __nop intrinsic is avoided so this compiles on ARM64 too.   \
       The return value is never used (detoured before any call).*/\
    volatile int p = __COUNTER__;                                 \
    p += 1; p += 1; p += 1; p += 1; p += 1; p += 1;               \
    p += 1; p += 1; p += 1; p += 1; p += 1; p += 1;               \
    return p;                                                      \
  }

namespace hijack {
STUB(GetFileVersionInfoA)
STUB(GetFileVersionInfoByHandle)
STUB(GetFileVersionInfoExA)
STUB(GetFileVersionInfoExW)
STUB(GetFileVersionInfoSizeA)
STUB(GetFileVersionInfoSizeExA)
STUB(GetFileVersionInfoSizeExW)
STUB(GetFileVersionInfoSizeW)
STUB(GetFileVersionInfoW)
STUB(VerFindFileA)
STUB(VerFindFileW)
STUB(VerInstallFileA)
STUB(VerInstallFileW)
STUB(VerLanguageNameA)
STUB(VerLanguageNameW)
STUB(VerQueryValueA)
STUB(VerQueryValueW)
}  // namespace hijack

#pragma comment(linker, "/export:GetFileVersionInfoA=?GetFileVersionInfoA@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=?GetFileVersionInfoByHandle@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoExA=?GetFileVersionInfoExA@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoExW=?GetFileVersionInfoExW@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=?GetFileVersionInfoSizeA@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=?GetFileVersionInfoSizeExA@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=?GetFileVersionInfoSizeExW@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=?GetFileVersionInfoSizeW@hijack@@YAHXZ")
#pragma comment(linker, "/export:GetFileVersionInfoW=?GetFileVersionInfoW@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerFindFileA=?VerFindFileA@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerFindFileW=?VerFindFileW@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerInstallFileA=?VerInstallFileA@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerInstallFileW=?VerInstallFileW@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerLanguageNameA=?VerLanguageNameA@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerLanguageNameW=?VerLanguageNameW@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerQueryValueA=?VerQueryValueA@hijack@@YAHXZ")
#pragma comment(linker, "/export:VerQueryValueW=?VerQueryValueW@hijack@@YAHXZ")

static void ForwardExports(HMODULE self) {
  BYTE* base = (BYTE*)self;
  auto dos = (IMAGE_DOS_HEADER*)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
  auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return;
  auto exp = (IMAGE_EXPORT_DIRECTORY*)(base +
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress);
  DWORD* names = (DWORD*)(base + exp->AddressOfNames);
  DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
  WORD*  ords  = (WORD*)(base + exp->AddressOfNameOrdinals);

  wchar_t sys[MAX_PATH + 1];
  GetSystemDirectoryW(sys, MAX_PATH);
  lstrcatW(sys, L"\\version.dll");
  HMODULE real = LoadLibraryW(sys);
  if (!real) return;

  for (DWORD i = 0; i < exp->NumberOfNames; i++) {
    char* name = (char*)(base + names[i]);
    void* target = (void*)GetProcAddress(real, name);
    if (!target) continue;
    void* ours = base + funcs[ords[i]];
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&ours, target);
    DetourTransactionCommit();
  }
}

// ---------------------------------------------------------------------------
// Strip BlockNonMicrosoftBinaries from Chrome's child-process mitigation
// policy — without this, renderers and other children die with
// STATUS_INVALID_IMAGE_HASH because this DLL is not Microsoft-signed.
// ---------------------------------------------------------------------------

static auto RealUpdateProcThreadAttribute = ::UpdateProcThreadAttribute;

static BOOL WINAPI MyUpdateProcThreadAttribute(
    LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD flags, DWORD_PTR attr,
    PVOID value, SIZE_T size, PVOID prev, PSIZE_T ret) {
  if (attr == PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY &&
      size >= sizeof(DWORD64))
    *(DWORD64*)value &= ~(0x00000001ui64 << 44);  // BlockNonMicrosoftBinaries
  return RealUpdateProcThreadAttribute(list, flags, attr, value, size, prev,
                                       ret);
}

// ---------------------------------------------------------------------------
// MV2 gate patching (ported from mv2-launcher)
// ---------------------------------------------------------------------------

// Host architecture. A version.dll proxy is loaded into chrome.exe, so it must
// match chrome.exe's architecture. Each arch reads its own container from
// signatures.json and accepts its own PE machine value. Build one DLL per arch.
#if defined(_M_X64)
static const char* kHostContainer = "pe";
static const WORD  kHostMachine   = 0x8664;  // IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_IX86)
static const char* kHostContainer = "pe32";
static const WORD  kHostMachine   = 0x014C;  // IMAGE_FILE_MACHINE_I386
#elif defined(_M_ARM64)
static const char* kHostContainer = "pe-arm64";
static const WORD  kHostMachine   = 0xAA64;  // IMAGE_FILE_MACHINE_ARM64
#else
#error "unsupported target architecture"
#endif

struct Site {
  int kind = 0;  // 0 = short jg (7F->EB), 1 = near jg (0F8F->90E9),
                 // 2 = AArch64 b.cond (cond nibble GT 0xC -> AL 0xE)
  std::vector<BYTE> sig;
  int jgOff    = 0;
  int expected = 1;
};

struct Milestone {
  std::vector<Site> sites;
};

// Tiny JSON parser (signatures.json subset) — from mv2-launcher.
struct JV {
  enum T { NUL, BOOL, NUM, STR, ARR, OBJ } t = NUL;
  bool b = false;
  double num = 0;
  std::string str;
  std::vector<JV> arr;
  std::vector<std::pair<std::string, JV>> obj;

  const JV* get(const char* k) const {
    for (auto& kv : obj)
      if (kv.first == k) return &kv.second;
    return nullptr;
  }
};

struct JParser {
  std::string s;
  const char* p;
  const char* e;

  explicit JParser(const std::string& src)
      : s(src), p(s.data()), e(s.data() + s.size()) {}

  [[noreturn]] static void err() {
    throw std::runtime_error("bad signatures.json");
  }

  void ws() {
    while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
      ++p;
  }

  bool lit(const char* w) {
    size_t n = strlen(w);
    if (e - p < (ptrdiff_t)n || strncmp(p, w, n) != 0) return false;
    p += n;
    return true;
  }

  JV val() {
    ws();
    if (p < e && *p == '{') {
      ++p;
      JV v;
      v.t = JV::OBJ;
      ws();
      if (p < e && *p == '}') {
        ++p;
        return v;
      }
      for (;;) {
        ws();
        std::string k = str();
        ws();
        if (p >= e || *p != ':') err();
        ++p;
        v.obj.emplace_back(std::move(k), val());
        ws();
        if (p < e && *p == ',') { ++p; continue; }
        if (p < e && *p == '}') { ++p; return v; }
        err();
      }
    }
    if (p < e && *p == '[') {
      ++p;
      JV v;
      v.t = JV::ARR;
      ws();
      if (p < e && *p == ']') {
        ++p;
        return v;
      }
      for (;;) {
        v.arr.push_back(val());
        ws();
        if (p < e && *p == ',') { ++p; continue; }
        if (p < e && *p == ']') { ++p; return v; }
        err();
      }
    }
    if (p < e && *p == '"') {
      JV v;
      v.t   = JV::STR;
      v.str = str();
      return v;
    }
    if (lit("true"))  { JV v; v.t = JV::BOOL; v.b = true;  return v; }
    if (lit("false")) { JV v; v.t = JV::BOOL; v.b = false; return v; }
    if (lit("null"))  { JV v; v.t = JV::NUL;  return v; }
    JV v;
    v.t = JV::NUM;
    char* end = nullptr;
    v.num = strtod(p, &end);
    if (end == p) err();
    p = end;
    return v;
  }

  std::string str() {
    if (p >= e || *p != '"') err();
    ++p;
    std::string out;
    while (p < e && *p != '"') {
      char c = *p++;
      if (c != '\\') { out += c; continue; }
      if (p >= e) err();
      char x = *p++;
      switch (x) {
        case '"':  out += '"';  break;
        case '\\': out += '\\'; break;
        case '/':  out += '/';  break;
        case 'b':  out += '\b'; break;
        case 'f':  out += '\f'; break;
        case 'n':  out += '\n'; break;
        case 'r':  out += '\r'; break;
        case 't':  out += '\t'; break;
        case 'u': {
          if (e - p < 4) err();
          unsigned cp = 0;
          for (int i = 0; i < 4; i++) {
            char h = *p++;
            cp <<= 4;
            cp |= (h <= '9') ? (unsigned)(h - '0')
                             : (unsigned)((h | 32) - 'a' + 10);
          }
          if (cp < 0x80) {
            out += (char)cp;
          } else if (cp < 0x800) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
          } else {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
          }
          break;
        }
        default: err();
      }
    }
    if (p >= e) err();
    ++p;
    return out;
  }
};

static std::vector<BYTE> HexToBytes(const std::string& h) {
  std::vector<BYTE> b(h.size() / 2);
  for (size_t i = 0; i < b.size(); i++)
    b[i] = (BYTE)strtoul(h.substr(i * 2, 2).c_str(), nullptr, 16);
  return b;
}

// milestones[] entries whose container matches this build's arch, and their
// sites. kind: short=0, near=1, bcond=2 (AArch64).
static std::vector<Milestone> ParseMilestones(const JV& doc,
                                              const char* container) {
  std::vector<Milestone> out;
  const JV* ms = doc.get("milestones");
  if (!ms || ms->t != JV::ARR) return out;
  for (const JV& m : ms->arr) {
    const JV* cont = m.get("container");
    if (!cont || cont->str != container) continue;
    Milestone mo;
    const JV* sites = m.get("sites");
    if (!sites || sites->t != JV::ARR) continue;
    for (const JV& sd : sites->arr) {
      Site s;
      const JV* kd = sd.get("kind");
      std::string ks = kd ? kd->str : "short";
      s.kind = (ks == "bcond") ? 2 : (ks == "near") ? 1 : 0;
      s.sig  = HexToBytes(sd.get("sig") ? sd.get("sig")->str : "");
      s.jgOff = sd.get("jgOff") ? (int)sd.get("jgOff")->num : 0;
      s.expected =
          sd.get("expectedMatches") ? (int)sd.get("expectedMatches")->num : 1;
      // Bytes the matcher touches at/after jgOff: short 2, near 6, bcond 4.
      int need = (s.kind == 2) ? 4 : (s.kind == 1) ? 6 : 2;
      if (s.sig.size() < 2 || s.jgOff < 0 ||
          (long long)s.jgOff + need > (long long)s.sig.size() ||
          s.expected < 1)
        continue;
      mo.sites.push_back(std::move(s));
    }
    if (!mo.sites.empty()) out.push_back(std::move(mo));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Config (mv2-launcher-config.txt next to chrome.exe) — the same TOML the
// mv2-launcher reads, so one file can serve both. Keys:
//   browser    — ignored here (this DLL is already inside the chosen Chrome).
//   signatures — an https URL or a local path. See PatchChromeDll for how a URL
//                is honored off the loader lock.
//   args       — accepted for compatibility but ignored (a DLL cannot rewrite
//                Chrome's command line safely; use the launcher for flags).
// Ported from mv2-launcher.
// ---------------------------------------------------------------------------

static const wchar_t* kDefaultSigUrl =
    L"https://github.com/Sketchystan1/chrome-mv2-patch/raw/master/signatures.json";

struct Config {
  std::wstring signatures = kDefaultSigUrl;
};

static std::wstring Utf8ToWide(const std::string& s) {
  if (s.empty()) return std::wstring();
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0);
  std::wstring w((size_t)n, 0);
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
  return w;
}

static std::vector<BYTE> ReadFileBytes(const wchar_t* path) {
  std::vector<BYTE> out;
  HANDLE f = CreateFileW(path, GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE) return out;
  LARGE_INTEGER sz{};
  if (GetFileSizeEx(f, &sz) && sz.QuadPart > 0 && sz.QuadPart < (1LL << 30)) {
    out.resize((size_t)sz.QuadPart);
    DWORD got = 0;
    SIZE_T off = 0;
    while (off < out.size() &&
           ReadFile(f, out.data() + off, (DWORD)(out.size() - off), &got, NULL) &&
           got)
      off += got;
    if (off != out.size()) out.clear();
  }
  CloseHandle(f);
  return out;
}

// TOML basic ("...", with \\ \" \n \t \r escapes) or literal ('...') string.
static bool TomlStr(const std::string& in, std::string& out) {
  if (in.size() < 2) return false;
  char q = in[0];
  if (q != '"' && q != '\'') return false;
  out.clear();
  for (size_t i = 1; i < in.size(); i++) {
    char ch = in[i];
    if (q == '"' && ch == '\\' && i + 1 < in.size()) {
      char nx = in[++i];
      switch (nx) {
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case 'r': out += '\r'; break;
        default:  out += nx;  // \\ and \" land here
      }
      continue;
    }
    if (ch == q) return true;
    out += ch;
  }
  return false;
}

// Read mv2-launcher-config.txt next to chrome.exe. Only "signatures" is honored;
// "browser" and "args" are accepted (launcher compatibility) and ignored.
static Config LoadConfig(const std::wstring& exeDir) {
  Config c;
  std::vector<BYTE> raw =
      ReadFileBytes((exeDir + L"\\mv2-launcher-config.txt").c_str());
  if (raw.empty()) return c;
  std::string text((const char*)raw.data(), raw.size());
  auto trim = [](std::string& s) {
    size_t a = s.find_first_not_of(" \t\r");
    if (a == std::string::npos) { s.clear(); return; }
    size_t b = s.find_last_not_of(" \t\r");
    s = s.substr(a, b - a + 1);
  };
  for (size_t i = 0; i < text.size();) {
    size_t nl = text.find('\n', i);
    std::string line =
        text.substr(i, (nl == std::string::npos ? text.size() : nl) - i);
    i = (nl == std::string::npos) ? text.size() : nl + 1;
    trim(line);
    if (line.empty() || line[0] == '#') continue;
    size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq), val = line.substr(eq + 1);
    trim(key);
    trim(val);
    std::string s;
    if (key == "signatures" && TomlStr(val, s) && !s.empty())
      c.signatures = Utf8ToWide(s);
  }
  return c;
}

// Fetch a file over https into memory. Refuses plain http; hard size cap. Only
// ever called from the deferred refresh thread — never under the loader lock.
static bool HttpsGet(const wchar_t* url, size_t maxBytes,
                     std::vector<BYTE>* out) {
  if (_wcsnicmp(url, L"https://", 8) != 0) return false;
  const wchar_t* rest = url + 8;
  const wchar_t* slash = wcschr(rest, L'/');
  size_t hostLen = slash ? (size_t)(slash - rest) : wcslen(rest);
  if (hostLen == 0 || hostLen >= 256) return false;
  wchar_t host[256];
  memcpy(host, rest, hostLen * sizeof(wchar_t));
  host[hostLen] = 0;
  const wchar_t* path = slash ? slash : L"/";
  bool ok = false;
  HINTERNET ses = WinHttpOpen(L"mv2-mem-patch/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  HINTERNET con =
      ses ? WinHttpConnect(ses, host, INTERNET_DEFAULT_HTTPS_PORT, 0) : NULL;
  HINTERNET req =
      con ? WinHttpOpenRequest(con, L"GET", path, NULL, WINHTTP_NO_REFERER,
                               WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
          : NULL;
  if (req &&
      WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                         WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
      WinHttpReceiveResponse(req, NULL)) {
    DWORD status = 0, sz = sizeof(status);
    if (WinHttpQueryHeaders(
            req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
            WINHTTP_NO_HEADER_INDEX) &&
        status == 200) {
      ok = true;
      for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
        if (out->size() + avail > maxBytes) { out->clear(); ok = false; break; }
        size_t old = out->size();
        out->resize(old + avail);
        DWORD got = 0;
        if (!WinHttpReadData(req, out->data() + old, avail, &got) || got == 0) {
          out->clear();
          ok = false;
          break;
        }
        out->resize(old + got);
      }
    }
  }
  if (req) WinHttpCloseHandle(req);
  if (con) WinHttpCloseHandle(con);
  if (ses) WinHttpCloseHandle(ses);
  return ok && !out->empty();
}

// Write via temp + atomic replace so a crash never leaves a truncated file.
static bool WriteAllBytesAtomic(const std::wstring& path,
                                const std::vector<BYTE>& b) {
  std::wstring tmp = path + L".tmp";
  HANDLE f = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE) return false;
  DWORD wrote = 0;
  SIZE_T off = 0;
  while (off < b.size() &&
         WriteFile(f, b.data() + off, (DWORD)(b.size() - off), &wrote, NULL) &&
         wrote)
    off += wrote;
  CloseHandle(f);
  if (off != b.size()) { DeleteFileW(tmp.c_str()); return false; }
  if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    DeleteFileW(tmp.c_str());
    return false;
  }
  return true;
}

// Deferred signatures refresh. The current run is already patched from the local
// file; this only replaces signatures.json for the NEXT launch, so it can run
// after Chrome's loader has released the lock. It validates the fetched body has
// pe milestones before overwriting, and never touches the loaded image.
struct RefreshArg {
  std::wstring url;
  std::wstring localPath;
};

static DWORD WINAPI RefreshThread(LPVOID p) {
  RefreshArg* a = (RefreshArg*)p;
  std::vector<BYTE> body;
  if (HttpsGet(a->url.c_str(), 1 << 20, &body)) {
    try {
      std::vector<Milestone> ms = ParseMilestones(
          JParser(std::string((const char*)body.data(), body.size())).val(),
          kHostContainer);
      if (!ms.empty()) {
        if (WriteAllBytesAtomic(a->localPath, body))
          DBG(L"signatures refreshed for next launch");
      } else {
        DBG(L"fetched signatures had no pe milestones — kept the old file");
      }
    } catch (...) {
      DBG(L"fetched signatures were unparseable — kept the old file");
    }
  }
  delete a;
  return 0;
}

// Read-only memory-mapped file (raw file-offset mapping, not image map).
struct MappedFile {
  HANDLE file = INVALID_HANDLE_VALUE;
  HANDLE map  = NULL;
  const BYTE* data = nullptr;
  size_t size = 0;

  MappedFile() = default;
  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;
  ~MappedFile() {
    if (data) UnmapViewOfFile(data);
    if (map) CloseHandle(map);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  }
};

static bool MapReadOnly(const wchar_t* path, MappedFile& mf) {
  mf.file = CreateFileW(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                        NULL);
  if (mf.file == INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER sz{};
  if (!GetFileSizeEx(mf.file, &sz) || sz.QuadPart <= 0) return false;
  mf.map = CreateFileMappingW(mf.file, NULL, PAGE_READONLY, 0, 0, NULL);
  if (!mf.map) return false;
  mf.data = (const BYTE*)MapViewOfFile(mf.map, FILE_MAP_READ, 0, 0, 0);
  if (!mf.data) return false;
  mf.size = (size_t)sz.QuadPart;
  return true;
}

struct Image {
  long long textRaw  = 0;  // file offset of .text data
  long long textSize = 0;
  long long textRVA  = 0;  // RVA of .text in the loaded image
  WORD machine       = 0;
};

static Image ParsePe(const BYTE* b, size_t n) {
  Image img;
  if (n < 0x40) return img;
  DWORD e = *(const DWORD*)&b[0x3C];
  if ((size_t)e > n - 24 || b[e] != 'P' || b[e + 1] != 'E') return img;
  img.machine = *(const WORD*)&b[e + 4];
  int nsec = *(const WORD*)&b[e + 6];
  int opt  = *(const WORD*)&b[e + 20];
  long long sec = (long long)e + 24 + opt;
  if (sec + (long long)nsec * 40LL > (long long)n) return img;
  for (int i = 0; i < nsec; i++) {
    long long sh = sec + (long long)i * 40LL;
    if (memcmp(&b[sh], ".text\0", 6) == 0) {
      img.textRVA  = *(const DWORD*)&b[sh + 12];
      img.textSize = *(const DWORD*)&b[sh + 16];
      img.textRaw  = *(const DWORD*)&b[sh + 20];
    }
  }
  return img;
}

// Signature match at a .text offset. The gate instruction itself is a
// wildcard that accepts both stock (jg) and already-patched (jmp) forms.
static bool SigAt(const BYTE* b, size_t n, long long start,
                  const std::vector<BYTE>& sig, int jgOff, int kind) {
  if (start < 0 || start + (long long)sig.size() > (long long)n) return false;
  for (size_t k = 0; k < sig.size(); k++) {
    BYTE p = b[start + k];
    if ((int)k == jgOff) {
      if (kind == 0) {
        if (p != 0x7F && p != 0xEB) return false;  // short jg / jmp
      } else if (kind == 1) {
        BYTE p1 = b[start + jgOff + 1];
        if (!((p == 0x0F && p1 == 0x8F) || (p == 0x90 && p1 == 0xE9)))
          return false;                            // near jg / nop+jmp
      } else {
        // AArch64 B.cond, little-endian [cond+o0][imm19][imm19][0x54]: the 0x54
        // opcode sits at jgOff+3, o0 (bit 4) must be 0, and the condition nibble
        // is GT (0x0C) stock or AL (0x0E) already-patched.
        if (b[start + jgOff + 3] != 0x54) return false;
        if ((p & 0x10) != 0) return false;
        BYTE lo = p & 0x0F;
        if (lo != 0x0C && lo != 0x0E) return false;
      }
    } else if ((int)k == jgOff + 1 && kind == 0) {
      // wildcard: imm8 of the short branch
    } else if (kind == 1 && (int)k >= jgOff + 2 && (int)k <= jgOff + 5) {
      // wildcard: rel32 of the near branch
    } else if (kind == 2 && ((int)k == jgOff + 1 || (int)k == jgOff + 2)) {
      // wildcard: imm19 middle bytes of the B.cond
    } else if (p != sig[k]) {
      return false;
    }
  }
  return true;
}

// Scan .text once for all sites of all milestones. A full match (every site
// at its expected count) beats a partial one; the milestone with more sites
// wins among fulls; an exact tie between two fulls declines.
static bool Locate(const BYTE* buf, size_t bufN, const Image& img,
                   const std::vector<Milestone>& milestones,
                   std::vector<std::pair<Site, std::vector<long long>>>* out,
                   bool* fullMatch = nullptr) {
  if (img.textSize == 0 || img.textRaw + img.textSize > (long long)bufN)
    return false;

  struct Job { int ms, si; const Site* s; };
  std::vector<Job> byFirst[256];
  for (int m = 0; m < (int)milestones.size(); m++)
    for (int si = 0; si < (int)milestones[m].sites.size(); si++)
      byFirst[(unsigned char)milestones[m].sites[si].sig[0]].push_back(
          {m, si, &milestones[m].sites[si]});

  std::vector<std::vector<std::vector<long long>>> hits(milestones.size());
  for (size_t m = 0; m < milestones.size(); m++)
    hits[m].resize(milestones[m].sites.size());

  long long textEnd = std::min(img.textRaw + img.textSize, (long long)bufN);
  for (long long i = img.textRaw; i < textEnd; i++) {
    for (const Job& j : byFirst[(unsigned char)buf[i]]) {
      if (i + 1 < textEnd && buf[i + 1] == j.s->sig[1] &&
          SigAt(buf, bufN, i, j.s->sig, j.s->jgOff, j.s->kind))
        hits[j.ms][j.si].push_back(i + j.s->jgOff);
    }
  }

  auto flatOffs =
      [](const std::vector<std::pair<Site, std::vector<long long>>>& per) {
        std::vector<long long> v;
        for (auto& kv : per)
          for (long long o : kv.second) v.push_back(o);
        std::sort(v.begin(), v.end());
        return v;
      };

  int fullSites = 0, partOk = 0, fullCount = 0;
  std::vector<std::pair<Site, std::vector<long long>>> fullPer, partPer;
  std::vector<long long> fullOffs;
  for (int m = 0; m < (int)milestones.size(); m++) {
    const Milestone& ms = milestones[m];
    std::vector<std::pair<Site, std::vector<long long>>> per;
    int ok = 0;
    for (int si = 0; si < (int)ms.sites.size(); si++) {
      auto& h = hits[m][si];
      if ((int)h.size() == ms.sites[si].expected) ok++;
      per.emplace_back(ms.sites[si], std::move(h));
    }
    if (ok == (int)ms.sites.size()) {
      if (fullSites == 0 || (int)ms.sites.size() > fullSites) {
        fullSites = (int)ms.sites.size();
        fullPer   = per;
        fullCount = 1;
        fullOffs  = flatOffs(per);
      } else if ((int)ms.sites.size() == fullSites) {
        // Two equal-size full matches are only ambiguous if they target
        // DIFFERENT bytes. Tables reused verbatim across version labels resolve
        // to the same gate offsets — keep the first winner instead of declining.
        if (flatOffs(per) != fullOffs) fullCount++;
      }
    } else if (ok > 0 && fullSites == 0 && ok > partOk) {
      partOk  = ok;
      partPer = per;
    }
  }

  if (fullCount > 1) return false;  // ambiguous — decline
  if (fullSites > 0) {
    if (fullMatch) *fullMatch = true;
    *out = std::move(fullPer);
    return true;
  }
  if (partOk > 0) {
    if (fullMatch) *fullMatch = false;
    *out = std::move(partPer);
    return true;
  }
  return false;
}

// Decide the write from the 2 current bytes at the branch. len is 1 for
// short/bcond, 2 for near. stock = still a taken conditional; done = already
// forced. Mirrors the scripts and the mv2-launcher core.
struct ApplyRes {
  BYTE patch[2];
  int  len;
  bool stock;
  bool done;
};

static ApplyRes ComputeApply(int kind, const BYTE cur[2]) {
  ApplyRes r{};
  if (kind == 0) {  // short jg: 7F -> EB
    r.stock    = cur[0] == 0x7F;
    r.done     = cur[0] == 0xEB;
    r.patch[0] = 0xEB;
    r.len      = 1;
  } else if (kind == 1) {  // near jg: 0F 8F -> 90 E9
    r.stock    = cur[0] == 0x0F && cur[1] == 0x8F;
    r.done     = cur[0] == 0x90 && cur[1] == 0xE9;
    r.patch[0] = 0x90;
    r.patch[1] = 0xE9;
    r.len      = 2;
  } else {  // AArch64 b.cond: condition nibble GT(0xC) -> AL(0xE)
    BYTE lo    = cur[0] & 0x0F;
    r.stock    = lo == 0x0C;
    r.done     = lo == 0x0E;
    r.patch[0] = (BYTE)((cur[0] & 0xF0) | 0x0E);
    r.len      = 1;
  }
  return r;
}

// Flip every matched gate in the loaded chrome.dll image:
//   file offset → RVA → runtime address, then patch via VirtualProtect.
static void ApplyInProcess(
    BYTE* chromeDllBase, const Image& img,
    const std::vector<std::pair<Site, std::vector<long long>>>& hits) {
  for (auto& [site, offs] : hits) {
    for (long long jgFileOff : offs) {
      BYTE* addr = chromeDllBase + img.textRVA + (jgFileOff - img.textRaw);
      BYTE cur[2] = {addr[0], addr[1]};
      ApplyRes a = ComputeApply(site.kind, cur);
      if (!a.stock) {
        if (!a.done) DBG(L"unexpected gate bytes — skipped");
        continue;
      }
      // PAGE_READWRITE, not RWX: the write needs no execute right, and RWX
      // on .text is a loud EDR signal.
      BYTE* page = (BYTE*)((ULONG_PTR)addr & ~(ULONG_PTR)0xFFF);
      DWORD old = 0;
      if (!VirtualProtect(page, 0x1000, PAGE_READWRITE, &old)) continue;
      memcpy(addr, a.patch, a.len);
      DWORD tmp = 0;
      VirtualProtect(page, 0x1000, old, &tmp);
      FlushInstructionCache(GetCurrentProcess(), addr, a.len);
    }
  }
}

static std::wstring AppDir() {
  wchar_t path[MAX_PATH];
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  wchar_t* slash = wcsrchr(path, L'\\');
  if (slash) *slash = L'\0';
  return path;
}

// Child processes (renderer, GPU, utility, …) carry --type=; only the
// browser process patches.
static bool IsBrowserProcess() {
  LPCWSTR cmd = GetCommandLineW();
  return !cmd || !wcsstr(cmd, L"--type=");
}

static void PatchChromeDll(HMODULE chromeDll) {
  try {
    wchar_t dllPath[MAX_PATH * 2]{};
    if (!GetModuleFileNameW(chromeDll, dllPath, MAX_PATH * 2)) return;

    MappedFile dll;
    if (!MapReadOnly(dllPath, dll)) {
      DBG(L"cannot map chrome.dll from disk");
      return;
    }
    Image img = ParsePe(dll.data, dll.size);
    if (img.machine != kHostMachine || img.textSize == 0) {
      DBG(L"chrome.dll arch does not match this proxy build, or has no .text");
      return;
    }

    std::wstring appDir    = AppDir();
    std::wstring localStore = appDir + L"\\signatures.json";
    Config cfg = LoadConfig(appDir);
    bool isUrl = _wcsnicmp(cfg.signatures.c_str(), L"https://", 8) == 0;

    // Where to read the gate table for THIS run. A URL source always reads the
    // local signatures.json (the store the refresh writes); a local-path source
    // reads that path (absolute, or relative to chrome.exe) and falls back to
    // signatures.json.
    std::wstring readPath = localStore;
    if (!isUrl) {
      const std::wstring& src = cfg.signatures;
      wchar_t d = src.empty() ? 0 : src[0];
      bool abs = (src.size() >= 3 &&
                  ((d >= L'A' && d <= L'Z') || (d >= L'a' && d <= L'z')) &&
                  src[1] == L':') ||
                 (!src.empty() && src[0] == L'\\');
      readPath = abs ? src : appDir + L"\\" + src;
    }

    auto loadFrom = [](const wchar_t* path) -> std::vector<Milestone> {
      MappedFile mf;
      if (!MapReadOnly(path, mf)) return {};
      try {
        return ParseMilestones(
            JParser(std::string((const char*)mf.data, mf.size)).val(),
            kHostContainer);
      } catch (...) {
        return {};
      }
    };

    std::vector<Milestone> milestones = loadFrom(readPath.c_str());
    if (milestones.empty() && readPath != localStore)
      milestones = loadFrom(localStore.c_str());  // fall back to signatures.json

    bool full = false;
    std::vector<std::pair<Site, std::vector<long long>>> hits;
    if (!milestones.empty() &&
        Locate(dll.data, dll.size, img, milestones, &hits, &full))
      ApplyInProcess((BYTE*)chromeDll, img, hits);
    else if (milestones.empty())
      DBG(L"no usable signatures (local file missing or unparseable)");
    else
      DBG(L"no milestone matched this chrome.dll build");

    // URL source + not a full match → refresh signatures.json for the next
    // launch. The thread is created here, but Chrome's loader thread cannot run
    // it until the current load finishes, so WinHTTP never runs inline. It only
    // rewrites the on-disk store; the current run is already patched.
    if (isUrl && !full) {
      RefreshArg* a = new (std::nothrow) RefreshArg{cfg.signatures, localStore};
      if (a) {
        HANDLE t = CreateThread(nullptr, 0, RefreshThread, a, 0, nullptr);
        if (t)
          CloseHandle(t);
        else
          delete a;
      }
    }
  } catch (...) {
    // Nothing may ever escape into LdrLoadDll.
    DBG(L"unexpected error while patching chrome.dll");
  }
}

// ---------------------------------------------------------------------------
// LdrLoadDll hook: patch chrome.dll the moment it is mapped. The real
// LdrLoadDll runs first (chrome.dll gets mapped and its DllMain executes),
// then we patch on the same thread. Chrome's main thread is the caller, so
// it cannot run any chrome.dll code until we return — no startup race.
// ---------------------------------------------------------------------------

struct LdrUnicodeString {  // UNICODE_STRING
  USHORT Length;           // in bytes; Buffer need not be NUL-terminated
  USHORT MaximumLength;
  PWSTR Buffer;
};

using LdrLoadDllFn = LONG(NTAPI*)(PCWSTR, ULONG*, LdrUnicodeString*, HANDLE*);

static LdrLoadDllFn RealLdrLoadDll;

static bool IsChromeDll(const LdrUnicodeString* name) {
  if (!name || !name->Buffer) return false;
  int n = name->Length / (int)sizeof(wchar_t);
  int b = 0;
  for (int i = n - 1; i >= 0; i--)
    if (name->Buffer[i] == L'\\' || name->Buffer[i] == L'/') { b = i + 1; break; }
  const wchar_t* k = L"chrome.dll";  // 10 chars, compared case-insensitively
  if (n - b != 10) return false;
  for (int i = 0; i < 10; i++) {
    wchar_t c = name->Buffer[b + i];
    if (c >= L'A' && c <= L'Z') c += 32;
    if (c != k[i]) return false;
  }
  return true;
}

static LONG NTAPI HookLdrLoadDll(PCWSTR searchPath, ULONG* dllChars,
                                 LdrUnicodeString* dllName, HANDLE* dllHandle) {
  LONG st = RealLdrLoadDll(searchPath, dllChars, dllName, dllHandle);
  // Low bits set on the handle mark LOAD_LIBRARY_AS_DATAFILE-style resource
  // loads — not a real mapped image.
  if (st >= 0 && dllHandle && *dllHandle && !((ULONG_PTR)*dllHandle & 3) &&
      IsChromeDll(dllName) && IsBrowserProcess())
    PatchChromeDll((HMODULE)*dllHandle);
  return st;
}

// ---------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD reason, LPVOID) {
  if (reason != DLL_PROCESS_ATTACH) return TRUE;
  DisableThreadLibraryCalls(hModule);

  // Forward our version.dll exports to the real system DLL.
  ForwardExports(hModule);

  // Keep Chrome's children alive despite the non-Microsoft proxy DLL.
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach((PVOID*)&RealUpdateProcThreadAttribute,
               (PVOID)MyUpdateProcThreadAttribute);
  if (DetourTransactionCommit() != NO_ERROR) DBG(L"mitigation hook failed");

  // Patch MV2 gates before any chrome.dll code runs.
  RealLdrLoadDll = (LdrLoadDllFn)GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll");
  if (!RealLdrLoadDll) {
    DBG(L"ntdll!LdrLoadDll not found");
    return TRUE;
  }
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach((PVOID*)&RealLdrLoadDll, (PVOID)HookLdrLoadDll);
  if (DetourTransactionCommit() != NO_ERROR) DBG(L"LdrLoadDll hook failed");

  return TRUE;
}
