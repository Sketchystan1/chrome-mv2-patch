// mv2_core.hpp - portable C++ core for the macOS memory-patch launcher.
//
// This is a straight port of the pieces of the Windows launcher
// (mv2-launcher/mv2-launcher.cpp) that are OS-independent:
//   - the tiny signatures.json parser (JV / JParser)
//   - the milestone/site model + HexToBytes
//   - the .text signature matcher (SigAt) and milestone selector (Locate)
//   - the per-kind apply table (short / near / bcond)
// plus the Mach-O (fat + thin) parser that the Windows PE parser stands in for.
//
// NO Objective-C and NO Mach here on purpose: everything in this header is
// pure byte math over a read-only view of the on-disk framework, so it is
// trivially testable and identical to what the .ps1/.sh/PE launcher do.
//
// Container scope: this build keeps ONLY "macho-x64" and "macho-arm64".
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <utility>
#include <stdexcept>
#include <algorithm>

namespace mv2 {

// kind: 0 = short jg (7F->EB), 1 = near jg (0F8F->90E9), 2 = AArch64 b.cond (GT->AL)
struct Site { std::string name; int kind = 0; std::vector<uint8_t> sig; int jgOff = 0; int expected = 1; };
struct Milestone { std::string name, container; std::vector<Site> sites; };

// ------------------------------------------------------------------ JSON ----
// Verbatim port of the Windows launcher's subset JSON parser.
struct JV {
  enum T { NUL, BOOL, NUM, STR, ARR, OBJ } t = NUL;
  bool b = false; double num = 0; std::string str;
  std::vector<JV> arr; std::vector<std::pair<std::string, JV>> obj;
  const JV* get(const char* k) const { for (auto& kv : obj) if (kv.first == k) return &kv.second; return nullptr; }
};

struct JParser {
  std::string s;                       // owned copy: callers may pass temporaries
  const char* p; const char* e;
  explicit JParser(const std::string& src) : s(src), p(s.data()), e(s.data() + s.size()) {}
  [[noreturn]] static void err() { throw std::runtime_error("bad signatures.json"); }
  void ws() { while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p; }
  bool lit(const char* w) { size_t n = strlen(w); if (e - p < (ptrdiff_t)n || strncmp(p, w, n) != 0) return false; p += n; return true; }
  JV val() {
    ws();
    if (p < e && *p == '{') {
      ++p; JV v; v.t = JV::OBJ; ws();
      if (p < e && *p == '}') { ++p; return v; }
      for (;;) {
        ws(); std::string k = str(); ws();
        if (p >= e || *p != ':') err(); ++p;
        v.obj.emplace_back(std::move(k), val()); ws();
        if (p < e && *p == ',') { ++p; continue; }
        if (p < e && *p == '}') { ++p; return v; }
        err();
      }
    }
    if (p < e && *p == '[') {
      ++p; JV v; v.t = JV::ARR; ws();
      if (p < e && *p == ']') { ++p; return v; }
      for (;;) {
        v.arr.push_back(val()); ws();
        if (p < e && *p == ',') { ++p; continue; }
        if (p < e && *p == ']') { ++p; return v; }
        err();
      }
    }
    if (p < e && *p == '"') { JV v; v.t = JV::STR; v.str = str(); return v; }
    if (lit("true")) { JV v; v.t = JV::BOOL; v.b = true; return v; }
    if (lit("false")) { JV v; v.t = JV::BOOL; v.b = false; return v; }
    if (lit("null")) { JV v; v.t = JV::NUL; return v; }
    JV v; v.t = JV::NUM; char* end = nullptr; v.num = strtod(p, &end); if (end == p) err(); p = end; return v;
  }
  std::string str() {
    if (p >= e || *p != '"') err(); ++p; std::string out;
    while (p < e && *p != '"') {
      char c = *p++;
      if (c != '\\') { out += c; continue; }
      if (p >= e) err();
      char x = *p++;
      switch (x) {
        case '"': out += '"'; break; case '\\': out += '\\'; break; case '/': out += '/'; break;
        case 'b': out += '\b'; break; case 'f': out += '\f'; break; case 'n': out += '\n'; break;
        case 'r': out += '\r'; break; case 't': out += '\t'; break;
        case 'u': {
          if (e - p < 4) err();
          unsigned cp = 0; for (int i = 0; i < 4; i++) { char h = *p++; cp <<= 4; cp |= (h <= '9') ? (h - '0') : ((h | 32) - 'a' + 10); }
          if (cp < 0x80) out += (char)cp;
          else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
          else { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
          break;
        }
        default: err();
      }
    }
    if (p >= e) err(); ++p; return out;
  }
};

inline std::vector<uint8_t> HexToBytes(const std::string& h) {
  std::vector<uint8_t> b(h.size() / 2);
  for (size_t i = 0; i < b.size(); i++) b[i] = (uint8_t)strtoul(h.substr(i * 2, 2).c_str(), nullptr, 16);
  return b;
}

// Keep macho-x64 / macho-arm64 milestones only; map kind string -> int; validate.
inline std::vector<Milestone> ParseMilestones(const JV& doc) {
  std::vector<Milestone> out;
  const JV* ms = doc.get("milestones");
  if (!ms || ms->t != JV::ARR) return out;
  for (const JV& m : ms->arr) {
    const JV* cont = m.get("container");
    if (!cont || (cont->str != "macho-x64" && cont->str != "macho-arm64")) continue;
    Milestone mo; mo.name = m.get("name") ? m.get("name")->str : "?"; mo.container = cont->str;
    const JV* sites = m.get("sites");
    if (!sites || sites->t != JV::ARR) continue;
    for (const JV& sd : sites->arr) {
      Site s;
      s.name = sd.get("name") ? sd.get("name")->str : "?";
      std::string k = sd.get("kind") ? sd.get("kind")->str : "short";
      s.kind = (k == "bcond") ? 2 : (k == "near") ? 1 : 0;
      s.sig = HexToBytes(sd.get("sig") ? sd.get("sig")->str : "");
      s.jgOff = sd.get("jgOff") ? (int)sd.get("jgOff")->num : 0;
      s.expected = sd.get("expectedMatches") ? (int)sd.get("expectedMatches")->num : 1;
      int need = (s.kind == 2) ? 4 : (s.kind == 1) ? 6 : 2;      // bytes the matcher touches at/after jgOff
      if (s.sig.size() < 2 || s.jgOff < 0 || s.expected < 1 || (int)s.sig.size() < s.jgOff + need) continue;
      mo.sites.push_back(std::move(s));
    }
    if (!mo.sites.empty()) out.push_back(std::move(mo));
  }
  return out;
}

// ------------------------------------------------------------- Mach-O -------
// Both x86_64 and arm64 macOS are little-endian; only the FAT wrapper header is
// stored big-endian. We read fields explicitly to avoid any host-endian doubt.
enum { C_X64 = 0, C_ARM64 = 1 };
constexpr uint32_t MV2_CPU_X86_64 = 0x01000007;
constexpr uint32_t MV2_CPU_ARM64  = 0x0100000C;

struct HostSlice {
  bool ok = false;
  int container = -1;                 // C_X64 / C_ARM64
  uint64_t sliceFileOffset = 0;       // start of this thin Mach-O within the (possibly fat) file
  uint64_t textFileOff = 0;           // __text section file offset, SLICE-relative
  uint64_t textVMAddr = 0;            // __text link-time vmaddr
  uint64_t textSize = 0;
  uint64_t segTextVMAddr = 0;         // __TEXT segment vmaddr (== image preferred base)
};

inline uint32_t rd_le32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
inline uint64_t rd_le64(const uint8_t* p) { return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32); }
inline uint32_t rd_be32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]; }
inline uint64_t rd_be64(const uint8_t* p) { return ((uint64_t)rd_be32(p) << 32) | (uint64_t)rd_be32(p + 4); }

inline bool seg16eq(const uint8_t* name, const char* want) {
  return strncmp((const char*)name, want, 16) == 0;
}

// Parse the __TEXT,__text of the slice whose cputype == wantCpu.
// Handles fat32 (CAFEBABE), fat64 (CAFEBABF) and thin 64-bit (FEEDFACF, LE).
inline bool ParseMachO(const uint8_t* b, size_t n, uint32_t wantCpu, HostSlice& out) {
  if (n < 4) return false;
  uint64_t sliceOff = 0, sliceSize = n;
  bool haveSlice = false;

  if (b[0] == 0xCA && b[1] == 0xFE && b[2] == 0xBA && (b[3] == 0xBE || b[3] == 0xBF)) {
    bool is64 = (b[3] == 0xBF);
    if (n < 8) return false;
    uint32_t nfat = rd_be32(b + 4);
    size_t archSz = is64 ? 32 : 20;
    for (uint32_t i = 0; i < nfat; i++) {
      size_t a = 8 + (size_t)i * archSz;
      if (a + archSz > n) break;
      uint32_t cpu = rd_be32(b + a);
      uint64_t off, sz;
      if (is64) { off = rd_be64(b + a + 8); sz = rd_be64(b + a + 16); }
      else      { off = rd_be32(b + a + 8); sz = rd_be32(b + a + 12); }
      if (cpu == wantCpu) { sliceOff = off; sliceSize = sz; haveSlice = true; break; }
    }
    if (!haveSlice) return false;                 // host slice not present in this fat binary
  } else if (b[0] == 0xCF && b[1] == 0xFA && b[2] == 0xED && b[3] == 0xFE) {
    // thin 64-bit Mach-O (MH_MAGIC_64 stored little-endian)
    if (n < 8) return false;
    uint32_t cpu = rd_le32(b + 4);
    if (cpu != wantCpu) return false;
    sliceOff = 0; sliceSize = n; haveSlice = true;
  } else {
    return false;                                 // unsupported / 32-bit / big-endian
  }

  if (sliceOff + 32 > n) return false;
  const uint8_t* mh = b + sliceOff;
  if (!(mh[0] == 0xCF && mh[1] == 0xFA && mh[2] == 0xED && mh[3] == 0xFE)) return false; // MH_MAGIC_64
  uint32_t ncmds = rd_le32(mh + 16);
  uint64_t p = sliceOff + 32;                     // load commands follow the 32-byte header
  const uint32_t MV2_LC_SEGMENT_64 = 0x19;
  bool foundText = false;
  for (uint32_t c = 0; c < ncmds; c++) {
    if (p + 8 > n) break;
    uint32_t cmd = rd_le32(b + p);
    uint32_t cmdsize = rd_le32(b + p + 4);
    if (cmdsize < 8 || p + cmdsize > n) break;
    if (cmd == MV2_LC_SEGMENT_64) {
      const uint8_t* seg = b + p;                 // segment_command_64
      if (seg16eq(seg + 8, "__TEXT")) {
        uint64_t segVM = rd_le64(seg + 24);       // vmaddr
        uint32_t nsects = rd_le32(seg + 64);
        uint64_t sp = p + 72;                      // first section_64
        for (uint32_t si = 0; si < nsects; si++) {
          if (sp + 80 > n) break;
          const uint8_t* sec = b + sp;             // section_64
          if (seg16eq(sec + 0, "__text")) {        // sectname
            out.sliceFileOffset = sliceOff;
            out.textVMAddr = rd_le64(sec + 32);    // addr
            out.textSize   = rd_le64(sec + 40);    // size
            out.textFileOff = rd_le32(sec + 48);   // offset (slice-relative)
            out.segTextVMAddr = segVM;
            foundText = true;
          }
          sp += 80;
        }
      }
    }
    p += cmdsize;
  }
  if (!foundText) return false;
  out.ok = true;
  out.container = (wantCpu == MV2_CPU_ARM64) ? C_ARM64 : C_X64;
  return true;
}

// ---------------------------------------------------------- matching --------
// Match sig at absolute offset `start`, wildcarding the branch opcode and its
// displacement so BOTH stock and already-patched builds match (idempotent).
inline bool SigAt(const uint8_t* b, size_t n, uint64_t start, const std::vector<uint8_t>& sig, int jgOff, int kind) {
  if (start + sig.size() > n) return false;
  for (size_t k = 0; k < sig.size(); k++) {
    uint8_t p = b[start + k];
    if ((int)k == jgOff) {
      if (kind == 0) {                             // short jg: 7F stock / EB done
        if (p != 0x7F && p != 0xEB) return false;
      } else if (kind == 1) {                      // near jg: 0F 8F stock / 90 E9 done
        uint8_t p1 = b[start + jgOff + 1];
        if (!((p == 0x0F && p1 == 0x8F) || (p == 0x90 && p1 == 0xE9))) return false;
      } else {                                     // bcond: 0x54 word, cond nibble 0xC stock / 0xE done, o0(bit4)=0
        if (b[start + jgOff + 3] != 0x54) return false;
        if ((p & 0x10) != 0) return false;
        uint8_t lo = p & 0x0F;
        if (lo != 0x0C && lo != 0x0E) return false;
      }
    } else if (kind == 0 && (int)k == jgOff + 1) {           // disp8 wild
    } else if (kind == 1 && (int)k >= jgOff + 2 && (int)k <= jgOff + 5) { // disp32 wild
    } else if (kind == 2 && ((int)k == jgOff + 1 || (int)k == jgOff + 2)) { // imm19 wild
    } else if (p != sig[k]) return false;
  }
  return true;
}

struct SiteHit { Site site; std::vector<uint64_t> branchOffsets; }; // absolute file offsets of the branch byte

// Sweep [scanStart, scanEnd) once; pick the winning milestone (full beats
// partial; among fulls the one with more sites; exact tie declines).
inline bool Locate(const uint8_t* buf, size_t bufN, uint64_t scanStart, uint64_t scanEnd,
                   const std::vector<Milestone>& milestones, const std::string& hostContainer,
                   Milestone& winner, std::vector<SiteHit>& perSiteOut, bool& full) {
  full = false;
  if (scanEnd > bufN) scanEnd = bufN;
  if (scanStart >= scanEnd) return false;

  struct Job { int m, si; const Site* s; };
  std::vector<Job> byFirst[256];
  std::vector<int> mIdx;                           // indices of host-container milestones
  for (int m = 0; m < (int)milestones.size(); m++) {
    if (milestones[m].container != hostContainer) continue;
    mIdx.push_back(m);
    for (int si = 0; si < (int)milestones[m].sites.size(); si++)
      byFirst[milestones[m].sites[si].sig[0]].push_back({ m, si, &milestones[m].sites[si] });
  }
  if (mIdx.empty()) return false;

  std::vector<std::vector<std::vector<uint64_t>>> hits(milestones.size());
  for (int m : mIdx) hits[m].resize(milestones[m].sites.size());

  for (uint64_t i = scanStart; i < scanEnd; i++) {
    for (const Job& j : byFirst[buf[i]]) {
      if (i + 1 < scanEnd && buf[i + 1] == j.s->sig[1] && SigAt(buf, bufN, i, j.s->sig, j.s->jgOff, j.s->kind))
        hits[j.m][j.si].push_back(i + j.s->jgOff);
    }
  }

  Milestone fullMs, partMs; int fullSites = 0, partOk = 0, fullCount = 0;
  std::vector<SiteHit> fullPer, partPer;
  std::vector<uint64_t> fullOffs;                  // flat sorted branch offsets of the current full winner
  auto flatOffs = [](const std::vector<SiteHit>& per) {
    std::vector<uint64_t> v;
    for (const auto& sh : per) for (uint64_t o : sh.branchOffsets) v.push_back(o);
    std::sort(v.begin(), v.end());
    return v;
  };
  for (int m : mIdx) {
    const Milestone& ms = milestones[m];
    std::vector<SiteHit> per;
    int ok = 0;
    for (int si = 0; si < (int)ms.sites.size(); si++) {
      auto& h = hits[m][si];
      if ((int)h.size() == ms.sites[si].expected) ok++;
      per.push_back({ ms.sites[si], h });
    }
    if (ok == (int)ms.sites.size()) {
      if (fullSites == 0 || (int)ms.sites.size() > fullSites) { fullMs = ms; fullSites = (int)ms.sites.size(); fullPer = per; fullCount = 1; fullOffs = flatOffs(per); }
      else if ((int)ms.sites.size() == fullSites) {
        // Only a full match that targets DIFFERENT bytes is truly ambiguous.
        // Duplicate milestones that resolve to the identical gate offsets (e.g.
        // an arm64 table reused verbatim across two version labels - 152 and 154)
        // patch the same thing, so keep the first winner instead of declining.
        if (flatOffs(per) != fullOffs) fullCount++;
      }
    } else if (ok > 0 && fullSites == 0 && ok > partOk) { partMs = ms; partOk = ok; partPer = per; }
  }
  if (fullCount > 1) return false;                 // ambiguous full match: decline
  if (fullSites > 0) { winner = fullMs; perSiteOut = std::move(fullPer); full = true; return true; }
  if (partOk > 0) { winner = partMs; perSiteOut = std::move(partPer); return true; }
  return false;
}

// ------------------------------------------------------------- apply --------
struct ApplyRes { std::vector<uint8_t> patch; bool isStock = false; bool isDone = false; bool known = false; };

// Given the 2 current bytes at the branch, decide the write. Read is always 2
// bytes; write is 1 (short/bcond) or 2 (near).
inline ApplyRes ComputeApply(int kind, const uint8_t cur[2]) {
  ApplyRes r;
  if (kind == 0) {                                 // short
    r.isStock = (cur[0] == 0x7F); r.isDone = (cur[0] == 0xEB);
    r.patch = { 0xEB };
  } else if (kind == 1) {                          // near
    r.isStock = (cur[0] == 0x0F && cur[1] == 0x8F); r.isDone = (cur[0] == 0x90 && cur[1] == 0xE9);
    r.patch = { 0x90, 0xE9 };
  } else {                                         // bcond: rewrite condition nibble GT(0xC)->AL(0xE)
    uint8_t lo = cur[0] & 0x0F;
    r.isStock = (lo == 0x0C); r.isDone = (lo == 0x0E);
    r.patch = { (uint8_t)((cur[0] & 0xF0) | 0x0E) };
  }
  r.known = r.isStock || r.isDone;
  return r;
}

// Absolute .text file offset of the branch byte -> runtime virtual address in
// the loaded image. imageLoadAddr is the framework's load address in the target
// (from dyld). slide = imageLoadAddr - segment __TEXT vmaddr.
inline uint64_t RuntimeAddr(const HostSlice& s, uint64_t branchAbsFileOff, uint64_t imageLoadAddr) {
  uint64_t vmaddrOfByte = s.textVMAddr + (branchAbsFileOff - s.sliceFileOffset - s.textFileOff);
  uint64_t slide = imageLoadAddr - s.segTextVMAddr;
  return vmaddrOfByte + slide;
}

// --------------------------------------------------------- TOML (config) ----
// Minimal readers, ported from the Windows launcher, for the TOML config
// format. Only used for defaults; safe to ignore.
inline bool TomlStr(const std::string& in, std::string& out) {
  if (in.size() < 2) return false;
  char q = in[0];
  if (q != '"' && q != '\'') return false;
  out.clear();
  for (size_t i = 1; i < in.size(); i++) {
    char ch = in[i];
    if (q == '"' && ch == '\\' && i + 1 < in.size()) {
      char nx = in[++i];
      switch (nx) { case 'n': out += '\n'; break; case 't': out += '\t'; break; case 'r': out += '\r'; break; default: out += nx; }
      continue;
    }
    if (ch == q) return true;
    out += ch;
  }
  return false;
}

inline std::vector<std::string> TomlArray(const std::string& in) {
  std::vector<std::string> out;
  size_t i = in.find('[');
  if (i == std::string::npos) return out;
  for (i++; i < in.size(); ) {
    while (i < in.size() && (in[i] == ' ' || in[i] == '\t' || in[i] == ',')) i++;
    if (i >= in.size() || in[i] == ']') break;
    if (in[i] != '"' && in[i] != '\'') { i++; continue; }
    char q = in[i]; std::string s; size_t j = i + 1;
    for (; j < in.size(); j++) {
      char ch = in[j];
      if (q == '"' && ch == '\\' && j + 1 < in.size()) {
        char nx = in[++j];
        switch (nx) { case 'n': s += '\n'; break; case 't': s += '\t'; break; case 'r': s += '\r'; break; default: s += nx; }
        continue;
      }
      if (ch == q) break;
      s += ch;
    }
    out.push_back(s);
    i = j + 1;
  }
  return out;
}

} // namespace mv2
