// Compile with the same Detours objects as the DLL; DllMain is not run by this EXE.
#include "../mv2-mem-patch-win/mv2-mem-patch.cpp"
#include <cassert>
#include <cstdio>

static Site Fixture(int kind, const char* code) {
  Site s;
  s.kind = kind;
  s.jgOff = 4;
  s.sig = HexToBytes(std::string("1F090071") + code + "00008052C0035FD6");
  return s;
}

int main() {
  const int kinds[] = {6, 7, 8, 9};
  const char* stock[] = {"7E18", "0F8E12345600", "8D000054", "E0C3881A"};
  const char* patched[] = {"9090", "909090909090", "1F2003D5", "E0E3881A"};
  for (int i = 0; i < 4; ++i) {
    Site s = Fixture(kinds[i], stock[i]);
    std::vector<BYTE> b(128, 0xCC);
    memcpy(b.data() + 64, s.sig.data(), s.sig.size());
    assert(SigAt(b.data(), b.size(), 64, s.sig, 4, s.kind));
    ApplyRes a = ComputeApply(s.kind, b.data() + 68, s.sig.data() + 4);
    auto want = HexToBytes(patched[i]);
    assert(a.stock && !a.done && a.len == (int)want.size());
    assert(memcmp(a.patch, want.data(), want.size()) == 0);
    memcpy(b.data() + 68, a.patch, a.len);
    assert(SigAt(b.data(), b.size(), 64, s.sig, 4, s.kind));
    a = ComputeApply(s.kind, b.data() + 68, s.sig.data() + 4);
    assert(a.done && !a.stock);
    b[68 + want.size() - 1] ^= 1;
    assert(!SigAt(b.data(), b.size(), 64, s.sig, 4, s.kind));
    b[68] ^= 1;
    assert(!SigAt(b.data(), b.size(), 64, s.sig, 4, s.kind));
  }

  auto parsed = ParseMilestones(JParser(R"({"milestones":[],"milestones_v2":[{"container":"pe","sites":[{"kind":"near-nop","jgOff":4,"expectedMatches":1,"sig":"1F0900710F8E1234560000008052C0035FD6"}]}]})").val(), "pe");
  assert(parsed.size() == 1 && parsed[0].sites[0].kind == 7);
  for (const char* bad : {"new-unknown-kind", "bcond-nop"}) {
    std::string json = std::string(R"({"milestones":[],"milestones_v2":[{"container":"pe","sites":[{"kind":")") + bad + R"(","jgOff":4,"sig":"1F0900718D00005400008052C0035FD6"}]}]})";
    bool refused = false;
    try { ParseMilestones(JParser(json).val(), "pe"); } catch (...) { refused = true; }
    assert(refused);
  }

  Image img;
  img.textSize = 256;
  img.machine = IMAGE_FILE_MACHINE_AMD64;
  std::vector<BYTE> buf(256, 0xCC);
  Site first = Fixture(6, stock[0]), second = Fixture(7, stock[1]);
  Site missing = Fixture(9, stock[3]);
  missing.optional = true;
  Milestone m;
  m.sites = {first, second, missing};
  memcpy(buf.data() + 32, first.sig.data(), first.sig.size());
  memcpy(buf.data() + 96, second.sig.data(), second.sig.size());
  std::vector<std::pair<Site, std::vector<long long>>> located;
  bool full = false;
  assert(Locate(buf.data(), buf.size(), img, {m}, &located, &full));
  assert(full && located.size() == 2 && located[0].second[0] == 36 && located[1].second[0] == 100);
  assert(!Locate(buf.data(), buf.size(), img, {m, m}, &located));
  buf[96] ^= 1;
  assert(!Locate(buf.data(), buf.size(), img, {m}, &located));
  buf[96] ^= 1;
  memcpy(buf.data() + 160, first.sig.data(), first.sig.size());
  assert(!Locate(buf.data(), buf.size(), img, {m}, &located));

  // A six-byte JLE spanning two pages must be fully patched and re-protected.
  BYTE* mem = (BYTE*)VirtualAlloc(nullptr, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  assert(mem);
  memcpy(mem + 0x1FFE, second.sig.data() + 4, 6);
  DWORD old;
  assert(VirtualProtect(mem, 0x4000, PAGE_EXECUTE_READ, &old));
  img.textSize = 0x4000;
  ApplyInProcess(mem, img, {{second, {0x1FFE}}});
  assert(memcmp(mem + 0x1FFE, HexToBytes(patched[1]).data(), 6) == 0);
  MEMORY_BASIC_INFORMATION info{};
  assert(VirtualQuery(mem + 0x2000, &info, sizeof(info)) && info.Protect == PAGE_EXECUTE_READ);
  VirtualFree(mem, 0, MEM_RELEASE);

  std::puts("Memory patcher tests passed");
  return 0;
}
