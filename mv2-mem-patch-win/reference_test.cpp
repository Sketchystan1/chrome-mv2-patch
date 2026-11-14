// Test-only made-up code checks that searches find the right references and respect their size limits.
#include "autoscan.cpp"
#include <cstdio>
#include <cstdlib>

namespace {
unsigned checks = 0;
void check(bool ok) { ++checks; if (!ok) { std::fprintf(stderr, "Reference fixture failed at check %u\n", checks); std::exit(1); } }
using Bytes = std::array<uint8_t, 0x4400>;
template<class T> void put(Bytes& bytes, size_t at, T value) { memcpy(bytes.data() + at, &value, sizeof(value)); }
Bytes fixture(unsigned textSize) {
  Bytes bytes{}; bool x86 = autoscan::NativeMachine() == IMAGE_FILE_MACHINE_I386;
  put<uint16_t>(bytes, 0, 0x5a4d); put<uint32_t>(bytes, 0x3c, 0x80); put<uint32_t>(bytes, 0x80, 0x4550);
  put<uint16_t>(bytes, 0x84, autoscan::NativeMachine()); put<uint16_t>(bytes, 0x86, 2); put<uint16_t>(bytes, 0x94, x86 ? 0xe0 : 0xf0);
  put<uint16_t>(bytes, 0x98, x86 ? 0x10b : 0x20b);
  if (x86) put<uint32_t>(bytes, 0xb4, 0x400000); else put<uint64_t>(bytes, 0xb0, 0x180000000);
  put<uint32_t>(bytes, 0xd0, 0x6000); put<uint32_t>(bytes, 0xd4, 0x400); put<uint32_t>(bytes, x86 ? 0xf4 : 0x104, 16);
  IMAGE_SECTION_HEADER text{}, data{};
  memcpy(text.Name, ".text", 5); text.Misc.VirtualSize = textSize; text.VirtualAddress = 0x1000;
  text.SizeOfRawData = 0x3000; text.PointerToRawData = 0x400; text.Characteristics = 0x60000020;
  memcpy(data.Name, ".rdata", 6); data.Misc.VirtualSize = 0x1000; data.VirtualAddress = 0x5000;
  data.SizeOfRawData = 0x1000; data.PointerToRawData = 0x3400; data.Characteristics = 0x40000040;
  size_t table = x86 ? 0x178 : 0x188; put(bytes, table, text); put(bytes, table + 40, data);
  std::fill(bytes.begin() + 0x400, bytes.begin() + 0x3400, uint8_t{0xcc});
  memcpy(bytes.data() + 0x3400, "InstallVerifier", 16); memcpy(bytes.data() + 0x3440, "apps-gallery-url", 17);
  return bytes;
}
void reference(Bytes& bytes, unsigned offset, uint32_t literal) {
#if defined(AUTOSCAN_ARM64)
  uint32_t pc = 0x1000 + offset, pages = (literal >> 12) - (pc >> 12);
  put<uint32_t>(bytes, 0x400 + offset, 0x90000000 | ((pages & 3) << 29) | ((pages >> 2) << 5));
  put<uint32_t>(bytes, 0x404 + offset, 0x91000000 | ((literal & 0xfff) << 10));
#elif defined(AUTOSCAN_X86)
  bytes[0x400 + offset] = 0x68; put<uint32_t>(bytes, 0x401 + offset, 0x400000 + literal);
#else
  bytes[0x400 + offset] = 0x48; bytes[0x401 + offset] = 0x8d; bytes[0x402 + offset] = 5;
  put<int32_t>(bytes, 0x403 + offset, static_cast<int32_t>(literal - (0x1000 + offset + 7)));
#endif
}
void verify(Bytes& bytes, uint32_t literal, unsigned expected) {
  autoscan::PeImage pe(bytes); check(pe.valid()); autoscan::RefBatch batch(pe);
  autoscan::FixedList<uint32_t, 64> found;
  check(autoscan::references(pe, literal, found, batch) == (expected <= 64));
  check(found.size() == std::min(expected, 64u));
}
void literalBoundaries() {
  for (unsigned offset : {0u,1u,4u,15u,16u,4096u-17u}) {
    auto bytes = fixture(64); std::fill(bytes.begin() + 0x3400, bytes.end(), uint8_t{0});
    std::memcpy(bytes.data() + 0x3400 + offset, "apps-gallery-url", 17);
    autoscan::PeImage pe(bytes); autoscan::RefBatch found(pe); check(found.gallery == 0x5000 + offset && found.queries.size() == 1);
    bytes[0x3400 + offset + 16] = 'x'; autoscan::RefBatch suffix(pe); check(!suffix.gallery);
    if (offset) { bytes[0x3400 + offset + 16] = 0; bytes[0x3400 + offset - 1] = 'x'; autoscan::RefBatch prefix(pe); check(!prefix.gallery); }
  }
  for (unsigned size : {1u,3u,4u,15u,16u}) {
    auto bytes = fixture(64); std::fill(bytes.begin() + 0x3400, bytes.end(), uint8_t{0});
    std::memcpy(bytes.data() + 0x3400, "apps-gallery-url", 17);
    size_t table = autoscan::NativeMachine() == IMAGE_FILE_MACHINE_I386 ? 0x178 : 0x188;
    put<uint32_t>(bytes, table + 40 + 8, size);
    autoscan::PeImage pe(bytes); check(pe.valid()); autoscan::RefBatch truncated(pe); check(!truncated.gallery);
  }
}
#if !defined(AUTOSCAN_ARM64)
void scalarReferences(const autoscan::PeImage& pe, std::span<autoscan::RefQuery> queries) {
  using namespace autoscan;
  auto code = pe.at(pe.text.rva, pe.text.size);
  for (size_t n = 2; n + 4 <= code.size(); ++n) {
#if defined(AUTOSCAN_X64)
    if ((code[n - 1] & 0xc7) != 5) continue;
    uint8_t op = code[n - 2];
    if (op != 0x8d && !(n >= 3 && code[n - 3] == 0x0f &&
        (op == 0x10 || op == 0x11 || op == 0x28 || op == 0x29 || op == 0x6f || op == 0x7f))) continue;
    int64_t end = static_cast<int64_t>(pe.text.rva) + n + 4;
    int64_t target = end + ReadInsn<int32_t>(code.data() + n);
#else
    int64_t target = int64_t{ReadInsn<uint32_t>(code.data() + n)} - static_cast<int64_t>(pe.imageBase);
    int64_t end = static_cast<int64_t>(pe.text.rva) + n + 4;
#endif
    RefQuery* matching = nullptr;
    for (auto& query : queries) if (query.complete && query.literal == target) { matching = &query; break; }
    if (!matching) continue;
    uint32_t first = static_cast<uint32_t>(std::max<int64_t>(pe.text.rva, end - 15));
    for (uint32_t pc = first; pc + 4 < end; ++pc) {
      auto i = Lift(pe.code(pc), pc);
      if (!i.length() || pc + i.length() != end) continue;
#if defined(AUTOSCAN_X64)
      if (!(i.detail & 0x100) || (op == 0x8d && i.width() != 8)) continue;
#else
      if (!((i.op == Op::MovReg && i.src == NoReg) || (i.op == Op::Other && i.other() == Other::Push && i.dst == NoReg) ||
            (i.memory() && i.disp == static_cast<int32_t>(pe.imageBase + matching->literal)))) continue;
#endif
      if (!matching->found.push_back(pc)) { matching->complete = false; break; }
    }
  }
}
void differentialReferences() {
  uint32_t random = 0x73a19b45;
  for (unsigned size : {6u,7u,8u,9u,17u,18u,19u,20u,21u,22u,31u,32u,33u,34u,35u,36u,37u,38u,63u,64u,65u,128u,1024u,4096u})
    for (unsigned dense = 0; dense < 4; ++dense) {
      auto bytes = fixture(size);
      for (unsigned n = 0; n < size; ++n) {
        random ^= random << 13; random ^= random >> 17; random ^= random << 5;
        bytes[0x400 + n] = dense == 2 ? 5 : static_cast<uint8_t>(random);
      }
      constexpr unsigned length = autoscan::NativeMachine() == IMAGE_FILE_MACHINE_I386 ? 5 : 7;
      if (dense) for (unsigned n = 1; n + length <= size; n += length + 2) {
        unsigned ordinal = n / (length + 2); uint32_t literal = 0x5000 + (ordinal % 3) * 0x40;
        reference(bytes, n, literal);
#if defined(AUTOSCAN_X64)
        bytes[0x402 + n] |= static_cast<uint8_t>((ordinal % 8) << 3);
        if (dense >= 2) {
          constexpr uint8_t ops[] = {0x10,0x11,0x28,0x29,0x6f,0x7f};
          bytes[0x400 + n] = dense == 2 ? 0x0f : 0xcc; bytes[0x401 + n] = ops[ordinal % 6];
        }
#endif
      }
      autoscan::PeImage pe(bytes);
      std::array<autoscan::RefQuery, 3> scalar{}, fast{};
      for (unsigned n = 0; n < scalar.size(); ++n) scalar[n].literal = fast[n].literal = 0x5000 + n * 0x40;
      scalarReferences(pe, scalar); autoscan::scanReferences(pe, fast);
      for (unsigned n = 0; n < scalar.size(); ++n) {
        check(scalar[n].complete == fast[n].complete && scalar[n].found.size() == fast[n].found.size());
        check(std::equal(scalar[n].found.begin(), scalar[n].found.end(), fast[n].found.begin()));
      }
    }
}
void alignmentCollisions() {
  for (unsigned size : {7u,19u,20u,21u,31u,32u,33u,63u,64u,65u,128u}) for (unsigned offset = 1; offset < 33; ++offset) {
    if (offset + 5 > size) continue;
    auto bytes = fixture(size);
    constexpr uint8_t filler[] = {0x20,0x99,0x40,0};
    for (unsigned n = 0; n < size; ++n) bytes[0x400 + n] = filler[n & 3];
    reference(bytes, offset, offset & 1 ? 0x5000 : 0x15000);
    autoscan::PeImage pe(bytes); check(pe.valid());
    std::array<autoscan::RefQuery, 3> original{}, candidate{};
    for (unsigned n = 0; n < 3; ++n) original[n].literal = candidate[n].literal = n == 0 ? 0x5000 : n == 1 ? 0x15000 : 0x5040;
    scalarReferences(pe, original); autoscan::scanReferences(pe, candidate);
    for (unsigned n = 0; n < 3; ++n) {
      check(original[n].complete == candidate[n].complete && original[n].found.size() == candidate[n].found.size());
      check(std::equal(original[n].found.begin(), original[n].found.end(), candidate[n].found.begin()));
    }
  }
  auto bytes = fixture(128);
  reference(bytes, 32, 0x115000);
  autoscan::PeImage pe(bytes);
  std::array<autoscan::RefQuery, 18> original{}, candidate{};
  for (unsigned n = 0; n < original.size(); ++n) original[n].literal = candidate[n].literal = 0x5000 + n * 0x10000;
  scalarReferences(pe, original); autoscan::scanReferences(pe, candidate);
  for (unsigned n = 0; n < original.size(); ++n) {
    check(original[n].complete == candidate[n].complete && original[n].found.size() == candidate[n].found.size());
    check(std::equal(original[n].found.begin(), original[n].found.end(), candidate[n].found.begin()));
  }
}
void cmpStarts() {
  using namespace autoscan;
  std::array<uint8_t, 15> bytes{};
  auto verifyStart = [&] {
    auto i = Lift(bytes, 0x1000);
    check(i.op != Op::CmpImm || i.width() != 4 || (i.imm != 2 && i.imm != 3) || cmpStart(bytes[0]));
  };
  // Cover every first byte and ModRM, including two prefixes that cancel REX.W.
  for (unsigned first = 0; first < 256; ++first)
    for (unsigned modrm = 0; modrm < 256; ++modrm) for (uint8_t value : {2,3}) {
      bytes.fill(0); bytes[0] = static_cast<uint8_t>(first); bytes[1] = static_cast<uint8_t>(modrm);
      for (unsigned at : {1u,2u,3u,4u,5u,6u,7u}) {
        auto old = bytes[at]; bytes[at] = value; verifyStart(); bytes[at] = old;
      }
    }
  for (unsigned first = 0; first < 256; ++first)
    for (uint8_t second : {0x40,0x48,0x4f,0x66,0x67,0x26,0xf0,0xf2,0xf3})
      for (uint8_t value : {2,3}) for (auto body : {
          std::initializer_list<uint8_t>{0x83,0xf8,value}, {0x81,0xf8,value,0,0,0}, {0x3d,value,0,0,0},
          {0x83,0x7a,0x50,value}, {0x81,0xbc,0x24,0x50,0,0,0,value,0,0,0}}) {
        bytes.fill(0); bytes[0] = static_cast<uint8_t>(first); bytes[1] = second;
        std::copy(body.begin(), body.end(), bytes.begin() + 2); verifyStart();
      }
}
#endif
}
int main() {
  literalBoundaries();
#if !defined(AUTOSCAN_ARM64)
  differentialReferences(); alignmentCollisions(); cmpStarts();
#endif
  constexpr unsigned length = autoscan::NativeMachine() == IMAGE_FILE_MACHINE_ARM64 ? 8 : autoscan::NativeMachine() == IMAGE_FILE_MACHINE_I386 ? 5 : 7;
  for (unsigned size : {7u, 8u, 18u, 19u, 20u, 31u, 32u, 33u, 63u, 64u, 65u, 128u})
    for (unsigned offset : {0u, 1u, 2u, 15u, 16u, 31u, 32u}) {
      if (offset + length > size || (length == 8 && (offset & 3)) || (length == 5 && !offset)) continue;
      auto bytes = fixture(size); reference(bytes, offset, 0x5000); verify(bytes, 0x5000, 1);
    }
  for (unsigned count : {0u, 1u, 63u, 64u, 65u, 80u}) {
    auto bytes = fixture(0x3000);
    for (unsigned n = 0; n < count; ++n) reference(bytes, n * 16 + (length == 5 ? 1 : 0), 0x5000);
    reference(bytes, 0x2000 + (length == 5 ? 1 : 0), 0x5040);
    autoscan::PeImage pe(bytes); autoscan::RefBatch batch(pe); autoscan::FixedList<uint32_t, 64> a, b;
    check(autoscan::references(pe, 0x5000, a, batch) == (count <= 64)); check(a.size() == std::min(count, 64u));
    check(autoscan::references(pe, 0x5040, b, batch) && b.size() == 1);
  }
  auto bytes = fixture(64); reference(bytes, length == 5 ? 1 : 0, 0x5800);
  verify(bytes, 0x5800, 1);
  std::fill(bytes.begin() + 0x3400, bytes.end(), uint8_t{0}); verify(bytes, 0x5800, 1);
  for (unsigned n = 0; n < 17; ++n) memcpy(bytes.data() + 0x3400 + n * 16, "InstallVerifier", 16);
  autoscan::PeImage crowded(bytes); autoscan::RefBatch ambiguous(crowded); check(ambiguous.providerAmbiguous && !ambiguous.providerCount);
  bytes = fixture(64); memcpy(bytes.data() + 0x3480, "apps-gallery-url", 17);
  autoscan::PeImage duplicate(bytes); autoscan::RefBatch gallery(duplicate); check(gallery.galleryAmbiguous && !gallery.gallery && gallery.providerCount == 1);
  std::printf("PASS: %u native reference, scalar parity and CMP-start checks\n", checks);
}
