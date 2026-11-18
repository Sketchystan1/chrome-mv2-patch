// Test-only made-up instructions check reading code, number ranges and safe pointer changes.
// Pointer changes use memory allocated by this test, which is released afterward.
#include "solver.hpp"
#include "autoscan_runtime.h"
#include <cstdio>
#include <cstdlib>
#include <cwchar>

namespace {
unsigned checks = 0;
void check(bool condition, const char* message) {
  ++checks;
  if (!condition) { std::fprintf(stderr, "FAIL %u: %s\n", checks, message); std::exit(1); }
}
template<class T, size_t N> void put(std::array<uint8_t, N>& bytes, size_t at, T value) {
  std::memcpy(bytes.data() + at, &value, sizeof(value));
}
std::array<uint8_t, 0x800> fixture(uint16_t machine) {
  std::array<uint8_t, 0x800> bytes{};
  bool x86 = machine == IMAGE_FILE_MACHINE_I386;
  put<uint16_t>(bytes, 0, IMAGE_DOS_SIGNATURE); put<uint32_t>(bytes, 0x3c, 0x80);
  put<uint32_t>(bytes, 0x80, IMAGE_NT_SIGNATURE); put<uint16_t>(bytes, 0x84, machine);
  put<uint16_t>(bytes, 0x86, 3); put<uint16_t>(bytes, 0x94, x86 ? 0xe0 : 0xf0);
  put<uint16_t>(bytes, 0x98, x86 ? 0x10b : 0x20b);
  if (x86) put<uint32_t>(bytes, 0xb4, 0x400000); else put<uint64_t>(bytes, 0xb0, 0x180000000);
  put<uint32_t>(bytes, 0xd0, 0x4000); put<uint32_t>(bytes, 0xd4, 0x200);
  put<uint32_t>(bytes, x86 ? 0xf4 : 0x104, 16);
  size_t section = x86 ? 0x178 : 0x188;
  for (unsigned n = 0; n < 3; ++n) {
    IMAGE_SECTION_HEADER header{};
    std::memcpy(header.Name, n == 0 ? ".text" : n == 1 ? ".pdata" : ".rdata", n == 0 ? 5 : 6);
    header.Misc.VirtualSize = header.SizeOfRawData = 0x200;
    header.VirtualAddress = 0x1000 * (n + 1); header.PointerToRawData = 0x200 * (n + 1);
    header.Characteristics = n == 0 ? 0x60000020 : 0x40000040;
    put(bytes, section + n * sizeof(header), header);
  }
  return bytes;
}
void lengths() {
  using namespace autoscan;
  constexpr std::array<uint8_t, 8> load{0x4d,0x8b,0x84,0x24,0x78,0x56,0x34,0x12};
  auto i = LiftX86(load, 0x1000, true);
  check(i.length() == 8 && i.op == Op::LoadField && i.dst == 8 && i.src == 12 && i.disp == 0x12345678 && i.width() == 8,
        "REX and SIB keep base, destination and displacement distinct");
  for (size_t n = 0; n < load.size(); ++n) check(!LiftX86(std::span(load).first(n), 0x1000, true).length(), "all truncations decline");
  constexpr std::array<uint8_t, 4> sub{0x48,0x83,0xe9,0x80};
  i = LiftX86(sub, 0x1000, true);
  check(i.op == Op::AddImm && i.imm == 128 && i.dst == 1 && i.setsFlags(), "SUB sign-extends imm8 before negating");
  constexpr std::array<uint8_t, 3> lea{0x8d,0x41,0xfc};
  i = LiftX86(lea, 0x1000, false);
  check(i.op == Op::AddImm && i.imm == -4 && !i.setsFlags(), "LEA preserves flags");
  constexpr std::array<uint8_t, 5> stackRead{0x4c,0x03,0x74,0x24,0x48};
  i = LiftX86(stackRead, 0x1000, true);
  check(i.length() == 5 && i.other() == Other::Overwrite && i.dst == 14 && i.src == 4 && i.disp == 0x48 &&
        i.memory() && i.setsFlags() && Writes(i, 14) && !Writes(i, 4), "ADD from a stack slot writes only its destination and flags");
  for (bool x64 : {false, true}) {
    for (auto code : {std::array<uint8_t, 3>{0xc1,0xe0,2}, {0xc1,0xfa,2}}) {
      i = LiftX86(code, 0x1000, x64);
      check(i.length() == 3 && i.width() == 4 && !i.memory() && i.setsFlags() &&
            Writes(i, code[1] & 7) && !Writes(i, 4) && !Writes(i, 5),
            "register SHL/SAR preserve the stack and frame while invalidating their destination and flags");
    }
    constexpr std::array<uint8_t, 2> registerSubtract{0x29,0xca};
    i = LiftX86(registerSubtract, 0x1000, x64);
    check(i.length() == 2 && i.width() == 4 && i.src == 1 && i.setsFlags() && Writes(i, 2) &&
          !Writes(i, 1) && !Writes(i, 4) && !Writes(i, 5),
          "register SUB retains its input and frame while invalidating its destination and flags");
  }
  constexpr std::array<uint8_t, 4> extendedShift{0x49,0xc1,0xfe,2};
  i = LiftX86(extendedShift, 0x1000, true);
  check(i.length() == 4 && i.width() == 8 && i.setsFlags() && Writes(i, 14) && !Writes(i, 4) && !Writes(i, 5),
        "REX.W SAR invalidates its extended destination without clobbering the frame");
  for (auto code : {std::array<uint8_t, 3>{0xc1,0x20,2}, {0xc1,0xc0,2}, {0xc0,0xfa,2}})
    check(LiftX86(code, 0x1000, false).other() == Other::Unknown,
          "memory shifts, rotations and unmodeled byte shifts retain conservative rejection");
  constexpr std::array<uint8_t, 2> memorySubtract{0x29,0x08};
  check(LiftX86(memorySubtract, 0x1000, false).other() == Other::Unknown,
        "unmodeled memory subtraction cannot be mistaken for a register overwrite");
  constexpr std::array<uint8_t, 6> back{0x0f,0x8d,0xf0,0xff,0xff,0xff};
  i = LiftX86(back, 0x1000, true);
  check(i.op == Op::JccSigned && i.target() == 0xff6 && i.condition() == 13, "near branch sign extension");
  constexpr std::array<uint8_t, 2> underflow{0xeb,0x80};
  check(!LiftX86(underflow, 0, true).length(), "RVA arithmetic cannot wrap");
  constexpr std::array<uint8_t, 4> bad{0xc5,0xf8,0x77,0xc3};
  check(!LiftX86(bad, 0x1000, true).length(), "unlisted VEX opcodes never guess a length");
  constexpr std::array<uint8_t, 6> evex{0x62,0xf1,0x7c,0x48,0x58,0xc0};
  constexpr std::array<uint8_t, 6> xop{0x8f,0xe8,0x78,0x85,0xc0,0};
  check(!LiftX86(evex, 0x1000, false).length() && !LiftX86(xop, 0x1000, true).length(), "EVEX/XOP cannot masquerade as BOUND or POP");
  std::array<uint8_t, 16> prefix{}; prefix.fill(0x66); prefix.back() = 0x90;
  check(!LiftX86(prefix, 0x1000, true).length(), "instruction length is capped at 15");
  constexpr std::array<uint8_t, 7> signedMov{0x48,0xc7,0xc0,0xff,0xff,0xff,0xff};
  i = LiftX86(signedMov, 0x1000, true);
  check(i.op == Op::MovReg && i.imm == -1 && i.detail == UINT32_MAX, "MOV r64, imm32 sign-extends");
  for (auto code : {std::array<uint8_t, 3>{0xc6,0xc4,1}, {0x80,0xfc,2}, {0xf6,0xc4,1}}) {
    i = LiftX86(code, 0x1000, false);
    check(i.op == Op::Other && i.other() == Other::Unknown, "high-byte registers never alias stack registers");
  }
  for (bool x64 : {false, true}) {
    constexpr std::array<uint8_t, 3> highSet{0x0f,0x95,0xc7};
    i = LiftX86(highSet, 0x1000, x64);
    check(i.other() == Other::Overwrite && i.dst == 3 && i.width() == 1 && Writes(i, 3) && !Writes(i, 4) && !Writes(i, 5) && !i.setsFlags(),
          "SETNE BH invalidates EBX without clobbering a frame or inventing a low-byte value");
    constexpr std::array<uint8_t, 2> highTest{0x84,0xfb};
    i = LiftX86(highTest, 0x1000, x64);
    check(i.other() == Other::TestReg && i.dst == NoReg && i.src == NoReg && i.width() == 1 && i.setsFlags() && !Writes(i, 3) && !Writes(i, 5),
          "TEST BL,BH changes only flags and never becomes a TEST BL,BL proof");
  }
  constexpr std::array<uint8_t, 4> rexSet{0x40,0x0f,0x95,0xc7};
  i = LiftX86(rexSet, 0x1000, true);
  check(i.other() == Other::Setcc && i.dst == 7, "REX retains the low-byte DIL destination");
  constexpr std::array<uint8_t, 6> extrq{0x66,0x0f,0x78,0xc0,1,2};
  check(!LiftX86(extrq, 0x1000, true).length(), "unlisted two-immediate SSE form declines");
  constexpr std::array<uint8_t, 7> ripLea{0x48,0x8d,0x0d,0,0,0,0};
  i = LiftX86(ripLea, 0x1000, true);
  check(i.other() == Other::Overwrite && i.dst == 1 && (i.detail & 0x100), "RIP-relative LEA preserves flags and clobbers only its destination");
  constexpr std::array<uint8_t, 4> decrement{0xf0,0xff,0x49,8};
  i = LiftX86(decrement, 0x1000, true);
  check(i.length() == 4 && i.other() == Other::AtomicAdd && i.dst == NoReg && i.src == 1 && i.disp == 8 &&
        i.memory() && !Writes(i, 4), "locked reference-count decrement updates memory without changing RSP");
  constexpr std::array<uint8_t, 3> invalidLock{0xf0,0xff,0xcc};
  check(LiftX86(invalidLock, 0x1000, true).other() == Other::Unknown, "LOCK on a register cannot masquerade as a memory update");
  constexpr std::array<uint8_t, 8> padding{0x66,0x2e,0x0f,0x1f,0x44,0x00,0,0xc3};
  i = LiftX86(padding, 0x1000, true);
  check(i.length() == 7 && i.other() == Other::Nop, "segment-prefixed indexed NOP is padding");
  std::array<uint8_t, 4> word{};
  put<uint32_t>(word, 0, 0xf9400820);
  i = LiftArm64(word, 0x1000);
  check(i.op == Op::LoadField && i.width() == 8 && i.src == 1 && i.dst == 0 && i.disp == 16, "ARM64 LDR scales imm12");
  put<uint32_t>(word, 0, 0x54ffffec);
  i = LiftArm64(word, 0x1000);
  check(i.op == Op::JccSigned && i.condition() == 15 && i.target() == 0xffc, "ARM64 branch offset is signed and instruction-relative");
  check(!LiftArm64(word, 0x1001).length(), "unaligned ARM64 instruction declines");
  put<uint32_t>(word, 0, 0x7100083f);
  i = LiftArm64(word, 0x1000);
  check(i.op == Op::CmpImm && i.dst == 1 && i.width() == 4 && i.imm == 2, "ARM64 SUBS WZR becomes CMP");
  for (unsigned cc = 10; cc <= 13; ++cc) {
    put<uint32_t>(word, 0, 0x54000040 | cc);
    i = LiftArm64(word, 0x1000);
    constexpr unsigned expected[] = {13,12,15,14};
    check(i.op == Op::JccSigned && i.condition() == expected[cc - 10] && i.target() == 0x1008, "ARM64 signed conditions map to the shared interval order");
  }
  put<uint32_t>(word, 0, 0x71000bff);
  check(LiftArm64(word, 0x1000).op == Op::Other, "CMP WZR cannot infer a stack field");
  put<uint32_t>(word, 0, 0x5280003f);
  check(LiftArm64(word, 0x1000).other() == Other::Nop, "writing WZR does not overwrite SP");
  put<uint32_t>(word, 0, 0xf94003ff);
  check(LiftArm64(word, 0x1000).op == Op::Other, "LDR XZR cannot overwrite SP");
}
void intervals() {
  using namespace autoscan;
  for (int32_t threshold : {INT32_MIN, -3, 2, 3, INT32_MAX}) {
    for (unsigned cc : {12u,13u,14u,15u}) {
      auto parts = SplitSigned({}, cc, threshold);
      check(Intersect(parts.taken, parts.fallthrough).empty(), "taken and fallthrough never overlap");
      for (int64_t value : {int64_t{INT32_MIN}, int64_t{INT32_MAX}, int64_t{threshold} - 1, int64_t{threshold}, int64_t{threshold} + 1}) {
        if (value < INT32_MIN || value > INT32_MAX) continue;
        bool expected = cc == 12 ? value < threshold : cc == 13 ? value >= threshold : cc == 14 ? value <= threshold : value > threshold;
        check(parts.taken.contains(static_cast<int32_t>(value)) == expected && parts.fallthrough.contains(static_cast<int32_t>(value)) != expected,
              "signed interval split covers both extrema without overflow");
      }
    }
  }
  auto parts = SplitSigned({0,2}, 15, 2);
  check(parts.taken.empty() && parts.fallthrough.low == 0 && parts.fallthrough.high == 2, "existing path constraints prune dead branches");
}
void boundaries() {
  using namespace autoscan;
  auto bytes = fixture(IMAGE_FILE_MACHINE_AMD64);
  put<uint32_t>(bytes, 0x120, 0x2000); put<uint32_t>(bytes, 0x124, 12);
  put<uint32_t>(bytes, 0x400, 0x1000); put<uint32_t>(bytes, 0x404, 0x1007); put<uint32_t>(bytes, 0x408, 0x3000);
  bytes[0x600] = 1;
  constexpr uint8_t body[] = {0xb8,0x90,0x90,0x90,0x90,0x90,0xcc};
  std::copy(std::begin(body), std::end(body), bytes.begin() + 0x200);
  PeImage pe(bytes); Boundaries ranges(pe);
  check(pe.valid() && !ranges.error && ranges.find(0x1000).end == 0x1005, "padding trimming does not eat immediate bytes");
  check(ranges.find(0x1003).begin == 0x1000 && ranges.find(0x1003).end == 0x1005,
        "cached trimming keeps the complete immediate and exact function bounds");
  auto different = bytes; different[0x200] = 0xc3;
  PeImage second(different); Boundaries other(second);
  check(other.find(0x1000).end == 0x1001 && ranges.find(0x1000).end == 0x1005,
        "each PE view keeps separate trimming state");
  bytes[0x602] = 255;
  PeImage bad(bytes); Boundaries invalid(bad);
  check(invalid.error != nullptr, "truncated xdata codes decline");
  bytes[0x602] = 0; bytes[0x600] = 0x21;
  put<uint32_t>(bytes, 0x604, 0x1000); put<uint32_t>(bytes, 0x608, 0x1007); put<uint32_t>(bytes, 0x60c, 0x3000);
  PeImage chain(bytes); Boundaries cyclic(chain);
  check(cyclic.error != nullptr, "cyclic chained unwind records decline");
  bytes = fixture(IMAGE_FILE_MACHINE_AMD64);
  put<uint32_t>(bytes, 0x120, 0x21f4); put<uint32_t>(bytes, 0x124, 12);
  put<uint32_t>(bytes, 0x5f4, 0x1000); put<uint32_t>(bytes, 0x5f8, 0x1007); put<uint32_t>(bytes, 0x5fc, 0x3000);
  bytes[0x600] = 1;
  std::copy(std::begin(body), std::end(body), bytes.begin() + 0x200);
  PeImage lastEntry(bytes); Boundaries atEnd(lastEntry);
  check(!atEnd.error && atEnd.find(0x1003).begin == 0x1000 && atEnd.find(0x1003).end == 0x1005,
        "runtime table's final complete entry at a section boundary is readable");
  put<uint32_t>(bytes, 0x124, 24);
  PeImage crossed(bytes); Boundaries gap(crossed);
  check(gap.error != nullptr, "runtime table crossing a virtual section gap declines");
  bytes = fixture(IMAGE_FILE_MACHINE_ARM64);
  put<uint32_t>(bytes, 0x120, 0x2000); put<uint32_t>(bytes, 0x124, 8);
  put<uint32_t>(bytes, 0x400, 0x1000); put<uint32_t>(bytes, 0x404, 1 | (3 << 2));
  put<uint32_t>(bytes, 0x200, 0xd65f03c0); put<uint32_t>(bytes, 0x204, 0xd4200000); put<uint32_t>(bytes, 0x208, 0xd4200000);
  PeImage arm(bytes); Boundaries packed(arm);
  check(!packed.error && packed.find(0x1000).end == 0x1004, "ARM64 packed length and BRK padding");
  put<uint32_t>(bytes, 0x124, 16);
  put<uint32_t>(bytes, 0x408, 0x3100); put<uint32_t>(bytes, 0x40c, 1 | (1 << 2));
  put<uint32_t>(bytes, 0x700, 0xd65f03c0);
  PeImage dataEntry(bytes); Boundaries notCode(dataEntry);
  check(notCode.error != nullptr, "runtime function cannot point into nonexecutable data");
  put<uint32_t>(bytes, 0x1fc, 0x60000020);
  PeImage extraCode(bytes); Boundaries auxiliary(extraCode);
  check(!auxiliary.error && auxiliary.find(0x1000).end == 0x1004, "ARM64 pdata may also describe auxiliary executable sections");
  put<uint32_t>(bytes, 0x124, 8); put<uint32_t>(bytes, 0x1fc, 0x40000040);
  put<uint32_t>(bytes, 0x404, 0x3000); put<uint32_t>(bytes, 0x600, 3 | (1u << 27));
  PeImage unpacked(bytes); Boundaries xdata(unpacked);
  check(!xdata.error && xdata.find(0x1000).end == 0x1004, "ARM64 unpacked xdata length");
  put<uint32_t>(bytes, 0x404, 3 | (3 << 2));
  PeImage reserved(bytes); Boundaries flags(reserved);
  check(flags.error != nullptr, "reserved ARM64 unwind flag declines");
  bytes = fixture(IMAGE_FILE_MACHINE_I386);
  constexpr unsigned configSize = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardFlags) + 4;
  put<uint32_t>(bytes, 0x148, 0x3040); put<uint32_t>(bytes, 0x14c, configSize);
  IMAGE_LOAD_CONFIG_DIRECTORY32 config{}; config.Size = configSize;
  config.GuardCFFunctionTable = 0x4030c0; config.GuardCFFunctionCount = 2; config.GuardFlags = 1u << 28;
  std::memcpy(bytes.data() + 0x640, &config, configSize);
  put<uint32_t>(bytes, 0x6c0, 0x1000); put<uint32_t>(bytes, 0x6c5, 0x1020);
  std::fill(bytes.begin() + 0x200, bytes.begin() + 0x400, uint8_t{0xcc});
  const uint8_t prologue[] = {0x55,0x8b,0xec,0xc3};
  std::copy(std::begin(prologue), std::end(prologue), bytes.begin() + 0x200);
  std::copy(std::begin(prologue), std::end(prologue), bytes.begin() + 0x220);
  PeImage x86(bytes); Boundaries cfg(x86);
  check(!cfg.error && cfg.find(0x1001).begin == 0x1000 && cfg.find(0x1021).begin == 0x1020, "CFG uses VA-to-RVA conversion and variable entry stride");
  bytes[0x210] = 0x55; bytes[0x211] = 0x89; bytes[0x212] = 0xe5; bytes[0x213] = 0xc3;
  PeImage clang(bytes); Boundaries alternate(clang);
  check(alternate.find(0x1011).begin == 0x1010, "padded 55 89 E5 is the equivalent x86 frame prologue");
  put<uint32_t>(bytes, 0x6c5, 0xfffffff0);
  PeImage outside(bytes); Boundaries invalidCfg(outside);
  check(invalidCfg.error != nullptr, "out-of-image CFG RVA declines");
  put<uint32_t>(bytes, 0x6c5, 0x1020);
  bytes[0x203] = 0xe8; put<int32_t>(bytes, 0x204, 8); bytes[0x208] = 0xc3;
  bytes[0x210] = 0x31; bytes[0x211] = 0xc0; bytes[0x212] = 0xc3;
  PeImage calls(bytes); Boundaries callBounds(calls);
  check(callBounds.find(0x1011).begin == 0x1010, "decoded E8 target recovers a prologue-free x86 function");
  put<uint32_t>(bytes, 0xd4, 0x100);
  check(!PeImage(bytes).valid(), "section table must fit in PE headers");
  bytes = fixture(IMAGE_FILE_MACHINE_AMD64);
  put<uint32_t>(bytes, 0x194, 0x100);
  check(!PeImage(bytes).valid(), "section RVA cannot overlap headers");
}

void evaluator() {
  using namespace autoscan;
  // Native encodings exercise the same connected layout with three independently moved offsets.
  for (unsigned shift : {0u, 4u, 8u}) {
    auto bytes = fixture(NativeMachine());
    size_t cursor = 0x200;
    struct Fixup { size_t at; unsigned label; };
    FixedList<Fixup, 8> fixups;
    std::array<size_t, 3> labels{};
    uint32_t comparePc = 0, branchPc = 0;
#if defined(AUTOSCAN_ARM64)
    auto emit = [&](uint32_t word) { put(bytes, cursor, word); cursor += 4; };
    auto branch = [&](unsigned cc, unsigned label) { fixups.push_back({cursor,label}); emit(0x54000000 | cc); };
    auto compare = [&](unsigned n) { emit(0x7100013f | (n << 10)); };
    emit(0xb9400009 | ((0x40 + shift) / 4 << 10)); // W9 = Extension.version
    comparePc = 0x1000 + static_cast<uint32_t>(cursor - 0x200); compare(2);
    branchPc = 0x1000 + static_cast<uint32_t>(cursor - 0x200); branch(12, 1);
    emit(0xf940000a | ((0x28 + shift * 2) / 8 << 10)); // X10 = Extension.manifest
    emit(0x39400009 | ((0x31 + shift * 2) << 10)); compare(0); branch(1, 0);
    emit(0xb9400149 | ((0x18 + shift) / 4 << 10));
    compare(1); branch(0, 0); compare(3); branch(0, 0); compare(8); branch(1, 1);
    labels[0] = cursor;
    emit(0xb9400149 | ((0x1c + shift) / 4 << 10));
    compare(5); branch(0, 1); compare(10); branch(0, 1);
    emit(0x52800020); emit(0xd65f03c0);
    labels[1] = cursor; emit(0x52800000); emit(0xd65f03c0);
    for (auto f : fixups) {
      uint32_t word = ReadInsn<uint32_t>(bytes.data() + f.at);
      put(bytes, f.at, word | (static_cast<uint32_t>((labels[f.label] - f.at) / 4) << 5));
    }
#else
    auto emit = [&](std::initializer_list<uint8_t> code) { for (auto b : code) bytes[cursor++] = b; };
    auto byte = [](unsigned n) { return static_cast<uint8_t>(n); };
    auto branch = [&](uint8_t cc, unsigned label) { fixups.push_back({cursor,label}); emit({cc,0}); };
    auto compare = [&](unsigned n) { emit({0x83,0xf8,byte(n)}); };
#if defined(AUTOSCAN_X86)
    emit({0x55,0x89,0xe5});
#endif
    emit({0x8b,0x41,byte(0x40 + shift)});
    comparePc = 0x1000 + static_cast<uint32_t>(cursor - 0x200); compare(2);
    branchPc = 0x1000 + static_cast<uint32_t>(cursor - 0x200); branch(0x7f, 1);
#if defined(AUTOSCAN_X64)
    emit({0x49,0xc7,0xc3,0xff,0xff,0xff,0xff,0x49,0x83,0xfb,0xff});
    branch(0x75, 2); // The impossible 64-bit -1 != -1 path must be pruned.
    emit({0x48});
#endif
    emit({0x8b,0x51,byte(0x28 + shift * 2)});
    emit({0x0f,0xb6,0x41,byte(0x31 + shift * 2)}); compare(0); branch(0x75, 0);
    emit({0x8b,0x42,byte(0x18 + shift)});
    compare(1); branch(0x74, 0); compare(3); branch(0x74, 0); compare(8); branch(0x75, 1);
    labels[0] = cursor;
    emit({0x8b,0x42,byte(0x1c + shift)});
    compare(5); branch(0x74, 1); compare(10); branch(0x74, 1);
    emit({0xb8,1,0,0,0});
#if defined(AUTOSCAN_X86)
    emit({0x5d});
#endif
    emit({0xc3});
    labels[1] = cursor; emit({0x31,0xc0});
#if defined(AUTOSCAN_X86)
    emit({0x5d});
#endif
    emit({0xc3});
#if defined(AUTOSCAN_X64)
    labels[2] = cursor; emit({0xcc});
#endif
    for (auto f : fixups) bytes[f.at + 1] = byte(static_cast<unsigned>(labels[f.label] - f.at - 2));
#endif
    Range range{0x1000, 0x1000 + static_cast<uint32_t>(cursor - 0x200)};
    PeImage pe(bytes); Program program;
    check(program.build(pe, range), "native member predicate has complete instruction boundaries");
    Head head{comparePc, branchPc, branchPc +
#if defined(AUTOSCAN_ARM64)
      4,
#else
      2,
#endif
      0x1000 + static_cast<uint32_t>(labels[1] - 0x200), false};
    Evaluator solver(pe, program, head); Gate gate; std::string_view reason;
    bool verified = solver.verify(gate, reason);
    if (!verified) std::fprintf(stderr, "evaluator: %.*s\n", static_cast<int>(reason.size()), reason.data());
    check(verified && !gate.freePredicate && gate.fields == std::array<int64_t,5>{
      0x40 + shift, 0x28 + shift * 2, 0x18 + shift, 0x1c + shift, 0x31 + shift * 2},
      "interval evaluation infers connected native fields without fixed offsets");
    // Changing a location equality into inequality must invalidate the predicate.
    auto wrong = fixups[fixups.size() - 1].at;
    bytes[wrong] ^= 1;
    Program badProgram; check(badProgram.build(pe, range), "negative predicate still decodes");
    Evaluator invalid(pe, badProgram, head);
    check(!invalid.verify(gate, reason), "wrong location polarity cannot produce a patch");
  }
}
int replacement() { return 1; }
int original() { return 0; }
unsigned protectionCall = 0, failProtection = 0;
BOOL WINAPI pointerProtect(LPVOID address, SIZE_T size, DWORD mode, PDWORD previous) {
  check(mode == PAGE_READONLY || mode == PAGE_READWRITE, "pointer swaps never request executable storage");
  if (++protectionCall == failProtection) return FALSE;
  return VirtualProtect(address, size, mode, previous);
}
void pointers() {
  using namespace autoscan;
  auto slot = static_cast<void**>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  check(slot != nullptr, "allocate isolated pointer fixture");
  *slot = reinterpret_cast<void*>(&original); DWORD old = 0;
  VirtualProtect(slot, 4096, PAGE_READONLY, &old);
  auto result = SwapPointer(slot, reinterpret_cast<void*>(&original), reinterpret_cast<void*>(&replacement));
  MEMORY_BASIC_INFORMATION memory{}; VirtualQuery(slot, &memory, sizeof(memory));
  check(result == ApplyResult::applied && memory.Protect == PAGE_READONLY && *slot == reinterpret_cast<void*>(&replacement), "pointer swap restores read-only protection");
  check(SwapPointer(slot, reinterpret_cast<void*>(&original), reinterpret_cast<void*>(&replacement)) == ApplyResult::alreadyApplied, "pointer swap is idempotent");
  for (unsigned failure : {1u,2u}) {
    protectionCall = 0; failProtection = failure;
    result = SwapPointer(slot, reinterpret_cast<void*>(&replacement), reinterpret_cast<void*>(&original), {pointerProtect});
    VirtualQuery(slot, &memory, sizeof(memory));
    check(result == ApplyResult::declined && *slot == reinterpret_cast<void*>(&replacement) && memory.Protect == PAGE_READONLY,
          "failed pointer protection restores the previous slot and protection");
  }
  VirtualFree(slot, 0, MEM_RELEASE);
}

}
int wmain() {
  lengths(); intervals(); boundaries(); evaluator(); pointers();
  std::printf("PASS: %u compact module checks\n", checks);
}
