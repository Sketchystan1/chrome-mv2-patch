#pragma once
// Translate browser instruction bytes into descriptions for analysis; nothing decoded here is executed.
#include <array>
#include <cstdint>
#include <cstring>
#include <span>

// Tests can inspect ARM64 instructions on an x64 computer because the scanner only reads their bytes.
#if defined(_M_ARM64) || defined(AUTOSCAN_TEST_ARM64)
#define AUTOSCAN_ARM64
#elif defined(_M_X64)
#define AUTOSCAN_X64
#elif defined(_M_IX86)
#define AUTOSCAN_X86
#endif

namespace autoscan {
enum class Op : uint8_t { LoadField, AddImm, MovReg, CmpImm, JccSigned, Jmp, Ret, Other };
enum class Other : uint8_t {
  Unknown, Nop, Trap, Call, Branch, Setcc, CmpReg, TestReg, TestImm,
  AndReg, OrReg, XorReg, AndImm, BitTest, Store, Push, Pop, Cmov, Overwrite, AtomicAdd, OrImm,
  RegisterBranch, PairLoad, ShiftRight, ConditionalCompare, Select, Subtract
};
constexpr uint8_t NoReg = 0xff;
#if defined(AUTOSCAN_ARM64)
constexpr unsigned StackReg = 31;
#else
constexpr unsigned StackReg = 4;
#endif
// This compact record describes one instruction: "detail" holds a destination, instruction kind, or part of a constant.
struct LiftedInsn {
  int32_t imm = 0, disp = 0;
  uint32_t detail = 0;
  Op op = Op::Other;
  uint8_t dst = NoReg, src = NoReg, encoding = 0;
  unsigned length() const { return encoding & 15; }
  unsigned width() const { return 1u << ((encoding >> 4) & 3); }
  bool memory() const { return (encoding & 0x80) != 0; }
  bool setsFlags() const { return (encoding & 0x40) != 0; }
  Other other() const { return static_cast<Other>(detail & 0xff); }
  unsigned condition() const { return dst; }
  bool conditional() const { return op == Op::JccSigned || (op == Op::Other && (other() == Other::Branch || other() == Other::RegisterBranch)); }
  uint32_t target() const { return op == Op::Other ? static_cast<uint32_t>(imm) : detail; }
};
static_assert(sizeof(LiftedInsn) == 16);

template<class T> inline T ReadInsn(const uint8_t* p) {
  T value; std::memcpy(&value, p, sizeof value); return value;
}
inline bool RelativeTarget(uint32_t pc, unsigned length, int64_t relative, uint32_t& target) {
  int64_t value = static_cast<int64_t>(pc) + length + relative;
  if (value < 0 || value > UINT32_MAX) return false;
  target = static_cast<uint32_t>(value); return true;
}

#if defined(AUTOSCAN_X86) || defined(AUTOSCAN_X64) || defined(AUTOSCAN_ALL_ARCH_TESTS)
namespace x86 {
enum Length : uint8_t { Invalid = 0, Plain = 1, ModRM = 2, Byte = 4, Word = 8, Operand = 16, Address = 32, Group = 64 };
inline constexpr auto lengths = [] {
  std::array<uint8_t, 256> t{};
  for (unsigned b = 0; b < 0x40; b += 8) {
    for (unsigned n = 0; n < 4; ++n) t[b + n] = ModRM;
    t[b + 4] = Byte; t[b + 5] = Operand;
    t[b + 6] = t[b + 7] = Plain;
  }
  for (unsigned b = 0x40; b <= 0x61; ++b) t[b] = Plain;
  t[0x62] = t[0x63] = ModRM; t[0x68] = Operand; t[0x69] = ModRM | Operand;
  t[0x6a] = Byte; t[0x6b] = ModRM | Byte;
  for (unsigned b = 0x6c; b < 0x70; ++b) t[b] = Plain;
  for (unsigned b = 0x70; b < 0x80; ++b) t[b] = Byte;
  t[0x80] = t[0x82] = t[0x83] = ModRM | Byte; t[0x81] = ModRM | Operand;
  for (unsigned b = 0x84; b <= 0x8f; ++b) t[b] = ModRM;
  for (unsigned b = 0x90; b <= 0x9f; ++b) t[b] = Plain;
  t[0x9a] = Invalid;
  for (unsigned b = 0xa0; b <= 0xa3; ++b) t[b] = Address;
  for (unsigned b = 0xa4; b <= 0xaf; ++b) t[b] = Plain;
  t[0xa8] = Byte; t[0xa9] = Operand;
  for (unsigned b = 0xb0; b <= 0xb7; ++b) t[b] = Byte;
  for (unsigned b = 0xb8; b <= 0xbf; ++b) t[b] = Operand;
  t[0xc0] = t[0xc1] = ModRM | Byte; t[0xc2] = Word; t[0xc3] = Plain;
  t[0xc4] = t[0xc5] = Invalid; t[0xc6] = ModRM | Byte; t[0xc7] = ModRM | Operand;
  t[0xc9] = Plain; t[0xca] = Word; t[0xcb] = t[0xcc] = Plain; t[0xcd] = Byte;
  t[0xce] = t[0xcf] = Plain;
  for (unsigned b = 0xd0; b <= 0xd3; ++b) t[b] = ModRM;
  for (unsigned b = 0xd8; b <= 0xdf; ++b) t[b] = ModRM;
  for (unsigned b = 0xe0; b <= 0xe7; ++b) t[b] = Byte;
  t[0xe8] = t[0xe9] = Operand; t[0xeb] = Byte;
  for (unsigned b = 0xec; b <= 0xef; ++b) t[b] = Plain;
  t[0xf1] = t[0xf4] = t[0xf5] = Plain; t[0xf6] = t[0xf7] = ModRM | Group;
  for (unsigned b = 0xf8; b <= 0xfd; ++b) t[b] = Plain;
  t[0xfe] = t[0xff] = ModRM;
  return t;
}();
inline uint8_t escapedLength(uint8_t b) {
  if (b >= 0x80 && b <= 0x8f) return Operand;
  if ((b >= 0x40 && b <= 0x6f) || (b >= 0x90 && b <= 0x9f) || b >= 0xd0 ||
      (b >= 0x10 && b <= 0x18) || (b >= 0x20 && b <= 0x2f) || (b >= 0x74 && b <= 0x76) ||
      b == 0x78 || b == 0x79 || (b >= 0x7c && b <= 0x7f) || b == 0x1f || b == 0xaf ||
      (b >= 0xb0 && b <= 0xb9) || (b >= 0xbb && b <= 0xbf) ||
      b == 0xa3 || b == 0xa5 || b == 0xab || b == 0xad || b == 0xae ||
      b == 0x00 || b == 0x01 || b == 0x02 || b == 0x03 || b == 0xc0 || b == 0xc1 || b == 0xc3 || b == 0xc7)
    return ModRM;
  if (b == 0x70 || (b >= 0x71 && b <= 0x73) || b == 0xa4 || b == 0xac || b == 0xba ||
      b == 0xc2 || (b >= 0xc4 && b <= 0xc6)) return ModRM | Byte;
  if ((b >= 0xc8 && b <= 0xcf) || b == 0x05 || b == 0x06 || b == 0x07 || b == 0x08 || b == 0x09 ||
      b == 0x0b || b == 0x0e || b == 0x30 || b == 0x31 || b == 0x32 || b == 0x33 || b == 0x34 ||
      b == 0x35 || b == 0x37 || b == 0x77 || b == 0xa0 || b == 0xa1 || b == 0xa2 || b == 0xa8 || b == 0xa9 || b == 0xaa)
    return Plain;
  return Invalid;
}
} // namespace x86

inline LiftedInsn LiftX86(std::span<const uint8_t> bytes, uint32_t pc, bool x64) {
  // x86 instructions are at most 15 bytes long; incomplete or unsupported forms stay unknown.
  LiftedInsn out;
  const size_t limit = bytes.size() < 15 ? bytes.size() : 15;
  size_t p = 0; bool operand16 = false, addressOverride = false, segment = false, lock = false, repeat = false;
  uint8_t rex = 0;
  while (p < limit) {
    uint8_t b = bytes[p];
    if (x64 && b >= 0x40 && b <= 0x4f) rex = b;
    else {
      if (b == 0x66) operand16 = true;
      else if (b == 0x67) addressOverride = true;
      else if (b == 0xf0) lock = true;
      else if (b == 0xf2 || b == 0xf3) repeat = true;
      else if (b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e || b == 0x64 || b == 0x65) segment = true;
      else break;
      rex = 0; // A legacy prefix after REX cancels that REX.
    }
    ++p;
  }
  if (p == limit) return out;
  uint8_t op = bytes[p++], second = 0;
  bool escaped = op == 0x0f;
  uint8_t flags = x86::lengths[op];
  if (escaped) {
    if (p == limit) return out;
    second = bytes[p++]; flags = x86::escapedLength(second);
  }
  // shortcut: VEX/EVEX and unlisted opcode maps decline; extend only with length tests.
  if (!flags || (x64 && (op == 0x62 || op == 0x82 || op == 0x60 || op == 0x61))) return out;
  if (p < limit && ((op == 0x62 && (bytes[p] & 0xc0) == 0xc0) || (op == 0x8f && (bytes[p] & 31) >= 8))) return out;
  if ((escaped && second == 0x78 && (repeat || operand16)) || (op == 0x68 && operand16 && (rex & 8))) return out;
  unsigned width = (rex & 8) ? 8 : operand16 ? 2 : 4;
  uint8_t mod = 3, group = 0, reg = NoReg, rm = NoReg, base = NoReg;
  bool indexed = false, rip = false;
  int32_t displacement = 0;
  if (flags & x86::ModRM) {
    if (p == limit) return out;
    uint8_t m = bytes[p++]; mod = m >> 6; group = (m >> 3) & 7;
    reg = group + ((rex & 4) ? 8 : 0); rm = (m & 7) + ((rex & 1) ? 8 : 0); base = rm;
    unsigned displacementBytes = 0;
    if (mod != 3) {
      if (!x64 && addressOverride) {
        indexed = true; displacementBytes = mod == 1 ? 1 : (mod == 2 || (m & 7) == 6) ? 2 : 0;
      } else {
        if ((m & 7) == 4) {
          if (p == limit) return out;
          uint8_t sib = bytes[p++];
          indexed = ((sib >> 3) & 7) != 4 || (rex & 2);
          base = (sib & 7) + ((rex & 1) ? 8 : 0);
          if (mod == 0 && (sib & 7) == 5) { base = NoReg; displacementBytes = 4; }
        }
        if (mod == 0 && (m & 7) == 5) { base = NoReg; displacementBytes = 4; rip = x64 && !addressOverride; }
        if (mod == 1) displacementBytes = 1;
        if (mod == 2) displacementBytes = 4;
      }
      if (displacementBytes > limit - p) return out;
      if (displacementBytes == 1) displacement = static_cast<int8_t>(bytes[p]);
      if (displacementBytes == 2) displacement = ReadInsn<int16_t>(bytes.data() + p);
      if (displacementBytes == 4) displacement = ReadInsn<int32_t>(bytes.data() + p);
      p += displacementBytes;
    }
  }
  unsigned immediateBytes = flags & x86::Byte ? 1 : flags & x86::Word ? 2 : flags & x86::Operand ? (width == 2 ? 2 : 4) : 0;
  if (flags & x86::Group) immediateBytes = group <= 1 ? (op == 0xf6 ? 1 : width == 2 ? 2 : 4) : 0;
  if (flags & x86::Address) immediateBytes = x64 ? (addressOverride ? 4 : 8) : (addressOverride ? 2 : 4);
  if (!escaped && op >= 0xb8 && op <= 0xbf && (rex & 8)) immediateBytes = 8;
  if (x64 && (op == 0xe8 || op == 0xe9 || (escaped && second >= 0x80 && second <= 0x8f))) immediateBytes = 4;
  if (immediateBytes > limit - p) return out;
  uint64_t immediate = 0;
  if (immediateBytes) std::memcpy(&immediate, bytes.data() + p, immediateBytes);
  p += immediateBytes;
  out.encoding = static_cast<uint8_t>(p | (width == 8 ? 0x30 : width == 4 ? 0x20 : 0x10));
  out.disp = displacement;
  if (mod != 3) { out.encoding |= 0x80; if (rip) out.detail |= 0x100; }
  auto other = [&](Other kind) { out.op = Op::Other; out.detail = (out.detail & 0x100) | static_cast<uint8_t>(kind); };
  auto byteWidth = [&] { width = 1; out.encoding &= ~0x30; };
  auto memory = [&] { if (mod != 3) { out.encoding |= 0x80; if (rip) out.detail |= 0x100; } };
  auto branch = [&](unsigned cc, int64_t relative) {
    uint32_t target;
    if (!RelativeTarget(pc, static_cast<unsigned>(p), relative, target)) { out = {}; return; }
    out.dst = static_cast<uint8_t>(cc);
    if (cc >= 12) { out.op = Op::JccSigned; out.detail = target; }
    else { other(Other::Branch); out.imm = static_cast<int32_t>(target); }
  };
  if (op == 0xcc || (escaped && (second == 0x0b || second == 0xb9 || second == 0xff)) || (op == 0xcd && immediate == 0x29)) {
    other(Other::Trap); return out;
  }
  if (escaped && second == 0xc1 && mod != 3 && !repeat) {
    other(Other::AtomicAdd); out.dst = reg; out.src = base; return out;
  }
  if (!escaped && op == 0xff && group == 1 && mod != 3 && !repeat && !segment && !indexed && !addressOverride) {
    // Memory DEC updates no register; the memory result remains unknown.
    other(Other::AtomicAdd); out.src = base; return out;
  }
  if (lock) return out;
  if ((op == 0x90 && !rex) || (escaped && second == 0x1f && group == 0)) { other(Other::Nop); return out; }
  if (escaped && (second == 0x10 || second == 0x11 || second == 0x28 || second == 0x29 ||
                  second == 0x6f || second == 0x7f || second == 0x57 || second == 0xef)) {
    bool store = mod != 3 && (second == 0x11 || second == 0x29 || second == 0x7f);
    other(store ? Other::Store : Other::Overwrite);
    // Conservatively cover all 16 bytes, including scalar SIMD stores.
    if (store) { out.detail |= 0x200; if (!segment && !indexed && !addressOverride) out.dst = base; }
    return out; // SIMD moves/XOR preserve flags and all integer registers.
  }
  if (segment || (mod != 3 && (indexed || addressOverride))) {
    if (!escaped && (op == 0x8b || op == 0x8a || op == 0x8d)) { other(Other::Overwrite); out.dst = reg; }
    else if (!escaped && (op == 0x89 || op == 0x88) && mod != 3) other(Other::Store);
    return out;
  }
  if (!escaped && (op == 0xc3 || op == 0xc2)) { out.op = Op::Ret; out.imm = static_cast<int32_t>(immediate); return out; }
  if (repeat) return out;
  if (!escaped && !x64 && op >= 0x40 && op <= 0x4f) {
    out.op = Op::AddImm; out.dst = out.src = op & 7; out.imm = op < 0x48 ? 1 : -1; out.encoding |= 0x40; return out;
  }
  if (!escaped && (op == 0x68 || op == 0x6a || (op == 0xff && group == 6))) {
    if (operand16) return out;
    other(Other::Push); out.dst = op == 0xff ? (mod == 3 ? rm : base) : NoReg;
    out.imm = static_cast<int32_t>(immediate); return out;
  }
  if (!escaped && (op == 0xa0 || op == 0xa1) && !addressOverride) {
    if (op == 0xa0) byteWidth();
    out.op = Op::LoadField; out.dst = 0; out.src = NoReg; out.disp = static_cast<int32_t>(immediate); out.encoding |= 0x80; return out;
  }
  if (escaped && second >= 0x40 && second <= 0x4f) {
    other(Other::Cmov); out.dst = reg; out.src = mod == 3 ? rm : base; return out;
  }
  if (!escaped && op == 0x03) {
    other(Other::Overwrite); out.dst = reg; out.src = mod == 3 ? rm : base; out.encoding |= 0x40; return out;
  }
  if (!escaped && x64 && op == 0x63) {
    other(Other::Overwrite); out.dst = reg; out.src = mod == 3 ? rm : base; return out;
  }
  if (!escaped && op >= 0x70 && op <= 0x7f) { branch(op & 15, static_cast<int8_t>(immediate)); return out; }
  if (escaped && second >= 0x80 && second <= 0x8f) {
    if (!x64 && operand16) return out;
    branch(second & 15, static_cast<int32_t>(immediate)); return out;
  }
  if (!escaped && (op == 0xeb || op == 0xe9 || op == 0xe8)) {
    if (!x64 && operand16 && op != 0xeb) return out;
    uint32_t target;
    if (!RelativeTarget(pc, static_cast<unsigned>(p), op == 0xeb ? static_cast<int8_t>(immediate) : static_cast<int32_t>(immediate), target)) return {};
    if (op == 0xe8) { other(Other::Call); out.imm = static_cast<int32_t>(target); }
    else { out.op = Op::Jmp; out.detail = target; }
    return out;
  }
  if (!escaped && op >= 0x50 && op <= 0x5f) {
    if (operand16) return out;
    other(op < 0x58 ? Other::Push : Other::Pop); out.dst = (op & 7) + ((rex & 1) ? 8 : 0); return out;
  }
  if (!escaped && op >= 0xb0 && op <= 0xbf) {
    if (op < 0xb8) { byteWidth(); if (!rex && (op & 7) >= 4) return out; }
    out.op = Op::MovReg; out.dst = (op & 7) + ((rex & 1) ? 8 : 0);
    out.imm = static_cast<int32_t>(immediate); out.detail = static_cast<uint32_t>(immediate >> 32); return out;
  }
  if (!escaped && (op == 0xc6 || op == 0xc7) && group == 0) {
    if (op == 0xc6) { byteWidth(); if (!rex && mod == 3 && rm >= 4) return out; }
    out.dst = mod == 3 ? rm : base; out.imm = static_cast<int32_t>(immediate); memory();
    if (mod == 3) {
      out.op = Op::MovReg;
      if (width == 8 && out.imm < 0) out.detail = UINT32_MAX;
    } else other(Other::Store);
    return out;
  }
  if (!escaped && (op == 0x8b || op == 0x8a || op == 0x89 || op == 0x88 || op == 0x8d)) {
    if (op == 0x8a || op == 0x88) { byteWidth(); if (!rex && (reg >= 4 || (mod == 3 && rm >= 4))) return out; }
    if (op == 0x8d) {
      if (mod == 3) return out;
      if (base == NoReg) { other(Other::Overwrite); out.dst = reg; return out; }
      out.op = Op::AddImm; out.dst = reg; out.src = base; out.imm = displacement; return out;
    }
    bool reverse = op == 0x89 || op == 0x88;
    out.dst = reverse ? (mod == 3 ? rm : base) : reg;
    out.src = reverse ? reg : (mod == 3 ? rm : base);
    memory();
    if (mod == 3) out.op = Op::MovReg;
    else { if (reverse) other(Other::Store); else out.op = Op::LoadField; }
    return out;
  }
  if (!escaped && (op == 0x80 || op == 0x81 || op == 0x83 || op == 0x3d || op == 0x3c)) {
    if (op == 0x80 || op == 0x3c) { byteWidth(); if (op == 0x80 && !rex && mod == 3 && rm >= 4) return out; }
    out.dst = (op == 0x3d || op == 0x3c) ? 0 : mod == 3 ? rm : base;
    out.imm = op == 0x83 ? static_cast<int8_t>(immediate) : static_cast<int32_t>(immediate);
    if (op != 0x3d && op != 0x3c) memory();
    if (group == 7 || op == 0x3d || op == 0x3c) out.op = Op::CmpImm;
    else if ((group == 0 || group == 5) && mod == 3) {
      out.op = Op::AddImm; out.src = out.dst; out.encoding |= 0x40;
      if (group == 5) out.imm = static_cast<int32_t>(0u - static_cast<uint32_t>(out.imm));
    } else if (group == 4 && mod == 3) other(Other::AndImm);
    else if (group == 1 && mod == 3) other(Other::OrImm);
    return out;
  }
  if (escaped && second >= 0x90 && second <= 0x9f && mod == 3) {
    if (!rex && rm >= 4) return out;
    byteWidth(); other(Other::Setcc); out.dst = rm; out.src = second & 15; return out;
  }
  if (escaped && second >= 0x90 && second <= 0x9f && mod != 3) {
    byteWidth(); other(Other::Store); out.dst = base; out.src = 32; return out;
  }
  if (escaped && second == 0xa3 && mod == 3) {
    other(Other::BitTest); out.dst = rm; out.src = reg; return out;
  }
  if (!escaped && (op == 0x84 || op == 0x85 || op == 0x38 || op == 0x39 || op == 0x3a || op == 0x3b ||
      op == 0x20 || op == 0x21 || op == 0x22 || op == 0x23 || op == 0x08 || op == 0x09 || op == 0x0a || op == 0x0b ||
      op == 0x30 || op == 0x31 || op == 0x32 || op == 0x33)) {
    if (!(op & 1)) { byteWidth(); if (!rex && (reg >= 4 || (mod == 3 && rm >= 4))) return out; }
    bool reverse = (op & 2) && op < 0x80;
    out.dst = reverse ? reg : (mod == 3 ? rm : base); out.src = reverse ? (mod == 3 ? rm : base) : reg;
    memory();
    if (mod != 3 && reverse) {
      if (op == 0x3b || op == 0x3a) { other(Other::CmpReg); out.encoding |= 0x40; }
      else { other(Other::Overwrite); out.encoding |= 0x40; }
      return out;
    }
    other(op >= 0x84 ? Other::TestReg : op >= 0x38 ? Other::CmpReg : op >= 0x30 ? Other::XorReg : op >= 0x20 ? Other::AndReg : Other::OrReg);
    return out;
  }
  if (!escaped && (op == 0xf6 || op == 0xf7) && group == 0) {
    if (op == 0xf6) { byteWidth(); if (!rex && mod == 3 && rm >= 4) return out; }
    other(Other::TestImm); out.dst = mod == 3 ? rm : base; out.imm = static_cast<int32_t>(immediate); memory(); return out;
  }
  if (escaped && (second == 0xb6 || second == 0xb7) && mod != 3 && base != NoReg) {
    if (width == 2) { other(Other::Overwrite); out.dst = reg; return out; }
    out.op = Op::LoadField; out.dst = reg; out.src = base;
    out.encoding = static_cast<uint8_t>((out.encoding & ~0x30) | (second == 0xb7 ? 0x10 : 0) | 0xc0); return out;
  }
  if (escaped && (second == 0xbe || second == 0xbf)) {
    other(Other::Overwrite); out.dst = reg; out.src = mod == 3 ? rm : base; memory(); return out;
  }
  if (!escaped && op == 0xff && (group == 2 || group == 3)) { other(Other::Call); return out; }
  return out;
}
#endif

#if defined(AUTOSCAN_ARM64) || defined(AUTOSCAN_ALL_ARCH_TESTS)
inline LiftedInsn LiftArm64(std::span<const uint8_t> bytes, uint32_t pc) {
  // ARM64 instructions must occupy four bytes at a four-byte boundary; reject other positions.
  if (bytes.size() < 4 || (pc & 3)) return {};
  uint32_t word = ReadInsn<uint32_t>(bytes.data());
  LiftedInsn out; out.encoding = 4 | ((word & 0x80000000) ? 0x30 : 0x20);
  out.dst = word & 31; out.src = (word >> 5) & 31;
  auto other = [&](Other kind) { out.detail = static_cast<uint8_t>(kind); };
  bool scaled = (word & 0x3b000000) == 0x39000000;
  bool unscaled = (word & 0x3b200000) == 0x38000000;
  if (scaled || unscaled) {
    unsigned size = word >> 30, opc = (word >> 22) & 3;
    bool simd = word & (1u << 26), load = opc & 1;
    if (!simd && opc > 1) {
      other(Other::Overwrite); if (out.dst == 31) out.dst = NoReg; return out;
    }
    if ((simd && opc > 1 && size) || (unscaled && ((word >> 10) & 3) == 2)) return out;
    unsigned width = simd && opc > 1 ? 16 : 1u << size;
    out.disp = scaled ? ((word >> 10) & 0xfff) * width : static_cast<int32_t>(word << 11) >> 23;
    out.encoding = static_cast<uint8_t>(4 | 0x80 | (width >= 8 ? 0x30 : width == 4 ? 0x20 : width == 2 ? 0x10 : 0x40));
    if (load) {
      if (simd || out.dst == 31) { other(Other::Overwrite); out.dst = NoReg; }
      else out.op = Op::LoadField;
    } else {
      unsigned value = out.dst; out.dst = out.src; out.src = simd ? 32 : value == 31 ? NoReg : static_cast<uint8_t>(value);
      other(Other::Store); if (width == 16) out.detail |= 0x200;
    }
    if (unscaled && ((word >> 10) & 3)) out.detail |= 0x800 | (((word >> 10) & 3) == 1 ? 0x1000 : 0);
    return out;
  }
  if ((word & 0x3a000000) == 0x28000000 && !(word & (1u << 26))) {
    unsigned mode = (word >> 23) & 3, size = word >> 30;
    if ((size != 0 && size != 2) || !mode) return out;
    bool load = word & (1u << 22);
    out.encoding = static_cast<uint8_t>(4 | 0x80 | (size == 2 ? 0x30 : 0x20));
    out.disp = (static_cast<int32_t>(word << 10) >> 25) * static_cast<int>(out.width());
    out.imm = (word >> 10) & 31;
    if (load) other(Other::PairLoad);
    else { unsigned value = out.dst; out.dst = out.src; out.src = static_cast<uint8_t>(value); other(Other::Store); }
    out.detail |= 0x400;
    if (mode != 2) out.detail |= 0x800 | (mode == 1 ? 0x1000 : 0);
    return out;
  }
  if ((word & 0x1f800000) == 0x11000000) {
    bool subtract = word & (1u << 30), flags = word & (1u << 29);
    out.imm = ((word >> 10) & 0xfff) << ((word & (1u << 22)) ? 12 : 0);
    if (flags && out.dst == 31) {
      if (!subtract || out.src == 31) return out;
      out.op = Op::CmpImm; out.dst = out.src; out.src = NoReg;
    } else {
      out.op = Op::AddImm;
      if (subtract) out.imm = -out.imm;
      if (flags) out.encoding |= 0x40;
    }
    return out;
  }
  if ((word & 0x7e000000) == 0x34000000 || (word & 0x7e000000) == 0x36000000) {
    bool bit = word & (1u << 25);
    int32_t relative = bit ? static_cast<int32_t>(word << 13) >> 18 : static_cast<int32_t>(word << 8) >> 13;
    uint32_t target;
    if (!RelativeTarget(pc, 0, static_cast<int64_t>(relative) * 4, target)) return {};
    out.src = out.dst; out.dst = word & (1u << 24) ? 5 : 4;
    out.disp = bit ? static_cast<int32_t>(((word >> 19) & 31) | ((word >> 26) & 32)) + 1 : 0;
    other(Other::RegisterBranch); out.imm = static_cast<int32_t>(target); return out;
  }
  if ((word & 0xff000010) == 0x54000000) {
    unsigned cc = word & 15;
    int32_t relative = static_cast<int32_t>(word << 8) >> 13;
    uint32_t target;
    if (!RelativeTarget(pc, 0, static_cast<int64_t>(relative) * 4, target)) return {};
    static constexpr uint8_t conditions[14] = {4,5,3,2,8,9,0,1,7,6,13,12,15,14};
    if (cc >= 14) return out;
    out.dst = conditions[cc];
    if (cc >= 10) { out.op = Op::JccSigned; out.detail = target; }
    else { other(Other::Branch); out.imm = static_cast<int32_t>(target); }
    return out;
  }
  if ((word & 0x7c000000) == 0x14000000) {
    int32_t relative = static_cast<int32_t>(word << 6) >> 6;
    uint32_t target;
    if (!RelativeTarget(pc, 0, static_cast<int64_t>(relative) * 4, target)) return {};
    if (word & 0x80000000) { other(Other::Call); out.imm = static_cast<int32_t>(target); }
    else { out.op = Op::Jmp; out.detail = target; } return out;
  }
  if ((word & 0xfffffc1f) == 0xd65f0000) { out.op = Op::Ret; return out; }
  if ((word & 0xfffffc1f) == 0xd63f0000) { other(Other::Call); return out; }
  if ((word & 0xffe0001f) == 0xd4200000) { other(Other::Trap); return out; }
  if (word == 0xd503201f) { other(Other::Nop); return out; }
  if ((word & 0x7fe0ffe0) == 0x2a0003e0) {
    if (out.dst == 31) { other(Other::Nop); return out; }
    out.op = Op::MovReg; out.src = (word >> 16) & 31;
    if (out.src == 31) out.src = NoReg;
    return out;
  }
  if ((word & 0x7f800000) == 0x52800000 || (word & 0x7f800000) == 0x12800000) {
    unsigned shift = ((word >> 21) & 3) * 16;
    if (out.width() == 4 && shift >= 32) return out;
    if (out.dst == 31) { other(Other::Nop); return out; }
    uint64_t value = static_cast<uint64_t>((word >> 5) & 0xffff) << shift;
    if (!(word & (1u << 30))) value = ~value & (out.width() == 8 ? UINT64_MAX : UINT32_MAX);
    out.op = Op::MovReg; out.src = NoReg; out.imm = static_cast<int32_t>(value); out.detail = static_cast<uint32_t>(value >> 32); return out;
  }
  if ((word & 0x1f000000) == 0x10000000 || (word & 0x7f800000) == 0x72800000) {
    other(Other::Overwrite); if (out.dst == 31) out.dst = NoReg; return out;
  }
  if ((word & 0x7fe0fc1f) == 0x6b00001f) {
    other(Other::CmpReg); out.dst = out.src; out.src = (word >> 16) & 31; return out;
  }
  if ((word & 0x7fe0fc00) == 0x4b000000 && out.dst != 31 && out.src != 31 && ((word >> 16) & 31) != 31) {
    other(Other::Subtract); out.imm = (word >> 16) & 31; return out;
  }
  if ((word & 0x1f200000) == 0x0b000000) {
    other(Other::Overwrite); if (out.dst == 31) out.dst = NoReg; if (word & (1u << 29)) out.encoding |= 0x40; return out;
  }
  if ((word & 0x3fff7c00) == 0x085f7c00) {
    out.op = Op::LoadField; out.encoding = static_cast<uint8_t>(4 | 0x80 | (word & (1u << 30) ? 0x30 : 0x20));
    if (out.dst == 31) { other(Other::Overwrite); out.op = Op::Other; out.dst = NoReg; } return out;
  }
  if ((word & 0x3fe07c00) == 0x08007c00) {
    out.imm = out.dst; out.dst = (word >> 16) & 31; if (out.dst == 31) out.dst = NoReg;
    other(Other::AtomicAdd); out.encoding = static_cast<uint8_t>(4 | 0x80 | (word & (1u << 30) ? 0x30 : 0x20)); return out;
  }
  if ((word & 0x7ffffc00) == 0x12000000 && out.dst == out.src) {
    other(Other::AndImm); out.imm = 1; return out;
  }
  if ((word & 0xfffffc1f) == 0x7200001f) {
    other(Other::TestImm); out.dst = out.src; out.src = NoReg; out.imm = 1; return out;
  }
  if ((word & 0x7fe0fc00) == 0x1ac02400) {
    other(Other::ShiftRight); out.imm = (word >> 16) & 31; return out;
  }
  constexpr uint8_t cc[] = {4,5,3,2,8,9,0,1,7,6,13,12,15,14};
  unsigned condition = (word >> 12) & 15;
  if ((word & 0x7fe00c10) == 0x7a400800 && condition < 14) {
    other(Other::ConditionalCompare); out.dst = out.src; out.src = cc[condition];
    out.imm = (word >> 16) & 31; out.disp = word & 15; return out;
  }
  if ((word & 0x7fff0fe0) == 0x1a9f07e0 && condition < 14) {
    other(Other::Setcc); out.src = cc[condition] ^ 1; if (out.dst == 31) out.dst = NoReg; return out;
  }
  if ((word & 0x7fe00c00) == 0x1a800000 && condition < 14) {
    other(Other::Select); out.imm = (word >> 16) & 31; out.disp = cc[condition]; return out;
  }
  if ((word & 0x1f800000) == 0x12000000) {
    other(Other::Overwrite); if (out.dst == 31) out.dst = NoReg;
    if (((word >> 29) & 3) == 3) out.encoding |= 0x40;
    return out;
  }
  return out;
}
#endif

inline LiftedInsn Lift(std::span<const uint8_t> bytes, uint32_t pc) {
  // Interpret only the processor type this scanner was built to understand.
#if defined(AUTOSCAN_X64)
  return LiftX86(bytes, pc, true);
#elif defined(AUTOSCAN_X86)
  return LiftX86(bytes, pc, false);
#elif defined(AUTOSCAN_ARM64)
  return LiftArm64(bytes, pc);
#else
#error Unsupported Windows architecture
#endif
}
} // namespace autoscan
