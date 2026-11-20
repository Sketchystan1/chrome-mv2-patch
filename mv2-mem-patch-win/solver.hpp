#pragma once
// Simulate the recognized browser decisions on paper, using value ranges rather than executing browser code.
#include "autoscan.h"
#include "boundaries.hpp"
#include <limits>

namespace autoscan {
struct S32Interval {
  // A range represents every possible value between its ends, so the proof does not rely on a few examples.
  int32_t low = INT32_MIN, high = INT32_MAX;
  bool empty() const { return low > high; }
  bool contains(int32_t n) const { return n >= low && n <= high; }
};
inline S32Interval Intersect(S32Interval a, S32Interval b) {
  return {std::max(a.low, b.low), std::min(a.high, b.high)};
}
struct IntervalSplit { S32Interval taken, fallthrough; };
inline IntervalSplit SplitSigned(S32Interval path, unsigned cc, int32_t immediate) {
  int64_t lo = INT32_MIN, hi = INT32_MAX, cut = immediate;
  bool less = cc == 12 || cc == 14;
  if (cc == 14 || cc == 15) ++cut;
  auto part = [&](int64_t a, int64_t b) -> S32Interval {
    a = std::max<int64_t>(a, path.low); b = std::min<int64_t>(b, path.high);
    return a > b ? S32Interval{1, 0} : S32Interval{static_cast<int32_t>(a), static_cast<int32_t>(b)};
  };
  auto below = part(lo, cut - 1), above = part(cut, hi);
  return less ? IntervalSplit{below, above} : IntervalSplit{above, below};
}
enum class SymKind : uint8_t { Unknown, Const, PtrOffset, FieldVal, BitShift };
// Track what each value came from; "Unknown" means it cannot be used as proof of a browser decision.
struct SymVal {
  uint64_t value = 0;
  int32_t disp = 0, add = 0;
  uint16_t base = 0;
  uint8_t width = 0, known = 0;
  SymKind kind = SymKind::Unknown;
  static SymVal constant(uint64_t n, unsigned w = 8) { SymVal v; v.kind = SymKind::Const; v.value = n; v.width = v.known = static_cast<uint8_t>(w); return v; }
  static SymVal pointer(unsigned base, int32_t disp = 0) { SymVal v; v.kind = SymKind::PtrOffset; v.base = static_cast<uint16_t>(base); v.disp = disp; v.width = v.known = sizeof(void*); return v; }
};
struct Node { uint32_t pc = 0; LiftedInsn insn{}; };
inline bool Terminal(const LiftedInsn& i) { return i.op == Op::Ret || (i.op == Op::Other && i.other() == Other::Trap); }
inline bool Writes(const LiftedInsn& i, unsigned reg) {
  if (i.op == Op::LoadField && (i.detail & 0x800) && i.src == reg) return true;
  if (i.op == Op::Other && (i.other() == Other::Store || i.other() == Other::PairLoad) && (i.detail & 0x800) &&
      (i.other() == Other::Store ? i.dst : i.src) == reg) return true;
  if (i.op == Op::Other && i.other() == Other::PairLoad) return reg != 31 && (i.dst == reg || i.imm == reg);
  if (i.op == Op::LoadField || i.op == Op::MovReg || i.op == Op::AddImm) return i.dst == reg;
  if (i.op != Op::Other) return false;
#if !defined(AUTOSCAN_ARM64)
  if ((i.other() == Other::Push || i.other() == Other::Pop) && reg == 4) return true;
#endif
  if (i.other() == Other::Unknown) return true;
  return i.dst == reg && (i.other() == Other::Setcc || i.other() == Other::AndReg || i.other() == Other::OrReg ||
    i.other() == Other::XorReg || i.other() == Other::AndImm || i.other() == Other::Pop || i.other() == Other::Cmov ||
    i.other() == Other::Overwrite || i.other() == Other::AtomicAdd || i.other() == Other::OrImm ||
    i.other() == Other::ShiftRight || i.other() == Other::Select || i.other() == Other::Subtract);
}
inline bool VolatileReg(unsigned r) {
#if defined(AUTOSCAN_ARM64)
  return r <= 18 || r == 30;
#elif defined(AUTOSCAN_X64)
  return r <= 2 || (r >= 8 && r <= 11);
#else
  return r <= 2;
#endif
}
inline unsigned StoreWidth(const LiftedInsn& i) {
  return i.detail & 0x400 ? i.width() * 2 : i.detail & 0x200 ? 16 : i.width();
}

// Mark every byte belonging to an instruction so a jump into its middle cannot create a false second instruction.
struct Program {
  FixedList<Node, 8192> nodes;
  FixedList<uint32_t, 16> noReturns;
  Range range{};
  bool complete = false;
  bool isNoReturn(uint32_t pc) const {
    for (auto p : noReturns) if (p == pc) return true;
    return false;
  }
  bool decode(const PeImage& pe, Range bounds) {
    nodes.count = 0; range = bounds; complete = false;
    if (!bounds || bounds.end - bounds.begin > 65536) return false;
    std::array<uint8_t, 65536> occupied;
    std::fill_n(occupied.begin(), bounds.end - bounds.begin, uint8_t{});
    FixedList<uint32_t, 512> todo; todo.push_back(bounds.begin);
    while (!todo.empty()) {
      uint32_t pc = todo.back(); --todo.count;
      while (bounds.contains(pc)) {
        auto& mark = occupied[pc - bounds.begin];
        if (mark == 1) break;
        if (mark == 2) return false;
        auto i = Lift(pe.at(pc, bounds.end - pc), pc);
        if (!i.length()) return false;
        for (unsigned n = 1; n < i.length(); ++n) if (occupied[pc - bounds.begin + n]) return false;
        if (!nodes.push_back({pc, i})) return false;
        mark = 1;
        for (unsigned n = 1; n < i.length(); ++n) occupied[pc - bounds.begin + n] = 2;
        if (Terminal(i) || isNoReturn(pc)) break;
        if (i.conditional() && bounds.contains(i.target()) && !todo.push_back(i.target())) return false;
        if (i.op == Op::Jmp) { pc = i.target(); continue; }
        pc += i.length();
      }
    }
    std::sort(nodes.begin(), nodes.end(), [](const Node& a, const Node& b) { return a.pc < b.pc; });
    complete = true; return true;
  }
  const Node* at(uint32_t pc) const {
    auto it = std::lower_bound(nodes.begin(), nodes.end(), pc, [](const Node& n, uint32_t p) { return n.pc < p; });
    return it != nodes.end() && it->pc == pc ? &*it : nullptr;
  }
  bool follows(const Node& n, uint32_t pc) const {
    if (Terminal(n.insn) || isNoReturn(n.pc)) return false;
    return ((n.insn.op == Op::Jmp || n.insn.conditional()) && n.insn.target() == pc) ||
      (n.insn.op != Op::Jmp && n.pc + n.insn.length() == pc);
  }
  const Node* predecessor(uint32_t pc) const {
    const Node* result = nullptr;
    for (const auto& n : nodes) if (follows(n, pc)) { if (result) return nullptr; result = &n; }
    return result;
  }
  bool stackAddress(uint32_t pc, unsigned reg, int64_t& offset, bool entry = false) const {
    struct Point { uint32_t pc; unsigned reg; int64_t offset; };
    FixedList<Point, 256> todo, seen; todo.push_back({pc,reg,0}); bool found = false;
    while (!todo.empty()) {
      auto point = todo.back(); --todo.count;
      if (point.reg == StackReg && (!entry || point.pc == range.begin)) {
        if (found && offset != point.offset) return false;
        offset = point.offset; found = true; continue;
      }
      if (point.reg >= 32 || point.pc == range.begin) return false;
      bool repeat = false;
      for (auto old : seen) repeat |= old.pc == point.pc && old.reg == point.reg && old.offset == point.offset;
      if (repeat) continue;
      if (!seen.push_back(point)) return false;
      bool previous = false;
      for (const auto& n : nodes) if (follows(n, point.pc)) {
        previous = true; auto next = point; next.pc = n.pc;
        const auto& i = n.insn;
        if ((!entry && Writes(i, StackReg)) ||
            (i.op == Op::Other && i.other() == Other::Call && ((entry && point.reg == StackReg) || VolatileReg(point.reg)))) return false;
        if (Writes(i, point.reg)) {
          if (entry && point.reg == StackReg && StackReg == 4 && i.op == Op::Other &&
              (i.other() == Other::Push || (i.other() == Other::Pop && i.dst != StackReg)))
            next.offset += i.other() == Other::Push ? -static_cast<int>(sizeof(void*)) : static_cast<int>(sizeof(void*));
          else {
            if ((i.op != Op::MovReg && i.op != Op::AddImm) || i.width() != sizeof(void*) || i.src >= 32) return false;
            next.reg = i.src;
            if (i.op == Op::AddImm) next.offset += i.imm;
          }
        }
        if (!todo.push_back(next)) return false;
      }
      if (!previous) return false;
    }
    return found;
  }
#if !defined(AUTOSCAN_X86)
  bool privateSlot(uint32_t pc, int32_t slot) const {
    // shortcut: spills must sit below address-taken locals, extend with alias tests for other frames.
    struct Point { uint32_t pc; int64_t slot; };
    FixedList<Point, 256> todo, seen; todo.push_back({pc,slot}); bool entry = false;
    while (!todo.empty()) {
      auto point = todo.back(); --todo.count;
      if (point.pc == range.begin) { if (point.slot + 8 > 0) return false; entry = true; continue; }
      bool repeat = false;
      for (auto old : seen) repeat |= old.pc == point.pc && old.slot == point.slot;
      if (repeat) continue;
      if (!seen.push_back(point)) return false;
      bool previous = false;
      for (const auto& n : nodes) if (follows(n, point.pc)) {
        previous = true; auto next = point; next.pc = n.pc; const auto& i = n.insn;
        if (Writes(i, StackReg)) {
          if (i.op == Op::AddImm && i.src == StackReg && i.width() == 8) next.slot += i.imm;
          else if (i.op == Op::Other && i.other() == Other::Push) next.slot -= 8;
          else if (i.op == Op::Other && i.other() == Other::Pop && i.dst != StackReg) next.slot += 8;
          else if (i.op == Op::Other && (i.other() == Other::Store || i.other() == Other::PairLoad) && (i.detail & 0x800)) next.slot += i.disp;
          else return false;
        }
        int64_t address = 0;
        if ((i.op == Op::MovReg || i.op == Op::AddImm) && i.dst != StackReg && stackAddress(n.pc, i.src, address)) {
          if (i.width() != 8 || address + (i.op == Op::AddImm ? i.imm : 0) < next.slot + 8) return false;
        }
        if (i.op == Op::Other && i.other() == Other::Store) {
          if (i.dst == NoReg || (i.src < 32 && (StackReg != 31 || i.src != 31) && stackAddress(n.pc, i.src, address) && address < next.slot + 8)) return false;
          if ((i.detail & 0x400) && i.imm != 31 && stackAddress(n.pc, static_cast<unsigned>(i.imm), address) && address < next.slot + 8) return false;
        }
        if (i.op == Op::Other && i.other() == Other::Push && stackAddress(n.pc, i.dst, address) && address < next.slot + 8) return false;
        if (i.op == Op::Other && (i.other() == Other::AndReg || i.other() == Other::OrReg || i.other() == Other::XorReg ||
            i.other() == Other::AndImm || i.other() == Other::OrImm || i.other() == Other::Cmov) &&
            (stackAddress(n.pc, i.dst, address) || (i.other() == Other::Cmov && !i.memory() && stackAddress(n.pc, i.src, address)))) return false;
        if (i.op == Op::Other && i.other() == Other::Overwrite && i.memory() && i.dst != NoReg && !(i.detail & 0x100)) return false;
        if (!todo.push_back(next)) return false;
      }
      if (!previous) return false;
    }
    return entry;
  }
#endif
  bool fromArgument(uint32_t pc, unsigned reg, unsigned argument, int32_t stackSlot = 0) const {
    // Trace all incoming paths back to the same function input instead of trusting one matching load.
    if (reg >= 32 || (argument >= 32 && argument != NoReg)) return false;
    struct Point { uint32_t pc; unsigned reg; int32_t slot = 0; };
    FixedList<Point, 256> todo, seen; todo.push_back({pc,reg}); bool entry = false;
    while (!todo.empty()) {
      auto point = todo.back(); --todo.count;
      bool repeat = false; for (auto old : seen) repeat |= old.pc == point.pc && old.reg == point.reg && old.slot == point.slot;
      if (repeat) continue;
      if (!seen.push_back(point)) return false;
      if (point.pc == range.begin) { if (point.reg != argument || point.slot != stackSlot) return false; entry = true; continue; }
      bool hasPrevious = false;
      for (const auto& n : nodes) if (follows(n, point.pc)) {
        hasPrevious = true; auto i = n.insn; unsigned source = point.reg;
#if !defined(AUTOSCAN_X86)
        if (source == NoReg) {
          if (Writes(i, StackReg)) return false;
          if (i.op == Op::Other) {
            if (StackReg == 4 && i.other() == Other::Call && point.slot < 32) return false;
            if (i.other() == Other::Store) {
              int64_t address = 0; if (!stackAddress(n.pc, i.dst, address)) return false;
              address += i.disp;
              unsigned width = StoreWidth(i);
              if (address < static_cast<int64_t>(point.slot) + 8 && address + width > point.slot) {
                if (i.width() != 8 || (i.detail & 0x200)) return false;
                if (address == point.slot) source = i.src;
                else if ((i.detail & 0x400) && address + 8 == point.slot) source = static_cast<unsigned>(i.imm);
                else return false;
                if (source >= 32 || (StackReg == 31 && source == 31)) return false;
              }
            } else if (i.memory() && (i.other() == Other::AndReg || i.other() == Other::OrReg ||
                i.other() == Other::XorReg || i.other() == Other::AtomicAdd)) return false;
          }
          if (!todo.push_back({n.pc,source,source == NoReg ? point.slot : 0})) return false;
          continue;
        }
#endif
        if (i.op == Op::Other && i.other() == Other::Call && VolatileReg(source)) return false;
        if (Writes(i, source)) {
#if !defined(AUTOSCAN_X86)
          if (i.op == Op::LoadField && i.width() == 8 && i.src == StackReg) {
            if (!privateSlot(n.pc, i.disp) || !todo.push_back({n.pc,NoReg,i.disp})) return false;
            continue;
          }
#else
          if (argument == NoReg && i.op == Op::LoadField && i.width() == 4) {
            int64_t offset = 0;
            if (!stackAddress(n.pc, i.src, offset, true) || offset + i.disp != stackSlot) return false;
            for (const auto& before : nodes) if (before.pc < n.pc && before.insn.op == Op::Other &&
                (before.insn.other() == Other::Store || before.insn.other() == Other::AtomicAdd || before.insn.other() == Other::Call)) return false;
            entry = true; continue;
          }
#endif
          if (i.op != Op::MovReg || i.src >= 32 || i.width() != sizeof(void*)) return false;
          source = i.src;
        }
        if (!todo.push_back({n.pc,source})) return false;
      }
      if (!hasPrevious) return false;
    }
    return entry;
  }
  bool guardedNoReturn(const PeImage& pe, const Node& call) const {
    // Recognize compiler failure checks so analysis stops on their fatal paths; this does not alter those checks.
#if defined(AUTOSCAN_ARM64)
    auto literalLoad = [&](uint32_t pc, uint32_t& address, unsigned& reg) {
      uint32_t word = 0;
      if (!pe.rvaRead(pc, word) || (word & 0x9f000000) != 0x90000000) return uint32_t{0};
      int32_t pages = static_cast<int32_t>((((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3)) << 11) >> 11;
      int64_t value = static_cast<int64_t>(pc & ~0xfffu) + int64_t{pages} * 4096;
      reg = word & 31; pc += 4;
      auto i = Lift(pe.code(pc), pc);
      if (i.op == Op::AddImm && i.src == reg && i.dst == reg && i.width() == 8 && !i.setsFlags()) {
        value += i.imm; pc += 4; i = Lift(pe.code(pc), pc);
      }
      if (i.op != Op::LoadField || i.width() != 8 || i.src != reg || (i.detail & 0x800)) return uint32_t{0};
      value += i.disp;
      if (value < 0 || value > UINT32_MAX) return uint32_t{0};
      address = static_cast<uint32_t>(value); reg = i.dst; return pc + 4;
    };
    uint32_t expected = 0; unsigned reg = NoReg;
    auto comparePc = literalLoad(call.insn.target(), expected, reg);
    if (!comparePc) return false;
    auto compare = Lift(pe.code(comparePc), comparePc), guard = Lift(pe.code(comparePc + 4), comparePc + 4);
    if (compare.op != Op::Other || compare.other() != Other::CmpReg || compare.width() != 8 ||
        !((compare.dst == 0 && compare.src == reg) || (compare.src == 0 && compare.dst == reg)) ||
        !guard.conditional() || guard.condition() != 5 || Lift(pe.code(comparePc + 8), comparePc + 8).op != Op::Ret ||
        callEffect(pe, guard.target(), 0)) return false;
    const auto* argument = predecessor(call.pc);
    if (!argument || argument->insn.op != Op::Other || argument->insn.other() != Other::Subtract ||
        argument->insn.dst != 0 || argument->insn.width() != 8) return false;
    const auto* saved = predecessor(argument->pc);
    if (!saved || saved->insn.op != Op::LoadField || saved->insn.width() != 8 || saved->insn.dst != argument->insn.imm ||
        (saved->insn.src != 29 && saved->insn.src != 31) || (saved->insn.detail & 0x800)) return false;
    const auto* branch = predecessor(saved->pc);
    if (!branch || !branch->insn.conditional() || branch->insn.condition() != 5 || branch->insn.target() != saved->pc) return false;
    const auto* checked = predecessor(branch->pc);
    const auto* decoded = checked ? predecessor(checked->pc) : nullptr;
    const auto* global = decoded ? predecessor(decoded->pc) : nullptr;
    const auto* page = global ? predecessor(global->pc) : nullptr;
    const auto* original = page ? predecessor(page->pc) : nullptr;
    uint32_t actual = 0; unsigned loaded = NoReg;
    if (!checked || !decoded || !global || !page || !original || literalLoad(page->pc, actual, loaded) != decoded->pc || actual != expected) return false;
    const auto& sub = decoded->insn; const auto& load = original->insn; const auto& cmp = checked->insn;
    return sub.op == Op::Other && sub.other() == Other::Subtract && sub.width() == 8 && sub.src == argument->insn.src &&
      load.op == Op::LoadField && load.width() == 8 && load.src == saved->insn.src && load.disp == saved->insn.disp &&
      !(load.detail & 0x800) && load.dst == sub.imm && cmp.op == Op::Other && cmp.other() == Other::CmpReg && cmp.width() == 8 &&
      ((cmp.dst == loaded && cmp.src == sub.dst) || (cmp.src == loaded && cmp.dst == sub.dst));
#elif defined(AUTOSCAN_X64) || defined(AUTOSCAN_X86)
    auto entry = Lift(pe.code(call.insn.target()), call.insn.target());
    constexpr unsigned pointerWidth = sizeof(void*);
    if (!call.insn.target() || entry.op != Op::Other || entry.other() != Other::CmpReg || entry.width() != pointerWidth ||
        !entry.memory() || !entry.setsFlags() || (!(entry.detail & 0x100) && entry.src != NoReg)) return false;
    auto guard = Lift(pe.code(call.insn.target() + entry.length()), call.insn.target() + entry.length());
    if (!guard.conditional() || guard.condition() != 5 || callEffect(pe, guard.target(), 0)) return false;
    auto simple = [](const LiftedInsn& i) {
      return i.op == Op::MovReg || i.op == Op::LoadField ||
        (i.op == Op::Other && (i.other() == Other::XorReg || i.other() == Other::Nop));
    };
    FixedList<const Node*, 16> tail, prefix;
    const Node* branch = nullptr; uint32_t pc = call.pc;
    for (unsigned n = 0; n < 8; ++n) {
      auto* previous = predecessor(pc); if (!previous) return false;
      if (previous->insn.conditional()) {
        if (previous->insn.condition() == 5 && previous->insn.target() == pc) branch = previous;
        break;
      }
      if (!simple(previous->insn) || previous->pc + previous->insn.length() != pc) return false;
      tail.push_back(previous); pc = previous->pc;
    }
    if (!branch) return false;
    auto* compare = predecessor(branch->pc);
    if (!compare || compare->insn.op != Op::Other || compare->insn.other() != Other::CmpReg ||
        compare->pc + compare->insn.length() != branch->pc) return false;
    pc = compare->pc;
    for (unsigned n = 0; n < 16; ++n) {
      auto* previous = predecessor(pc);
      if (!previous || !simple(previous->insn) || previous->pc + previous->insn.length() != pc) break;
      prefix.push_back(previous); pc = previous->pc;
    }
    struct Expr { unsigned kind, a, b; uint64_t value; };
    FixedList<Expr, 96> expressions; std::array<unsigned, 32> regs{};
    auto intern = [&](unsigned kind, unsigned a, unsigned b, uint64_t value) {
      for (unsigned n = 0; n < expressions.size(); ++n) {
        auto e = expressions[n]; if (e.kind == kind && e.a == a && e.b == b && e.value == value) return n + 1;
      }
      return expressions.push_back({kind,a,b,value}) ? static_cast<unsigned>(expressions.size()) : 0u;
    };
    for (unsigned r = 0; r < regs.size(); ++r) regs[r] = intern(0, r, 0, 0);
    auto memory = [&](const Node& n, unsigned base) {
      if (n.insn.detail & 0x100) return intern(2, 0, 0, static_cast<int64_t>(n.pc) + n.insn.length() + n.insn.disp);
      if (base == NoReg) return intern(2, 0, 0, static_cast<uint32_t>(n.insn.disp));
      return base < 32 ? intern(2, regs[base], 0, static_cast<uint64_t>(n.insn.disp)) : 0u;
    };
    auto run = [&](const Node& n) {
      const auto& i = n.insn;
      if (i.op == Op::Other && i.other() == Other::Nop) return true;
      if (i.width() != pointerWidth || i.dst >= 32) return false;
      unsigned value = 0;
      if (i.op == Op::LoadField) value = memory(n, i.src);
      else if (i.op == Op::MovReg) value = i.src < 32 ? regs[i.src] : intern(1, 0, 0, static_cast<uint32_t>(i.imm) | (static_cast<uint64_t>(i.detail) << 32));
      else if (i.op == Op::Other && i.other() == Other::XorReg && !i.memory() && i.src < 32) {
        unsigned a = regs[i.dst], b = regs[i.src];
        value = a == b ? intern(1, 0, 0, 0) : intern(3, std::min(a,b), std::max(a,b), 0);
      }
      regs[i.dst] = value; return value != 0;
    };
    for (size_t n = prefix.size(); n; --n) if (!run(*prefix[n - 1])) return false;
    auto operands = [&](const Node& n, unsigned& left, unsigned& right) {
      const auto& i = n.insn;
      if (i.width() != pointerWidth) return false;
      left = i.dst < 32 ? regs[i.dst] : 0; right = i.src < 32 ? regs[i.src] : 0;
      if (i.memory()) { if (i.setsFlags()) right = memory(n, i.src); else left = memory(n, i.dst); }
      return left && right;
    };
    unsigned left = 0, right = 0, argument = 0, required = 0;
    if (!operands(*compare, left, right)) return false;
    for (size_t n = tail.size(); n; --n) if (!run(*tail[n - 1])) return false;
    if (!operands({call.insn.target(), entry}, argument, required)) return false;
    return (left == argument && right == required) || (right == argument && left == required);
#else
    (void)pe; (void)call; return false;
#endif
  }
  bool build(const PeImage& pe, Range bounds) {
    noReturns.count = 0;
    if (!decode(pe, bounds)) return false;
    for (const auto& n : nodes) if (n.insn.op == Op::Other && n.insn.other() == Other::Call && guardedNoReturn(pe, n))
      if (!noReturns.push_back(n.pc)) { complete = false; return false; }
    return noReturns.empty() || decode(pe, bounds);
  }
  unsigned callEffect(const PeImage& pe, uint32_t pc, unsigned reg, unsigned depth = 0) const {
    // If a called function's effect cannot be established within the limit, assume it may change the value.
    if (!pc || depth == 3) return 3;
    struct Point { uint32_t pc; bool dirty; };
    FixedList<Point, 64> todo, seen;
    todo.push_back({pc, false}); unsigned effect = 0;
    while (!todo.empty()) {
      auto point = todo.back(); --todo.count;
      bool repeat = false;
      for (const auto& p : seen) repeat |= p.pc == point.pc && p.dirty == point.dirty;
      if (repeat) continue;
      if (!seen.push_back(point)) return 3;
      auto i = Lift(pe.code(point.pc), point.pc);
      if (!i.length()) return 3;
      if (i.op == Op::Ret) { effect |= point.dirty ? 2 : 1; continue; }
      if (Terminal(i)) continue;
      point.dirty |= Writes(i, reg);
      if (i.op == Op::Other && i.other() == Other::Call) {
        unsigned nested = callEffect(pe, i.target(), reg, depth + 1);
        if (!nested) continue;
        point.dirty |= VolatileReg(reg) && (nested & 2);
      }
      if ((i.op == Op::Jmp || i.conditional()) && !todo.push_back({i.target(), point.dirty})) return 3;
      if (i.op != Op::Jmp && !todo.push_back({point.pc + i.length(), point.dirty})) return 3;
    }
    return effect;
  }
  SymVal constantBefore(const PeImage& pe, uint32_t pc, unsigned reg) const {
    struct Point { uint32_t pc; unsigned reg; };
    FixedList<Point, 256> todo, seen;
    todo.push_back({pc, reg}); bool found = false; SymVal result;
    while (!todo.empty()) {
      auto point = todo.back(); --todo.count;
      bool repeat = false;
      for (const auto& p : seen) repeat |= p.pc == point.pc && p.reg == point.reg;
      if (repeat) continue;
      if (!seen.push_back(point)) return {};
      bool predecessor = false;
      for (const auto& n : nodes) if (follows(n, point.pc)) {
        predecessor = true; auto i = n.insn; unsigned source = point.reg;
        if (i.op == Op::Other && i.other() == Other::Call && VolatileReg(source)) {
          unsigned effect = callEffect(pe, i.target(), source);
          if (!effect) continue;
          if (effect & 2) return {};
        }
        if (Writes(i, source)) {
          bool known = false; uint64_t value = 0;
          if (i.op == Op::MovReg && i.width() >= 4) {
            if (i.src != NoReg) source = i.src;
            else { value = static_cast<uint32_t>(i.imm) | (i.width() == 8 ? static_cast<uint64_t>(i.detail) << 32 : 0); known = true; }
          } else if (i.op == Op::Other && i.other() == Other::XorReg && i.dst == i.src && i.width() >= 4) known = true;
          else return {};
          if (known) {
            if (found && result.value != value) return {};
            found = true; result = SymVal::constant(value); continue;
          }
        }
        if (!todo.push_back({n.pc, source})) return {};
      }
      if (!predecessor) return {};
    }
    return found ? result : SymVal{};
  }
};

struct Head { uint32_t compare = 0, jump = 0, affected = 0, unaffected = 0; bool inverted = false; };
struct Field { uint16_t base = 0; int32_t disp = 0; uint8_t width = 0; unsigned comparisons = 0; };
struct Role { unsigned version = 0, type = 0, location = 0; int flag = -1; std::array<int64_t, 5> offsets{}; };
class Evaluator {
  // Each state is a possible route through the decision, with the values and comparisons known on that route.
  static constexpr size_t MaxFields = 32;
  struct Flags { SymVal value{}; uint64_t immediate = 0; unsigned width = 4; enum { Unknown, Compare, Test, Bit, BitZero, Literal } kind = Unknown; };
  struct State {
    std::array<SymVal, 32> regs{};
    std::array<S32Interval, MaxFields> constraints{};
    Flags flags{};
    uint32_t pc = 0; unsigned steps = 0;
  };
  struct Outcome { std::array<S32Interval, MaxFields> constraints; int result; };
  struct Checkpoint { uint32_t pc = 0, changed = 0; std::array<SymVal, 32> regs{}; bool ret = false; uint8_t byteStore = NoReg; };
  const PeImage& pe_;
  const Program& program_;
  Head head_;
  FixedList<Field, MaxFields> fields_;
  FixedList<Outcome, 256> outcomes_;
  FixedList<Checkpoint, 16> checkpoints_;
  FixedList<std::pair<uint32_t, unsigned>, 16> exits_;
  State initial_;
  int version_ = -1;
  bool overflow_ = false;
  bool freeEligible_ = false;
  uint32_t rootAt_ = 0;
  static uint64_t mask(unsigned width) { return width == 8 ? UINT64_MAX : (uint64_t{1} << (width * 8)) - 1; }
  static bool same(SymVal a, SymVal b, unsigned width) {
    if (a.kind == SymKind::Unknown || b.kind != a.kind || a.known < width || b.known < width) return false;
    if (a.kind == SymKind::Const) return (a.value & mask(width)) == (b.value & mask(width));
    return a.base == b.base && a.disp == b.disp && a.add == b.add;
  }
  int field(SymVal value) {
    if (value.kind != SymKind::FieldVal) return -1;
    for (size_t n = 0; n < fields_.size(); ++n) {
      auto f = fields_[n];
      if (f.base == value.base && f.disp == value.disp && f.width == value.width) return static_cast<int>(n);
    }
    if (!fields_.push_back({value.base, value.disp, value.width, 0})) { overflow_ = true; return -1; }
    return static_cast<int>(fields_.size() - 1);
  }
  SymVal scalar(SymVal v, unsigned width) {
    if (v.known < width) return {};
    if (v.kind == SymKind::Const) { v.value &= mask(width); return v; }
    if (v.kind == SymKind::FieldVal && width < v.width) return {};
    if (v.kind == SymKind::PtrOffset && v.base >= 1 && v.base <= 32 && width == 4) {
      v.kind = SymKind::FieldVal; v.add = v.disp; v.disp = v.base - 1; v.base = 0; v.width = 4;
    }
    return v;
  }
  SymVal move(SymVal value, unsigned width) {
    return value.kind == SymKind::PtrOffset && width == sizeof(void*) ? value : scalar(value, width);
  }
  SymVal load(SymVal address, int32_t displacement, unsigned width, State& state) {
    if (address.kind == SymKind::FieldVal && address.width == sizeof(void*) && !address.add) {
      int index = field(address); if (index < 0) return {};
      address = SymVal::pointer(33 + index);
    }
    if (address.kind != SymKind::PtrOffset) return {};
    int64_t offset = static_cast<int64_t>(address.disp) + displacement;
    if (offset < INT32_MIN || offset > INT32_MAX) return {};
    SymVal value; value.kind = SymKind::FieldVal; value.base = address.base;
    value.disp = static_cast<int32_t>(offset); value.width = value.known = static_cast<uint8_t>(width);
    int index = field(value);
    if (index >= 0 && width < 4) state.constraints[index] = Intersect(state.constraints[index], {0, static_cast<int32_t>(mask(width))});
    return value;
  }
  SymVal operand(const LiftedInsn& i, State& s) {
    if (i.dst >= s.regs.size()) return {};
    return i.memory() ? load(s.regs[i.dst], i.disp, i.width(), s) : scalar(s.regs[i.dst], i.width());
  }
  void write(State& s, unsigned reg, SymVal value, unsigned width, bool zeroExtend = false) {
    if (reg >= s.regs.size()) { overflow_ = true; return; }
    if (width < 4 && value.kind == SymKind::Const && s.regs[reg].kind == SymKind::Const && s.regs[reg].width >= 4) {
      value.value = (s.regs[reg].value & ~mask(width)) | (value.value & mask(width)); value.width = value.known = s.regs[reg].width;
    } else if (value.kind == SymKind::Const) { value.value &= mask(width); value.width = value.known = width >= 4 || zeroExtend ? 8 : static_cast<uint8_t>(width); }
    else if (value.kind != SymKind::Unknown) value.known = width >= 4 || zeroExtend ? 8 : static_cast<uint8_t>(width);
    s.regs[reg] = value;
  }
  void compare(State& s, SymVal value, uint64_t immediate, unsigned width) {
    s.flags = {value, immediate, width, Flags::Compare};
    int index = field(value);
    if (index >= 0 && width == 4) {
      int64_t n = static_cast<int32_t>(immediate) - static_cast<int64_t>(value.add);
      fields_[index].comparisons |= n == 1 ? 1 : n == 3 ? 2 : n == 8 ? 4 : n == 5 ? 8 : n == 10 ? 16 : 0;
    }
  }
  SymVal add(SymVal value, int32_t immediate, unsigned width) {
    if (width == 4 && sizeof(void*) == 8) value = scalar(value, width);
    if (value.kind == SymKind::Const) value.value = (value.value + static_cast<int64_t>(immediate)) & mask(width);
    else if (value.kind == SymKind::PtrOffset) {
      int64_t offset = static_cast<int64_t>(value.disp) + immediate;
      if (offset < INT32_MIN || offset > INT32_MAX) return {};
      value.disp = static_cast<int32_t>(offset);
    } else if (value.kind == SymKind::FieldVal && width == 4)
      value.add = static_cast<int32_t>(static_cast<uint32_t>(value.add) + static_cast<uint32_t>(immediate));
    else if (value.kind == SymKind::FieldVal && width == sizeof(void*) && value.width == sizeof(void*) && !value.add) {
      int index = field(value); if (index < 0) return {};
      value = SymVal::pointer(33 + index, immediate);
    } else return {};
    return value;
  }
  void prefix(const LiftedInsn& compareInsn) {
    freeEligible_ = head_.compare - program_.range.begin <= 16;
    rootAt_ = head_.compare;
#if !defined(AUTOSCAN_X86)
    if (compareInsn.memory()) return;
#else
    (void)compareInsn;
#endif
    FixedList<const Node*, 32> previous;
    uint32_t pc = head_.compare;
    for (unsigned n = 0; n < 32; ++n) {
      const auto* before = program_.predecessor(pc);
      if (!before || before->insn.conditional() || before->insn.op == Op::Jmp ||
          (before->insn.op == Op::Other && (before->insn.other() == Other::Unknown || before->insn.other() == Other::Call ||
            before->insn.other() == Other::Store || before->insn.other() == Other::AtomicAdd))) break;
      previous.push_back(before); pc = before->pc;
    }
    rootAt_ = pc;
    for (unsigned r = 0; r < 32; ++r) {
      auto value = program_.constantBefore(pe_, pc, r);
      initial_.regs[r] = value.kind == SymKind::Const && (value.value == 0 || value.value == 1 || value.value == 0x10a) ? value : SymVal::pointer(r + 1);
    }
    for (size_t n = previous.size(); n; --n) {
      auto i = previous[n - 1]->insn;
      if (i.op == Op::MovReg) {
        auto value = i.src == NoReg ? SymVal::constant(static_cast<uint32_t>(i.imm) | (static_cast<uint64_t>(i.detail) << 32)) :
          i.src < 32 ? move(initial_.regs[i.src], i.width()) : SymVal{};
        write(initial_, i.dst, value, i.width());
      } else if (i.op == Op::LoadField) {
        auto value = i.src < 32 ? load(initial_.regs[i.src], i.detail & 0x1000 ? 0 : i.disp, i.width(), initial_) : SymVal{};
        if ((i.detail & 0x800) && i.src < 32) write(initial_, i.src, add(initial_.regs[i.src], i.disp, sizeof(void*)), sizeof(void*));
        write(initial_, i.dst, value, i.width(), i.setsFlags());
      } else if (i.op == Op::AddImm) write(initial_, i.dst, i.src < 32 ? add(initial_.regs[i.src], i.imm, i.width()) : SymVal{}, i.width());
      else if (i.op == Op::Other && i.other() == Other::XorReg && i.dst == i.src && !i.memory())
        write(initial_, i.dst, SymVal::constant(0), i.width());
      else if (i.op == Op::Other && (i.other() == Other::Push || i.other() == Other::Pop)) {
        auto& stack = initial_.regs[4];
        if (stack.kind == SymKind::PtrOffset) stack.disp += i.other() == Other::Push ? -static_cast<int32_t>(sizeof(void*)) : static_cast<int32_t>(sizeof(void*));
        if (i.other() == Other::Pop && i.dst < 32) initial_.regs[i.dst] = {};
      } else for (unsigned r = 0; r < 32; ++r) if (Writes(i,r)) initial_.regs[r] = {};
    }
  }
  static int condition(const Flags& f, unsigned cc) {
    if (f.kind == Flags::Unknown || f.value.kind != SymKind::Const || cc > 15) return -1;
    uint64_t a = f.value.value & mask(f.width), b = f.immediate & mask(f.width);
    if (f.kind == Flags::Bit || f.kind == Flags::BitZero) {
      if (f.kind == Flags::BitZero) cc = cc == 4 ? 3 : cc == 5 ? 2 : 16;
      if (cc != 2 && cc != 3) return -1;
      bool carry = (b >> (a & (f.width * 8 - 1))) & 1;
      return cc == 2 ? carry : !carry;
    }
    uint64_t result = f.kind == Flags::Test ? a & b : (a - b) & mask(f.width);
    uint64_t sign = uint64_t{1} << (f.width * 8 - 1);
    bool cf = f.kind == Flags::Compare && a < b, zf = result == 0, sf = (result & sign) != 0;
    bool of = f.kind == Flags::Compare && ((a ^ b) & (a ^ result) & sign);
    if (f.kind == Flags::Literal) { sf = (f.immediate & 8) != 0; zf = (f.immediate & 4) != 0; cf = !(f.immediate & 2); of = (f.immediate & 1) != 0; }
    switch (cc) {
      case 0: return of; case 1: return !of; case 2: return cf; case 3: return !cf;
      case 4: return zf; case 5: return !zf; case 6: return cf || zf; case 7: return !cf && !zf;
      case 8: return sf; case 9: return !sf;
      case 12: return sf != of; case 13: return sf == of; case 14: return zf || sf != of; case 15: return !zf && sf == of;
      default: return -1;
    }
  }
  bool branch(const State& source, unsigned cc, bool take, uint32_t target, unsigned setReg, FixedList<State, 64>& todo) {
    cc ^= take ? 0 : 1;
    auto push = [&](S32Interval interval, int index) {
      if (interval.empty()) return true;
      State next = source; next.pc = target;
      if (index >= 0) next.constraints[index] = interval;
      if (setReg != NoReg) write(next, setReg, SymVal::constant(take), StackReg == 31 ? 4 : 1);
      if (!todo.push_back(next)) { overflow_ = true; return false; }
      return true;
    };
    int known = condition(source.flags, cc);
    if (known >= 0) return !known || push({}, -1);
    auto value = source.flags.value;
    int index = field(value);
    if (index < 0 || source.flags.kind == Flags::Unknown) return false;
    S32Interval current = source.constraints[index];
    if (source.flags.kind == Flags::Bit || source.flags.kind == Flags::BitZero) {
      if (source.flags.kind == Flags::BitZero) cc = cc == 4 ? 3 : cc == 5 ? 2 : 16;
      if ((cc != 2 && cc != 3) || static_cast<int64_t>(current.low) + value.add < 0 ||
          static_cast<int64_t>(current.high) + value.add >= static_cast<int64_t>(source.flags.width * 8)) return false;
      for (int64_t n = current.low; n <= current.high; ++n) {
        bool carry = (source.flags.immediate >> (n + value.add)) & 1;
        if ((cc == 2 ? carry : !carry) && !push({static_cast<int32_t>(n), static_cast<int32_t>(n)}, index)) return false;
      }
      return true;
    }
    if (source.flags.kind == Flags::Test && source.flags.immediate != mask(source.flags.width)) return false;
    int32_t immediate = source.flags.kind == Flags::Test ? 0 : static_cast<int32_t>(source.flags.immediate);
    if (source.flags.width > 4 || (source.flags.width != 4 && cc != 4 && cc != 5)) return false;
    FixedList<S32Interval, 4> allowed;
    auto add = [&](int64_t low, int64_t high) {
      low = std::max<int64_t>(low, INT32_MIN); high = std::min<int64_t>(high, INT32_MAX);
      if (low <= high) allowed.push_back({static_cast<int32_t>(low), static_cast<int32_t>(high)});
    };
    auto unsignedRange = [&](uint64_t low, uint64_t high) {
      if (low > high || low > UINT32_MAX) return;
      high = std::min<uint64_t>(high, UINT32_MAX);
      if (low <= INT32_MAX) add(low, std::min<uint64_t>(high, INT32_MAX));
      if (high > INT32_MAX) add(static_cast<int64_t>(std::max<uint64_t>(low, 0x80000000ull)) - 0x100000000ll,
                               static_cast<int64_t>(high) - 0x100000000ll);
    };
    if (cc >= 12) allowed.push_back(SplitSigned({}, cc, immediate).taken);
    else if (cc == 4) add(immediate, immediate);
    else if (cc == 5) { add(INT32_MIN, static_cast<int64_t>(immediate) - 1); add(static_cast<int64_t>(immediate) + 1, INT32_MAX); }
    else {
      uint64_t u = static_cast<uint32_t>(immediate);
      if (source.flags.kind == Flags::Test) {
        if (cc == 2) return true;
        if (cc == 3) return push(current, index);
      }
      if (cc == 2) { if (u) unsignedRange(0, u - 1); }
      else if (cc == 3) unsignedRange(u, UINT32_MAX);
      else if (cc == 6) unsignedRange(0, u);
      else if (cc == 7) unsignedRange(u + 1, UINT32_MAX);
      else return false;
    }
    for (auto range : allowed) if (!range.empty()) {
      // Include values that wrap around at the 32-bit limit when undoing an addition.
      for (int64_t wrap : {-0x100000000ll, 0ll, 0x100000000ll}) {
        int64_t low = static_cast<int64_t>(range.low) - value.add + wrap;
        int64_t high = static_cast<int64_t>(range.high) - value.add + wrap;
        low = std::max<int64_t>(low, current.low); high = std::min<int64_t>(high, current.high);
        if (low <= high && !push({static_cast<int32_t>(low), static_cast<int32_t>(high)}, index)) return false;
      }
    }
    return true;
  }
  bool falseFlagsSafe() const {
    // Taking the existing non-MV2 route must not depend on leftover comparison results we cannot establish.
    FixedList<uint32_t, 128> todo, seen; todo.push_back(head_.unaffected);
    while (!todo.empty()) {
      auto pc = todo.back(); --todo.count;
      bool repeat = false; for (auto old : seen) repeat |= old == pc;
      if (repeat) continue;
      if (!seen.push_back(pc)) return false;
      const auto* node = program_.at(pc); if (!node) return false;
      const auto& i = node->insn;
      if (Terminal(i) || i.op == Op::CmpImm || (i.op == Op::AddImm && i.setsFlags())) continue;
      bool registerBranch = i.op == Op::Other && i.other() == Other::RegisterBranch;
      if (i.op == Op::Other) {
        auto o = i.other();
        if (o == Other::AtomicAdd && (i.detail & 0x4000)) return false;
        if (o == Other::Call || o == Other::CmpReg || o == Other::TestReg || o == Other::TestImm ||
            (StackReg != 31 && (o == Other::AndReg || o == Other::AndImm || o == Other::OrReg || o == Other::OrImm ||
                              o == Other::XorReg || (o == Other::AtomicAdd && !(i.detail & 0x2000)))) || (o == Other::Overwrite && i.setsFlags())) continue;
        if (o != Other::Nop && o != Other::Push && o != Other::Pop && o != Other::Store && o != Other::Overwrite &&
            o != Other::PairLoad && o != Other::ShiftRight && o != Other::Subtract && o != Other::AtomicAdd && !registerBranch) return false;
      }
      if (i.conditional() && !registerBranch) return false;
      if ((i.op == Op::Jmp || registerBranch) && !todo.push_back(i.target())) return false;
      if (i.op != Op::Jmp && !todo.push_back(pc + i.length())) return false;
    }
    return true;
  }
  void checkpoints() {
    State state = initial_; state.pc = head_.unaffected; uint32_t changed = 0;
    for (unsigned n = 0; n < 16; ++n) {
      const auto* node = program_.at(state.pc); if (!node) break;
      const auto& i = node->insn;
      bool repeat = false;
      for (const auto& point : checkpoints_) repeat |= point.pc == state.pc;
      if (repeat) break;
      uint8_t byteStore = NoReg;
      if (i.op == Op::Other && i.other() == Other::Store && i.width() == 1 && i.src < 32 && i.dst != i.src &&
          (changed & (1u << i.src)) && same(state.regs[i.src], SymVal::constant(0), 1)) {
        uint32_t next = state.pc + i.length();
        for (unsigned look = 0; look < 8; ++look) {
          const auto* after = program_.at(next); if (!after) break;
          const auto& overwrite = after->insn;
          if (overwrite.op == Op::Other && overwrite.other() == Other::Nop) { next += overwrite.length(); continue; }
          if ((overwrite.op == Op::MovReg || overwrite.op == Op::LoadField || (overwrite.op == Op::Other && overwrite.other() == Other::Overwrite)) &&
              overwrite.dst == i.src && overwrite.src != i.src && overwrite.width() >= 4) byteStore = i.src;
          break;
        }
      }
      checkpoints_.push_back({state.pc, changed, state.regs, i.op == Op::Ret, byteStore});
      if (i.op == Op::Jmp) { state.pc = i.target(); continue; }
      if (i.op == Op::MovReg && i.src == NoReg) {
        write(state, i.dst, SymVal::constant(static_cast<uint32_t>(i.imm) | (static_cast<uint64_t>(i.detail) << 32)), i.width());
      } else if (i.op == Op::Other && i.other() == Other::XorReg && i.dst == i.src && !i.memory())
        write(state, i.dst, SymVal::constant(0), i.width());
      else if (i.op != Op::Other || i.other() != Other::Nop) break;
      if (i.dst < 32) changed |= 1u << i.dst;
      state.pc += i.length();
    }
  }
  bool falseCheckpoint(const State& state) const {
    for (const auto& point : checkpoints_) if (point.pc == state.pc) {
      bool equal = true;
      for (unsigned r = 0; r < 32; ++r) if ((point.changed & (1u << r)) && !(point.ret && r == 0))
        equal &= same(state.regs[r], point.regs[r], point.byteStore == r ? 1 : sizeof(void*));
      if (point.ret) equal &= same(state.regs[0], point.regs[0], 1);
      if (equal) return true;
    }
    return false;
  }
  bool walk(uint32_t affectedExit = 0) {
    // Explore both possible sides of comparisons; unsupported operations or too much work prevent a proof.
    outcomes_.count = 0;
    FixedList<State, 64> todo; todo.push_back(initial_);
    unsigned budget = 0;
    auto outcome = [&](const State& s, int result) {
      if (!outcomes_.push_back({s.constraints, result})) overflow_ = true;
    };
    while (!todo.empty() && !overflow_) {
      State s = todo.back(); --todo.count;
      for (;;) {
        if (++s.steps > 256 || ++budget > 8192) return false;
        if (falseCheckpoint(s)) { outcome(s, 0); break; }
        if (affectedExit && s.pc == affectedExit) { outcome(s, 1); break; }
        const auto* node = program_.at(s.pc);
        if (!node) { outcome(s, -1); break; }
        const auto& i = node->insn; ++decoded;
        uint32_t next = s.pc + i.length();
        if (i.conditional()) {
          Flags preserved = s.flags;
          bool registerBranch = i.op == Op::Other && i.other() == Other::RegisterBranch;
          if (registerBranch) {
            auto value = i.src == 31 ? SymVal::constant(0) : scalar(s.regs[i.src], i.width());
            if (value.kind == SymKind::BitShift && i.disp == 1) {
              value.kind = SymKind::FieldVal; s.flags = {value, value.value, i.width(), Flags::BitZero};
            } else {
              int index = field(value);
              // The converted-user-script member is a C++ bool; ARM64 tests its low bit.
              if (index >= 0 && value.width == 1 && i.disp == 1) s.constraints[index] = Intersect(s.constraints[index], {0,1});
              bool boolean = index >= 0 && value.width == 1 && i.disp == 1;
              s.flags = {value, !i.disp || boolean ? mask(i.width()) : uint64_t{1} << (i.disp - 1), i.width(), Flags::Test};
            }
          }
          if (s.flags.kind == Flags::Compare && (s.flags.immediate == 5 || s.flags.immediate == 10)) {
            int index = field(s.flags.value);
            if (index >= 0) for (auto pc : {i.target(), next}) {
              bool found = false; for (auto exit : exits_) found |= exit.first == pc && exit.second == static_cast<unsigned>(index);
              if (!found && !exits_.push_back({pc, static_cast<unsigned>(index)})) overflow_ = true;
            }
          }
          auto first = todo.size();
          if (!branch(s, i.condition(), true, i.target(), NoReg, todo) || !branch(s, i.condition(), false, next, NoReg, todo)) outcome(s, -1);
          if (registerBranch) for (size_t n = first; n < todo.size(); ++n) todo[n].flags = preserved;
          break;
        }
        if (i.op == Op::Jmp) { s.pc = i.target(); continue; }
        if (i.op == Op::Ret) {
          auto value = scalar(s.regs[0], 1);
          outcome(s, value.kind == SymKind::Const && value.value <= 1 ? static_cast<int>(value.value) : -1); break;
        }
        if (i.op == Op::Other && i.other() == Other::Store) {
          int result = -1;
          for (const auto& point : checkpoints_) if (point.pc == s.pc && point.byteStore != NoReg) {
            auto value = scalar(s.regs[point.byteStore], 1); bool equal = true;
            for (unsigned r = 0; r < 32; ++r) if ((point.changed & (1u << r)) && r != point.byteStore)
              equal &= same(s.regs[r], point.regs[r], sizeof(void*));
            if (equal && value.kind == SymKind::Const && value.value <= 1) result = static_cast<int>(value.value);
          }
          outcome(s, result); break;
        }
        if (i.op == Op::CmpImm) compare(s, operand(i, s), static_cast<uint64_t>(static_cast<int64_t>(i.imm)), i.width());
        else if (i.op == Op::LoadField) {
          if (i.src >= 32) { outcome(s, -1); break; }
          auto value = load(s.regs[i.src], i.detail & 0x1000 ? 0 : i.disp, i.width(), s);
          if (i.detail & 0x800) write(s, i.src, add(s.regs[i.src], i.disp, sizeof(void*)), sizeof(void*));
          write(s, i.dst, value, i.width(), i.setsFlags());
        } else if (i.op == Op::MovReg) {
          auto value = i.src == NoReg ? SymVal::constant(static_cast<uint32_t>(i.imm) | (static_cast<uint64_t>(i.detail) << 32)) :
            i.src < 32 ? move(s.regs[i.src], i.width()) : SymVal{};
          write(s, i.dst, value, i.width());
        } else if (i.op == Op::AddImm) {
          auto value = i.src < 32 ? add(s.regs[i.src], i.imm, i.width()) : SymVal{};
          write(s, i.dst, value, i.width());
          if (i.setsFlags()) s.flags = {};
        } else if (i.op == Op::Other) {
          auto kind = i.other();
          if (kind == Other::Nop) {}
#if !defined(AUTOSCAN_ARM64)
          else if (kind == Other::Pop && i.dst < 32 && i.dst != 4) {
            s.regs[i.dst] = {};
            s.regs[4] = add(s.regs[4], sizeof(void*), sizeof(void*));
          }
#endif
          else if (kind == Other::Setcc) {
            if (!branch(s, i.src, true, next, i.dst, todo) || !branch(s, i.src, false, next, i.dst, todo)) outcome(s, -1);
            break;
          } else if (kind == Other::ConditionalCompare || kind == Other::Select) {
            unsigned cc = kind == Other::Select ? static_cast<unsigned>(i.disp) : i.src;
            for (bool take : {true, false}) {
              auto first = todo.size();
              if (!branch(s, cc, take, next, NoReg, todo)) { outcome(s, -1); break; }
              for (size_t n = first; n < todo.size(); ++n) {
                auto& out = todo[n];
                if (kind == Other::Select) {
                  unsigned reg = take ? i.src : static_cast<unsigned>(i.imm);
                  write(out, i.dst, reg == 31 ? SymVal::constant(0) : scalar(out.regs[reg], i.width()), i.width());
                } else if (take) compare(out, scalar(out.regs[i.dst], i.width()), static_cast<uint32_t>(i.imm), i.width());
                else out.flags = {SymVal::constant(0), static_cast<uint32_t>(i.disp), i.width(), Flags::Literal};
              }
            }
            break;
          } else if (kind == Other::ShiftRight) {
            auto bits = i.src < 32 ? scalar(s.regs[i.src], i.width()) : SymVal{};
            auto value = i.imm < 32 ? scalar(s.regs[i.imm], i.width()) : SymVal{};
            if (bits.kind != SymKind::Const || value.kind != SymKind::FieldVal || value.add || i.width() != 4) { outcome(s, -1); break; }
            int index = field(value);
            if (index >= 0 && bits.value == 0x10a) fields_[index].comparisons |= 7;
            value.kind = SymKind::BitShift; value.value = bits.value;
            write(s, i.dst, value, i.width());
          } else if (kind == Other::BitTest) {
            auto bits = i.dst < 32 ? scalar(s.regs[i.dst], i.width()) : SymVal{};
            auto value = i.src < 32 ? scalar(s.regs[i.src], i.width()) : SymVal{};
            if (bits.kind != SymKind::Const) { outcome(s, -1); break; }
            s.flags = {value, bits.value, i.width(), Flags::Bit};
            int index = field(value);
            if (index >= 0 && bits.value == 0x10a && !value.add && i.width() == 4) fields_[index].comparisons |= 7;
          } else if (kind == Other::CmpReg || kind == Other::TestReg || kind == Other::TestImm) {
            if (i.memory() && i.setsFlags()) { outcome(s, -1); break; }
            auto left = operand(i, s), right = i.src < 32 ? scalar(s.regs[i.src], i.width()) : SymVal{};
            if (kind == Other::TestReg && i.dst == i.src && !i.memory())
              s.flags = {left, mask(i.width()), i.width(), Flags::Test};
            else if (kind == Other::TestImm && left.kind == SymKind::BitShift && i.imm == 1) {
              left.kind = SymKind::FieldVal; s.flags = {left, left.value, i.width(), Flags::BitZero};
            } else if (kind == Other::TestImm) s.flags = {left, static_cast<uint64_t>(static_cast<int64_t>(i.imm)), i.width(), Flags::Test};
            else if (right.kind == SymKind::Const) {
              if (kind == Other::CmpReg) compare(s, left, right.value, i.width());
              else s.flags = {left, right.value, i.width(), Flags::Test};
            } else if (kind == Other::CmpReg && same(left, right, i.width())) compare(s, SymVal::constant(0), 0, i.width());
            else s.flags = {};
          } else if (kind == Other::XorReg || kind == Other::AndReg || kind == Other::OrReg || kind == Other::OrImm || kind == Other::AndImm) {
            if (i.memory() || i.dst >= 32) { outcome(s, -1); break; }
            auto a = scalar(s.regs[i.dst], i.width());
            auto b = kind == Other::AndImm || kind == Other::OrImm ?
              SymVal::constant(static_cast<uint64_t>(static_cast<int64_t>(i.imm))) : i.src < 32 ? scalar(s.regs[i.src], i.width()) : SymVal{};
            if (kind == Other::XorReg && i.dst == i.src) a = SymVal::constant(0);
            else if (a.kind != SymKind::Const || b.kind != SymKind::Const) { outcome(s, -1); break; }
            else if (kind == Other::XorReg) a.value ^= b.value;
            else if (kind == Other::OrReg || kind == Other::OrImm) a.value |= b.value;
            else a.value &= b.value;
            write(s, i.dst, a, i.width()); s.flags = {a, mask(i.width()), i.width(), Flags::Test};
          } else { outcome(s, -1); break; }
        } else { outcome(s, -1); break; }
        s.pc = next;
      }
    }
    return !overflow_ && !outcomes_.empty();
  }
  static unsigned membership(S32Interval interval) {
    unsigned members = interval.contains(1) + interval.contains(3) + interval.contains(8);
    return (members ? 2u : 0u) | (static_cast<int64_t>(interval.high) - interval.low + 1 > members ? 1u : 0u);
  }
  bool proves(const Role& role) const {
    // Every modeled outcome must match the expected extension type, install location, and converted-script rule.
    for (const auto& result : outcomes_) {
      if (result.result < 0) return false;
      auto type = membership(result.constraints[role.type]);
      auto location = result.constraints[role.location];
      unsigned excluded = location.contains(5) + location.contains(10);
      bool locTrue = static_cast<int64_t>(location.high) - location.low + 1 > excluded;
      bool locFalse = excluded != 0;
      bool flagTrue = false, flagFalse = true;
      if (role.flag >= 0) {
        auto flag = result.constraints[role.flag];
        flagTrue = flag.low < 0 || flag.high > 0; flagFalse = flag.contains(0);
      }
      bool yes = (flagTrue || (type & 2)) && locTrue;
      bool no = (flagFalse && (type & 1)) || locFalse;
      if (result.result ? no || !yes : yes || !no) return false;
    }
    return true;
  }
  bool roleFor(unsigned type, unsigned location, Role& role) const {
    if (version_ < 0 || type == location || type == static_cast<unsigned>(version_) || location == static_cast<unsigned>(version_)) return false;
    const auto& mv = fields_[version_]; const auto& tf = fields_[type]; const auto& lf = fields_[location];
    if (mv.width != 4 || tf.width != 4 || lf.width != 4) return false;
    role = {static_cast<unsigned>(version_), type, location, -1, {}};
#if defined(AUTOSCAN_ARM64)
    if (freeEligible_ && !mv.base && mv.disp == 0 && !tf.base && tf.disp == 1 && !lf.base && lf.disp == 2)
      return program_.fromArgument(rootAt_,0,0) && program_.fromArgument(rootAt_,1,1) && program_.fromArgument(rootAt_,2,2);
#elif defined(AUTOSCAN_X64)
    if (freeEligible_ && !mv.base && mv.disp == 1 && !tf.base && tf.disp == 2 && !lf.base && lf.disp == 8)
      return program_.fromArgument(rootAt_,1,1) && program_.fromArgument(rootAt_,2,2) && program_.fromArgument(rootAt_,8,8);
#else
    if (freeEligible_ && mv.base == 5 && mv.disp == 4 && tf.base == 5 && tf.disp == 8 && lf.base == 5 && lf.disp == 12)
      return program_.fromArgument(rootAt_,4,4);
#endif
    if (tf.base != lf.base || tf.base < 33 || tf.base - 33 >= fields_.size()) return false;
    const auto& parent = fields_[tf.base - 33];
    if (parent.width != sizeof(void*) || parent.base != mv.base) return false;
    for (size_t n = 0; n < fields_.size(); ++n) if (fields_[n].width == 1 && fields_[n].base == mv.base) {
      if (role.flag >= 0) return false;
      role.flag = static_cast<int>(n);
    }
    if (role.flag < 0) return false;
    role.offsets = {mv.disp, parent.disp, tf.disp, lf.disp, fields_[role.flag].disp};
    return true;
  }
 public:
  unsigned decoded = 0;
  Evaluator(const PeImage& pe, const Program& program, Head head) : pe_(pe), program_(program), head_(head) {}
  bool verify(Gate& gate, std::string_view& reason) {
    // Accept one connected, unambiguous interpretation; otherwise explain why this decision will not be patched.
    if (!falseFlagsSafe()) { reason = "not-affected path consumes unknown flags"; return false; }
    for (unsigned r = 0; r < 32; ++r) {
      auto value = program_.constantBefore(pe_, head_.compare, r);
      initial_.regs[r] = value.kind == SymKind::Const && (value.value == 0 || value.value == 1 || value.value == 0x10a) ? value : SymVal::pointer(r + 1);
    }
    const auto* node = program_.at(head_.compare);
    if (!node) return false;
    prefix(node->insn);
    auto mv = operand(node->insn, initial_); version_ = field(mv);
    if (version_ < 0 || mv.add || mv.width != 4) { reason = "manifest value is not a connected 32-bit field"; return false; }
    initial_.constraints[version_] = {INT32_MIN, 2};
    compare(initial_, mv, static_cast<uint32_t>(node->insn.imm), 4);
    initial_.pc = head_.affected;
    checkpoints();
    if (!walk()) { reason = overflow_ ? "symbolic state capacity exceeded" : "unsupported predicate or analysis limit"; return false; }
    FixedList<Role, 8> roles;
    for (unsigned t = 0; t < fields_.size(); ++t) if ((fields_[t].comparisons & 7) == 7)
      for (unsigned l = 0; l < fields_.size(); ++l) if ((fields_[l].comparisons & 24) == 24) {
        Role role;
        if (roleFor(t, l, role) && !roles.push_back(role)) { reason = "too many field roles"; return false; }
      }
    if (roles.size() != 1) { reason = "missing or ambiguous connected field roles"; return false; }
    auto role = roles.front(); uint32_t exit = 0;
    if (!proves(role)) {
      if (role.flag < 0) { reason = "predicate differs from MV2 source contract"; return false; }
      auto candidates = exits_;
      for (auto candidate : candidates) if (candidate.second == role.location && program_.at(candidate.first)) {
        bool falsePoint = false; for (const auto& point : checkpoints_) falsePoint |= point.pc == candidate.first;
        if (!falsePoint && walk(candidate.first) && proves(role)) {
          if (exit && exit != candidate.first) { reason = "ambiguous affected continuation"; return false; }
          exit = candidate.first;
        }
      }
      if (!exit) { reason = "predicate differs or has unsupported side effects"; return false; }
    }
    gate.compare = head_.compare; gate.rva = head_.jump; gate.function = program_.range.begin;
    gate.affected = head_.affected; gate.unaffected = head_.unaffected; gate.exit = exit;
    for (unsigned n = 0; n < 8; ++n) {
      const auto* jump = program_.at(gate.unaffected);
      if (!jump || jump->insn.op != Op::Jmp || !program_.range.contains(jump->insn.target())) break;
      gate.unaffected = jump->insn.target();
    }
    gate.fields = role.offsets; gate.freePredicate = role.flag < 0; gate.decoded = decoded;
    return true;
  }
};
} // namespace autoscan
