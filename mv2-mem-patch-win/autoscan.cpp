#include "solver.hpp"
#include <bcrypt.h>

namespace autoscan {
namespace {
bool prefilter(const PeImage& pe, Head head, Range range) {
  FixedList<uint32_t, 256> todo, seen;
  todo.push_back(head.affected); unsigned constants = 0; bool bit = false;
  while (!todo.empty()) {
    auto pc = todo.back(); --todo.count;
    if (!range.contains(pc) || pc == head.unaffected) continue;
    bool repeat = false; for (auto p : seen) repeat |= p == pc;
    if (repeat) continue;
    if (!seen.push_back(pc)) return false;
    auto i = Lift(pe.at(pc, range.end - pc), pc);
    if (!i.length() || Terminal(i) || (i.op == Op::Other && (i.other() == Other::Call || i.other() == Other::Store))) continue;
    if (i.width() == 4 && (i.op == Op::CmpImm || (i.op == Op::Other && i.other() == Other::ConditionalCompare)))
      constants |= i.imm == 1 ? 1 : i.imm == 3 ? 2 : i.imm == 8 ? 4 : i.imm == 5 ? 8 : i.imm == 10 ? 16 : 0;
    bit |= i.op == Op::Other && (i.other() == Other::BitTest || i.other() == Other::ShiftRight);
    if ((i.op == Op::Jmp || i.conditional()) && !todo.push_back(i.target())) return false;
    if (i.op != Op::Jmp && !todo.push_back(pc + i.length())) return false;
  }
  return (constants & 28) == 28 && (bit || (constants & 3) == 3);
}
bool makePatch(const PeImage& pe, Gate& gate, bool inverted) {
  auto jump = Lift(pe.code(gate.rva), gate.rva);
  gate.width = jump.length();
  if (!gate.width || gate.width > gate.stock.size()) return false;
  std::copy_n(pe.code(gate.rva).begin(), gate.width, gate.stock.begin());
  gate.patch = gate.stock;
#if defined(AUTOSCAN_ARM64)
  gate.kind = inverted ? 8 : 2;
  uint32_t word = inverted ? 0xd503201f : (ReadInsn<uint32_t>(gate.stock.data()) & ~15u) | 14;
  if (gate.optional == InstallVerifier) {
    gate.kind = 5;
    word = 0x14000000 | ((static_cast<int64_t>(jump.target()) - gate.rva) / 4 & 0x03ffffff);
  }
  std::memcpy(gate.patch.data(), &word, 4);
#else
  gate.kind = gate.width == 2 ? (inverted ? 6 : 0) : (inverted ? 7 : 1);
  if (inverted) std::fill_n(gate.patch.begin(), gate.width, 0x90);
  else if (gate.width == 2) gate.patch[0] = 0xeb;
  else { gate.patch[0] = 0x90; gate.patch[1] = 0xe9; }
#endif
  return true;
}
bool threshold(const LiftedInsn& cmp, const LiftedInsn& jump) {
  return cmp.op == Op::CmpImm && cmp.width() == 4 && jump.op == Op::JccSigned &&
    ((cmp.imm == 2 && (jump.condition() == 14 || jump.condition() == 15)) ||
     (cmp.imm == 3 && (jump.condition() == 12 || jump.condition() == 13)));
}
bool references(const PeImage& pe, uint32_t literal, FixedList<uint32_t, 64>& found) {
  auto code = pe.at(pe.text.rva, pe.text.size);
#if defined(AUTOSCAN_ARM64)
  for (size_t n = 0; n + 8 <= code.size(); n += 4) {
    uint32_t word = ReadInsn<uint32_t>(code.data() + n), next = ReadInsn<uint32_t>(code.data() + n + 4);
    if ((word & 0x9f000000) != 0x90000000 || (next & 0xffc00000) != 0x91000000 ||
        (next & 31) != (word & 31) || ((next >> 5) & 31) != (word & 31)) continue;
    int32_t pages = static_cast<int32_t>((((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3)) << 11) >> 11;
    uint32_t pc = pe.text.rva + static_cast<uint32_t>(n);
    if (static_cast<int64_t>(pc & ~0xfffu) + int64_t{pages} * 4096 + ((next >> 10) & 0xfff) == literal &&
        !found.push_back(pc)) return false;
  }
#else
  for (size_t n = 2; n + 4 <= code.size(); ++n) {
#if defined(AUTOSCAN_X64)
    if ((code[n - 1] & 0xc7) != 5) continue;
    uint8_t op = code[n - 2];
    if (op != 0x8d && !(n >= 3 && code[n - 3] == 0x0f &&
        (op == 0x10 || op == 0x11 || op == 0x28 || op == 0x29 || op == 0x6f || op == 0x7f))) continue;
    int64_t end = static_cast<int64_t>(pe.text.rva) + n + 4;
    if (end + ReadInsn<int32_t>(code.data() + n) != literal) continue;
#else
    if (ReadInsn<uint32_t>(code.data() + n) != pe.imageBase + literal) continue;
    int64_t end = static_cast<int64_t>(pe.text.rva) + n + 4;
#endif
    uint32_t first = static_cast<uint32_t>(std::max<int64_t>(pe.text.rva, end - 15));
    for (uint32_t pc = first; pc + 4 < end; ++pc) {
      auto i = Lift(pe.code(pc), pc);
      if (!i.length() || pc + i.length() != end) continue;
#if defined(AUTOSCAN_X64)
      if (!(i.detail & 0x100) || (op == 0x8d && i.width() != 8)) continue;
#else
      if (!((i.op == Op::MovReg && i.src == NoReg) || (i.op == Op::Other && i.other() == Other::Push && i.dst == NoReg) ||
            (i.memory() && i.disp == static_cast<int32_t>(pe.imageBase + literal)))) continue;
#endif
      if (!found.push_back(pc)) return false;
    }
  }
#endif
  return true;
}
void installVerifier(const PeImage& pe, const Boundaries& boundaries, Program& program, const std::array<int64_t, 5>& layout, Report& report) {
  auto data = pe.at(pe.rdata.rva, pe.rdata.size), code = pe.at(pe.text.rva, pe.text.size);
  constexpr char name[] = "InstallVerifier";
  FixedList<uint32_t, 16> literals, getters;
  auto unique = [](auto& list, uint32_t value) {
    for (auto n : list) if (n == value) return true;
    return list.push_back(value);
  };
  for (size_t n = 0; n + sizeof(name) <= data.size(); ++n) if (!memcmp(data.data() + n, name, sizeof(name)))
    if (!literals.push_back(pe.rdata.rva + static_cast<uint32_t>(n))) { report.installVerifier = "ambiguous provider name"; return; }
  if (literals.empty()) { report.installVerifier = "provider name absent"; return; }
  for (auto literal : literals) {
    FixedList<uint32_t, 64> refs;
    if (!references(pe, literal, refs)) { report.installVerifier = "too many provider references"; return; }
    for (auto pc : refs) {
      auto range = boundaries.find(pc);
      if (!range || range.end - range.begin > 256 || !program.build(pe, range) || !program.at(pc)) continue;
      if (!unique(getters, range.begin)) { report.installVerifier = "too many provider getters"; return; }
    }
  }
  FixedList<uint32_t, 64> methods;
  for (size_t n = 0; n + sizeof(uintptr_t) <= data.size(); n += sizeof(uintptr_t)) {
    uint64_t pointer = ReadInsn<uintptr_t>(data.data() + n);
    if (pointer < pe.imageBase || pointer - pe.imageBase > UINT32_MAX) continue;
    bool getter = false; for (auto rva : getters) getter |= rva == pointer - pe.imageBase;
    if (!getter) continue;
    bool bounded = false;
    for (unsigned slot = 1; slot <= 32 && n + (slot + 1) * sizeof(uintptr_t) <= data.size(); ++slot) {
      pointer = ReadInsn<uintptr_t>(data.data() + n + slot * sizeof(uintptr_t));
      if (pointer < pe.imageBase || pointer - pe.imageBase > UINT32_MAX || !pe.text.contains(static_cast<uint32_t>(pointer - pe.imageBase))) { bounded = true; break; }
      auto range = boundaries.find(static_cast<uint32_t>(pointer - pe.imageBase));
      if (range && range.begin == pointer - pe.imageBase && !unique(methods, range.begin)) { report.installVerifier = "too many provider methods"; return; }
    }
    if (!bounded) { report.installVerifier = "unbounded provider vtable"; return; }
  }
  FixedList<Gate, 16> candidates;
  for (auto start : methods) {
    auto range = boundaries.find(start);
    if (!range || !program.build(pe, range)) continue;
    bool reason = false;
    for (const auto& n : program.nodes) {
      const auto& i = n.insn;
      if (i.op != Op::Other || i.other() != Other::Store || i.width() != 4 || (i.detail & 0x400)) continue;
      auto value = i.src == NoReg ? SymVal::constant(static_cast<uint32_t>(i.imm)) : program.constantBefore(pe, n.pc, i.src);
      reason |= value.kind == SymKind::Const && value.value == 0x100;
    }
    if (!reason) continue;
    for (const auto& n : program.nodes) {
      const auto& test = n.insn;
      const auto* decision = program.at(n.pc + test.length());
      if (!decision || !decision->insn.conditional() || decision->insn.condition() != 5 || !range.contains(decision->insn.target())) continue;
#if defined(AUTOSCAN_ARM64)
      if (test.op != Op::LoadField || test.width() != 1 || decision->insn.other() != Other::RegisterBranch ||
          decision->insn.src != test.dst || decision->insn.disp != 4 || !program.fromArgument(n.pc, test.src, 1)) continue;
#else
      if (test.op != Op::Other || test.other() != Other::TestImm || !test.memory() ||
          (test.width() != 1 && test.width() != 4) || test.imm != 8) continue;
#if defined(AUTOSCAN_X86)
      if (!program.fromArgument(n.pc, test.dst, NoReg, 4)) continue;
#else
      if (!program.fromArgument(n.pc, test.dst, 2)) continue;
#endif
#endif
      auto jump = decision->insn;
      uint32_t pc = decision->pc + jump.length(); bool called = false, joined = false;
      for (unsigned steps = 0; steps < 24; ++steps) {
        const auto* next = program.at(pc); if (!next || Terminal(next->insn) || next->insn.op == Op::Jmp || pc == jump.target()) break;
        const auto& i = next->insn;
#if defined(AUTOSCAN_ARM64)
        if (called && i.op == Op::Other && i.other() == Other::RegisterBranch && i.src == 0 && i.disp == 1) {
          joined = (i.condition() == 4 && pc + i.length() == jump.target()) ||
                   (i.condition() == 5 && i.target() == jump.target());
          break;
        }
#else
        if (called && i.op == Op::Other && i.other() == Other::TestReg && i.width() == 1 && !i.memory() && i.dst == 0 && i.src == 0) {
          const auto* branch = program.at(pc + i.length());
          if (branch && branch->insn.conditional()) joined =
            (branch->insn.condition() == 4 && branch->pc + branch->insn.length() == jump.target()) ||
            (branch->insn.condition() == 5 && branch->insn.target() == jump.target());
          break;
        }
#endif
        if (i.op == Op::Other && i.other() == Other::Call) called = true;
        else if (Writes(i, 0)) called = false;
        if (i.conditional()) break;
        if (i.op == Op::Other && i.other() == Other::Store) {
          int64_t offset = 0;
          if (sizeof(void*) != 4 || !program.stackAddress(pc, i.dst, offset, true) || offset + i.disp >= 0) break;
        }
        pc += i.length();
      }
      if (!joined) continue;
      Gate gate; gate.compare = n.pc; gate.rva = decision->pc; gate.function = range.begin;
      gate.unaffected = jump.target(); gate.affected = decision->pc + jump.length(); gate.fields = layout; gate.optional = InstallVerifier;
      if (!makePatch(pe, gate, false) || !candidates.push_back(gate)) { report.installVerifier = "too many provider candidates"; return; }
    }
  }
  report.installVerifier = candidates.empty() ? "no recognized provider gate" : candidates.size() == 1 ? "structurally verified provider gate" : "ambiguous provider gates";
  if (candidates.size() == 1) report.gates.push_back(candidates.front());
}

#if defined(AUTOSCAN_X86)
bool downloadFrame(const PeImage& pe, const Boundaries& boundaries, const Program& program,
                   uint32_t from, uint32_t to, int32_t slot) {
  auto cleanup = [&](auto&& self, uint32_t target, unsigned depth, int32_t& pop) -> bool {
    if (!target || depth == 4) return false;
    auto range = boundaries.find(target);
    if (!range || range.begin != target) return false;
    FixedList<uint32_t, 2048> todo, seen; todo.push_back(target); bool found = false;
    auto accept = [&](int32_t value) { if (found && value != pop) return false; found = true; pop = value; return true; };
    while (!todo.empty()) {
      auto pc = todo.back(); --todo.count;
      bool repeat = false; for (auto old : seen) repeat |= old == pc;
      if (repeat) continue;
      if (!seen.push_back(pc)) return false;
      if (!range.contains(pc)) {
        int32_t nested = 0;
        if (!self(self, pc, depth + 1, nested) || !accept(nested)) return false;
        continue;
      }
      auto i = Lift(pe.code(pc), pc);
      if (!i.length()) return false;
      if (i.op == Op::Ret) { if (!accept(i.imm)) return false; continue; }
      if (Terminal(i)) continue;
      if ((i.conditional() || i.op == Op::Jmp) && !todo.push_back(i.target())) return false;
      if (i.op != Op::Jmp && !todo.push_back(pc + i.length())) return false;
    }
    return found;
  };
  auto indirectPop = [&](const Node& call, int32_t& pop) {
    const auto& i = call.insn;
    auto config = pe.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    uint32_t guard = 0;
    constexpr uint32_t offset = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFCheckFunctionPointer);
    if (config.Size >= offset + 4 && pe.rvaRead(config.VirtualAddress + offset, guard) && guard &&
        i.memory() && static_cast<uint32_t>(i.disp) == guard) { pop = 0; return true; }
    const auto* next = program.at(call.pc + i.length());
    // Caller-cleaned callbacks use cdecl; other unresolved indirect calls decline.
    if (!i.memory() && next && next->insn.op == Op::AddImm && next->insn.dst == 4 && next->insn.imm > 0) { pop = 0; return true; }
    if (!i.memory() || static_cast<uint32_t>(i.disp) < pe.imageBase) return false;
    uint32_t slotRva = static_cast<uint32_t>(i.disp - pe.imageBase);
    auto imports = pe.directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    for (uint32_t at = 0; at + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= imports.Size; at += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
      IMAGE_IMPORT_DESCRIPTOR descriptor{};
      if (!pe.rvaRead(imports.VirtualAddress + at, descriptor) || !descriptor.Name) break;
      if (!descriptor.OriginalFirstThunk || slotRva < descriptor.FirstThunk || (slotRva - descriptor.FirstThunk) % 4) continue;
      uint32_t name = 0;
      if (!pe.rvaRead(descriptor.OriginalFirstThunk + slotRva - descriptor.FirstThunk, name) || (name & 0x80000000)) continue;
      auto text = pe.at(name + 2, 32); if (text.empty()) continue;
      auto end = std::find(text.begin(), text.end(), 0);
      std::string_view symbol(reinterpret_cast<const char*>(text.data()), end - text.begin());
      if (symbol == "GetModuleHandleW") { pop = 4; return true; }
      if (symbol == "GetProcAddress") { pop = 8; return true; }
    }
    return false;
  };
  std::array<bool, 8192> reaches{};
  FixedList<uint32_t, 8192> ancestors; ancestors.push_back(to);
  while (!ancestors.empty()) {
    auto pc = ancestors.back(); --ancestors.count;
    const auto* current = program.at(pc); if (!current) return false;
    size_t index = current - program.nodes.items.data();
    if (reaches[index]) continue;
    reaches[index] = true;
    if (pc == from) continue;
    for (const auto& n : program.nodes) if (program.follows(n, pc) && !ancestors.push_back(n.pc)) return false;
  }
  constexpr int32_t unknown = INT32_MIN;
  struct State { uint32_t pc; std::array<int32_t, 8> addresses; };
  State initial{from}; initial.addresses.fill(unknown); initial.addresses[4] = 0;
  FixedList<State, 256> todo; FixedList<State, 2048> seen; todo.push_back(initial); bool arrived = false;
  while (!todo.empty()) {
    auto state = todo.back(); --todo.count;
    if (state.pc == to) { if (state.addresses[4]) return false; arrived = true; continue; }
    const auto* node = program.at(state.pc); if (!node) return false;
    if (!reaches[node - program.nodes.items.data()]) continue;
    bool repeat = false; for (const auto& old : seen) repeat |= old.pc == state.pc && old.addresses == state.addresses;
    if (repeat) continue;
    if (!seen.push_back(state)) return false;
    const auto& i = node->insn;
    bool store = i.op == Op::Other && (i.other() == Other::Store || i.other() == Other::AtomicAdd);
    unsigned base = i.other() == Other::AtomicAdd ? i.src : i.dst;
    if (store && base < 8 && state.addresses[base] != unknown) {
      int64_t address = int64_t{state.addresses[base]} + i.disp;
      if (address < int64_t{slot} + 4 && address + StoreWidth(i) > slot) return false;
    }
    if (i.op == Op::Other && i.other() == Other::Call) {
      int32_t pop = 0;
      if (i.target() ? !cleanup(cleanup, i.target(), 0, pop) : !indirectPop(*node, pop)) return false;
      state.addresses[4] += pop;
      for (unsigned r = 0; r < 3; ++r) state.addresses[r] = unknown;
    } else if (i.op == Op::Other && (i.other() == Other::Push || i.other() == Other::Pop)) {
      if (i.other() == Other::Pop && i.dst == 4) return false;
      state.addresses[4] += i.other() == Other::Push ? -4 : 4;
      if (i.other() == Other::Pop && i.dst < 8) state.addresses[i.dst] = unknown;
      if (i.other() == Other::Push && state.addresses[4] < int64_t{slot} + 4 && int64_t{state.addresses[4]} + 4 > slot) return false;
    } else if ((i.op == Op::MovReg || i.op == Op::AddImm) && i.width() == 4 && i.dst < 8) {
      auto address = i.src < 8 ? state.addresses[i.src] : unknown;
      if (address != unknown && i.op == Op::AddImm) {
        int64_t sum = int64_t{address} + i.imm;
        if (sum < INT32_MIN + 1ll || sum > INT32_MAX) return false;
        address = static_cast<int32_t>(sum);
      }
      state.addresses[i.dst] = address;
    } else {
      if (Writes(i, 4)) return false;
      for (unsigned r = 0; r < 8; ++r) if (Writes(i, r)) state.addresses[r] = unknown;
    }
    if (state.addresses[4] == unknown || state.addresses[4] < -4096 || state.addresses[4] > 4096) return false;
    if (i.op == Op::Jmp || i.conditional()) { auto taken = state; taken.pc = i.target(); if (!todo.push_back(taken)) return false; }
    if (i.op != Op::Jmp && !Terminal(i)) { state.pc += i.length(); if (!todo.push_back(state)) return false; }
  }
  return arrived;
}
#endif

void crxDownload(const PeImage& pe, const Boundaries& boundaries, Program& program, Report& report) {
  auto data = pe.at(pe.rdata.rva, pe.rdata.size), code = pe.at(pe.text.rva, pe.text.size);
  constexpr char name[] = "apps-gallery-url";
  constexpr unsigned argumentReg = StackReg == 31 ? 0 : 1;
  uint32_t literal = 0, installer = 0; int32_t reasonOffset = 0;
  for (size_t n = 0; n + sizeof(name) <= data.size(); ++n) if (!memcmp(data.data() + n, name, sizeof(name))) {
    if (literal) { report.crxDownload = "ambiguous gallery switch"; return; }
    literal = pe.rdata.rva + static_cast<uint32_t>(n);
  }
  if (!literal) { report.crxDownload = "gallery switch absent"; return; }
  auto call = [](const Node* n) { return n && n->insn.op == Op::Other && n->insn.other() == Other::Call && n->insn.target(); };
  FixedList<uint32_t, 64> refs;
  if (!references(pe, literal, refs)) { report.crxDownload = "too many gallery references"; return; }
  for (auto pc : refs) {
    auto range = boundaries.find(pc);
    if (!range || range.end - range.begin > 1024 || !program.build(pe, range) || !program.at(pc)) continue;
    for (const auto& node : program.nodes) {
      const auto& cmp = node.insn;
      const auto* jump = program.at(node.pc + cmp.length());
      if (!jump || !jump->insn.conditional() || jump->insn.condition() != 4) continue;
#if defined(AUTOSCAN_ARM64)
      if (cmp.op != Op::LoadField || cmp.width() != 4 || cmp.disp <= 0 ||
          jump->insn.other() != Other::RegisterBranch || jump->insn.disp || jump->insn.src != cmp.dst ||
          !program.fromArgument(node.pc, cmp.src, argumentReg)) continue;
#else
      if (cmp.op != Op::CmpImm || !cmp.memory() || cmp.width() != 4 || cmp.imm || cmp.disp <= 0 ||
          !program.fromArgument(node.pc, cmp.dst, argumentReg)) continue;
#endif
      const auto* external = program.at(jump->pc + jump->insn.length());
      const auto* webstore = program.at(jump->insn.target());
      if (!call(external) || !call(webstore)) continue;
      uint32_t end = webstore->pc + webstore->insn.length();
      for (unsigned steps = 0; end < pc && steps < 3; ++steps) {
        const auto* move = program.at(end);
        if (!move || move->insn.op != Op::MovReg || move->insn.src != 0 || move->insn.dst != argumentReg) break;
        end += move->insn.length();
      }
      if (end != pc) continue;
      const auto* join = program.at(external->pc + external->insn.length());
      if (!join || join->insn.op != Op::Jmp || join->insn.target() <= pc || !range.contains(join->insn.target())) continue;
      auto zero = Lift(pe.code(external->insn.target()), external->insn.target());
      bool returnsZero = zero.width() == 4 && zero.dst == 0 &&
        ((zero.op == Op::Other && zero.other() == Other::XorReg && zero.src == 0) ||
         (zero.op == Op::MovReg && zero.src == NoReg && !zero.imm && !zero.detail));
      if (!returnsZero || Lift(pe.code(external->insn.target() + zero.length()), external->insn.target() + zero.length()).op != Op::Ret) continue;
      bool format = false;
      for (uint32_t at = join->insn.target(), steps = 0; steps < 8; ++steps) {
        const auto* next = program.at(at); if (!next) break;
        const auto& i = next->insn;
#if defined(AUTOSCAN_X86)
        format = i.op == Op::Other && i.other() == Other::Push && !i.memory() && i.dst == 0;
#else
        format = i.op == Op::MovReg && i.dst == (StackReg == 31 ? 2 : 8) && i.src == 0 && i.width() == 4;
#endif
        if (format) break;
        if (Terminal(i) || i.conditional() || i.op == Op::Jmp || call(next) || Writes(i, 0)) break;
        at += i.length();
      }
      if (!format) continue;
      if (installer && (installer != range.begin || reasonOffset != cmp.disp)) { report.crxDownload = "ambiguous CRX installers"; return; }
      installer = range.begin; reasonOffset = cmp.disp;
    }
  }
  if (!installer) { report.crxDownload = "no recognized CRX installer"; return; }
  FixedList<Gate, 2> candidates;
  // shortcut: only stack-held installers are recognized; extend with provenance tests for other compiler layouts.
  for (size_t n = 0; n + (StackReg == 31 ? 4 : 5) <= code.size(); n += StackReg == 31 ? 4 : 1) {
    if (StackReg == 31 ? (ReadInsn<uint32_t>(code.data() + n) & 0xfc000000) != 0x94000000 : code[n] != 0xe8) continue;
    uint32_t pc = pe.text.rva + static_cast<uint32_t>(n);
    if (Lift(pe.code(pc), pc).target() != installer) continue;
    auto range = boundaries.find(pc);
    if (!range || !program.build(pe, range) || !call(program.at(pc))) continue;
    const Node* argument = program.predecessor(pc);
    for (unsigned steps = 0; argument && steps < 4 && !Writes(argument->insn, argumentReg); ++steps) {
      bool push = sizeof(void*) == 4 && argument->insn.op == Op::Other && argument->insn.other() == Other::Push;
      if (call(argument) || argument->insn.conditional() || argument->insn.op == Op::Jmp || (!push && Writes(argument->insn, StackReg))) { argument = nullptr; break; }
      argument = program.predecessor(argument->pc);
    }
    if (!argument || argument->insn.op != Op::LoadField || argument->insn.dst != argumentReg ||
        argument->insn.src != StackReg || argument->insn.width() != sizeof(void*)) continue;
    for (const auto& node : program.nodes) {
      const auto& store = node.insn;
      if (node.pc >= argument->pc || store.op != Op::Other || store.other() != Other::Store || store.width() != 4 ||
          (store.detail & 0x400) || store.disp != reasonOffset) continue;
      auto value = store.src == NoReg ? SymVal::constant(static_cast<uint32_t>(store.imm)) : program.constantBefore(pe, node.pc, store.src);
      if (value.kind != SymKind::Const || value.value != 2) continue;
      const auto* load = program.predecessor(node.pc);
#if defined(AUTOSCAN_ARM64)
      if (!load || load->insn.op != Op::MovReg || load->insn.dst != store.src || load->insn.src != NoReg || load->insn.imm != 2) continue;
      load = program.predecessor(load->pc);
#endif
      if (!load || load->insn.op != Op::LoadField || load->insn.width() != sizeof(void*) || load->insn.dst != store.dst ||
          load->insn.src != StackReg || load->insn.disp != argument->insn.disp) continue;
      const auto* jump = program.predecessor(load->pc);
      if (!jump || !jump->insn.conditional() || jump->insn.condition() != 4 || jump->insn.target() != node.pc + store.length()) continue;
      const auto* test = jump;
#if defined(AUTOSCAN_ARM64)
      if (jump->insn.other() != Other::RegisterBranch || jump->insn.src != 0 || jump->insn.disp != 1 || jump->insn.width() != 4 ||
          !call(program.predecessor(jump->pc))) continue;
#else
      test = program.predecessor(jump->pc);
      if (!test || test->insn.op != Op::Other || test->insn.other() != Other::TestReg || test->insn.memory() ||
          test->insn.width() != 1 || test->insn.dst != 0 || test->insn.src != 0) continue;
      const auto* before = program.predecessor(test->pc);
      if (sizeof(void*) == 4 && before && before->insn.op == Op::AddImm && before->insn.dst == StackReg && before->insn.imm > 0)
        before = program.predecessor(before->pc);
      if (!call(before)) continue;
#endif
#if defined(AUTOSCAN_X86)
      bool stable = downloadFrame(pe, boundaries, program, node.pc + store.length(), argument->pc, argument->insn.disp);
#else
      bool stable = true;
      for (const auto& between : program.nodes) if (between.pc > node.pc && between.pc < pc) {
        const auto& i = between.insn;
        int64_t address = 0;
        bool stackStore = i.op == Op::Other && (i.other() == Other::Store || i.other() == Other::AtomicAdd) &&
          program.stackAddress(between.pc, i.other() == Other::Store ? i.dst : i.src, address);
        address += i.disp;
        if (Writes(i, StackReg) || (stackStore && address < int64_t{argument->insn.disp} + sizeof(void*) &&
            address + StoreWidth(i) > argument->insn.disp)) stable = false;
      }
#endif
      if (!stable) continue;
      // Select ShouldOpenDownload's existing allow-reason store; verification and confirmation still run.
      Gate gate; gate.compare = test->pc; gate.rva = jump->pc; gate.function = range.begin;
      gate.affected = jump->insn.target(); gate.unaffected = load->pc; gate.optional = CrxDownload;
      if (!makePatch(pe, gate, true) || !candidates.push_back(gate)) { report.crxDownload = "ambiguous CRX download gates"; return; }
    }
  }
  report.crxDownload = candidates.size() == 1 ? "structurally verified CRX download gate" : "missing or ambiguous CRX download gate";
  if (candidates.size() == 1) report.gates.push_back(candidates.front());
}
} // namespace

ImageInfo Inspect(std::span<const uint8_t> bytes) {
  PeImage pe(bytes);
  if (!pe.valid() || pe.machine != NativeMachine()) return {};
  return {pe.text.rva, pe.text.raw, pe.text.size, pe.imageSize};
}
HashValue Hash(std::span<const uint8_t> bytes) {
  HashValue result{}; std::array<uint8_t, 32> digest{};
  alignas(void*) std::array<uint8_t, 512> object{};
  DWORD required = 0, received = 0; BCRYPT_HASH_HANDLE hash = nullptr;
  if (bytes.size() > ULONG_MAX ||
      BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&required),
                        sizeof(required), &received, 0) < 0 || required > object.size() ||
      BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash, object.data(), required, nullptr, 0, 0) < 0) return result;
  bool ok = BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) >= 0 &&
            BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
  BCryptDestroyHash(hash);
  if (ok) {
    constexpr char hex[] = "0123456789abcdef";
    for (size_t n = 0; n < digest.size(); ++n) { result[n * 2] = hex[digest[n] >> 4]; result[n * 2 + 1] = hex[digest[n] & 15]; }
  }
  return result;
}
Report Analyze(std::span<const uint8_t> bytes) {
  Report report; PeImage pe(bytes);
  if (!pe.valid()) { report.error = pe.error; return report; }
  if (pe.machine != NativeMachine()) { report.error = "scanner architecture differs from PE machine"; return report; }
  Boundaries boundaries(pe);
  if (boundaries.error) { report.error = boundaries.error; return report; }
  Program program;
  auto issue = [&](uint32_t pc, std::string_view reason) {
    if (!report.unresolved.push_back({pc, reason})) report.error = "too many unresolved candidates";
  };
  auto consider = [&](uint32_t jumpPc) {
    auto jump = Lift(pe.code(jumpPc), jumpPc);
    if (jump.op != Op::JccSigned) return;
    ++report.heads;
    FixedList<std::pair<Head, Range>, 16> variants;
#if defined(AUTOSCAN_ARM64)
    uint32_t lower = jumpPc >= pe.text.rva + 4 ? jumpPc - 4 : pe.text.rva;
    constexpr unsigned step = 4;
#else
    uint32_t lower = jumpPc - pe.text.rva > 15 ? jumpPc - 15 : pe.text.rva;
    constexpr unsigned step = 1;
#endif
    bool plausible = false;
    for (uint32_t cp = lower; cp < jumpPc; cp += step) {
      auto cmp = Lift(pe.code(cp), cp);
      if (cp + cmp.length() != jumpPc || !threshold(cmp, jump)) continue;
      auto bounds = boundaries.find(cp); if (!bounds) continue;
      bool inverted = jump.condition() == 12 || jump.condition() == 14;
      Head head{cp, jumpPc, inverted ? jump.target() : jumpPc + jump.length(),
                inverted ? jumpPc + jump.length() : jump.target(), inverted};
      if (!prefilter(pe, head, bounds)) continue;
      plausible = true;
      if (program.range.begin != bounds.begin || program.range.end != bounds.end) program.build(pe, bounds);
      if (program.complete && program.at(cp) && program.at(jumpPc)) variants.push_back({head, bounds});
    }
    if (!plausible) { ++report.rejected; return; }
    ++report.screened;
    if (variants.size() != 1) { issue(jumpPc, "missing or ambiguous instruction boundary"); return; }
    auto [head, bounds] = variants.front();
    if (program.range.begin != bounds.begin || program.range.end != bounds.end) program.build(pe, bounds);
    Gate gate; std::string_view reason;
    Evaluator evaluator(pe, program, head);
    if (evaluator.verify(gate, reason) && makePatch(pe, gate, head.inverted)) {
      if (!report.gates.push_back(gate)) report.error = "too many gates for the bounded runtime plan";
    } else issue(jumpPc, reason.empty() ? "unsupported predicate" : reason);
  };
  auto text = pe.at(pe.text.rva, pe.text.size);
#if defined(AUTOSCAN_ARM64)
  for (size_t p = 0; p + 8 <= text.size(); p += 4) {
    auto cmp = Lift(text.subspan(p), pe.text.rva + static_cast<uint32_t>(p));
    if (cmp.op == Op::CmpImm && (cmp.imm == 2 || cmp.imm == 3)) consider(pe.text.rva + static_cast<uint32_t>(p) + 4);
  }
#else
  for (size_t p = 0; p < text.size(); ++p) if (text[p] == 2 || text[p] == 3) {
    auto probe = [&](size_t n) {
      if (n + 1 < text.size() && ((text[n] >= 0x7c && text[n] <= 0x7f) ||
          (text[n] == 0x0f && text[n + 1] >= 0x8c && text[n + 1] <= 0x8f)))
        consider(pe.text.rva + static_cast<uint32_t>(n));
    };
    probe(p + 1);
    if (p + 4 < text.size() && !text[p + 1] && !text[p + 2] && !text[p + 3]) probe(p + 4);
  }
#endif
  std::sort(report.gates.begin(), report.gates.end(), [](const Gate& a, const Gate& b) { return a.rva < b.rva; });
  bool free = false, hasLayout = false, coherent = true;
  std::array<int64_t, 5> layout{}; FixedList<uint32_t, 64> paired;
  for (const auto& gate : report.gates) {
    free |= gate.freePredicate;
    if (!gate.freePredicate) {
      if (hasLayout && layout != gate.fields) coherent = false;
      layout = gate.fields; hasLayout = true;
    }
    for (const auto& other : report.gates) if (other.function == gate.function && other.affected == gate.affected &&
        other.unaffected == gate.unaffected && other.kind != gate.kind) {
      bool found = false; for (auto function : paired) found |= function == gate.function;
      if (!found) paired.push_back(gate.function);
    }
  }
  if (report.error.empty() && (!hasLayout || !coherent || (!free && paired.size() < 2)))
    report.error = "need one coherent member layout and a free predicate or independent paired diagnostic bodies";
  report.installVerifier = "optional provider not recognized by the bounded lifter";
  report.crxDownload = "optional CRX downloads not recognized by the bounded lifter";
  if (report.ready() && report.gates.size() < 64) {
    installVerifier(pe, boundaries, program, layout, report);
    if (report.gates.size() < 64) crxDownload(pe, boundaries, program, report);
    std::sort(report.gates.begin(), report.gates.end(), [](const Gate& a, const Gate& b) { return a.rva < b.rva; });
  }
  return report;
}
Report Discover(std::span<const uint8_t> bytes) {
  auto hash = Hash(bytes); Report report;
  if (!hash[0]) { report.error = "SHA-256 failed"; return report; }
  report = Analyze(bytes); report.sha256 = hash; return report;
}
} // namespace autoscan
