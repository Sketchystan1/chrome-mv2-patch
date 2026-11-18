// Read the browser DLL, recognize supported extension decisions, and propose replacement bytes; this file does not write them.
#include "solver.hpp"
#include <bcrypt.h>
#include "blake3.h"
#include <bit>
#if defined(AUTOSCAN_X64) || defined(AUTOSCAN_X86)
#include <emmintrin.h>
#endif

namespace autoscan {
namespace {
bool prefilter(const PeImage& pe, Head head, Range range, bool* complete = nullptr) {
  // Quickly discard unrelated comparisons; surviving matches still need the full proof below.
  if (complete) *complete = true;
  FixedList<uint32_t, 256> todo, seen;
  todo.push_back(head.affected); unsigned constants = 0; bool bit = false;
  while (!todo.empty()) {
    auto pc = todo.back(); --todo.count;
    if (!range.contains(pc) || pc == head.unaffected) continue;
    bool repeat = false; for (auto p : seen) repeat |= p == pc;
    if (repeat) continue;
    if (!seen.push_back(pc)) { if (complete) *complete = false; return false; }
    auto i = Lift(pe.at(pc, range.end - pc), pc);
    if (!i.length()) { if (complete) *complete = false; continue; }
    if (Terminal(i) || (i.op == Op::Other && (i.other() == Other::Call || i.other() == Other::Store))) continue;
    if (i.width() == 4 && (i.op == Op::CmpImm || (i.op == Op::Other && i.other() == Other::ConditionalCompare)))
      constants |= i.imm == 1 ? 1 : i.imm == 3 ? 2 : i.imm == 8 ? 4 : i.imm == 5 ? 8 : i.imm == 10 ? 16 : 0;
    bit |= i.op == Op::Other && (i.other() == Other::BitTest || i.other() == Other::ShiftRight);
    if ((i.op == Op::Jmp || i.conditional()) && !todo.push_back(i.target())) { if (complete) *complete = false; return false; }
    if (i.op != Op::Jmp && !todo.push_back(pc + i.length())) { if (complete) *complete = false; return false; }
  }
  return (constants & 28) == 28 && (bit || (constants & 3) == 3);
}
bool makePatch(const PeImage& pe, Gate& gate, bool inverted) {
  // Describe a change to the browser's existing branch, keeping its original bytes for validation and rollback.
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
#if !defined(AUTOSCAN_ARM64)
bool cmpStart(uint8_t byte) {
  return byte == 0x81 || byte == 0x83 || byte == 0x3d || byte == 0x67
#if defined(AUTOSCAN_X64)
    || (byte >= 0x40 && byte <= 0x4f)
#endif
    ;
}
#endif
struct RefQuery { uint32_t literal = 0; FixedList<uint32_t, 64> found; bool complete = true; };
struct RefBatch {
  FixedList<RefQuery, 17> queries;
  unsigned providerCount = 0;
  uint32_t gallery = 0;
  bool providerAmbiguous = false, galleryAmbiguous = false, scanned = false;
  explicit RefBatch(const PeImage& pe) {
    // These browser names are search clues in the DLL; searching for "apps-gallery-url" makes no network request.
    auto data = pe.at(pe.rdata.rva, pe.rdata.size);
    std::string_view hay(reinterpret_cast<const char*>(data.data()), data.size());
    for (auto name : {std::string_view("InstallVerifier"), std::string_view("apps-gallery-url")}) {
      bool provider = name[0] == 'I', ambiguous = false;
      unsigned count = 0, limit = provider ? 16 : 1;
      size_t begin = queries.size();
      size_t anchor = provider ? 0 : 4; // The gallery hyphen has fewer false matches than its initial 'a'.
      for (size_t at = hay.find(name[anchor], anchor); at != std::string_view::npos; at = hay.find(name[anchor], at + 1)) {
        size_t n = at - anchor;
        if ((n && data[n - 1]) || name.size() + 1 > data.size() - n || memcmp(data.data() + n, name.data(), name.size()) || data[n + name.size()]) continue;
        RefQuery query; query.literal = pe.rdata.rva + static_cast<uint32_t>(n);
        if (++count > limit || !queries.push_back(query)) { ambiguous = true; queries.count = begin; break; }
      }
      if (provider) { providerAmbiguous = ambiguous; providerCount = ambiguous ? 0 : count; }
      else { galleryAmbiguous = ambiguous; if (!ambiguous && count) gallery = queries.back().literal; }
    }
  }
};
void scanReferences(const PeImage& pe, std::span<RefQuery> queries) {
  auto code = pe.at(pe.text.rva, pe.text.size);
#if defined(AUTOSCAN_ARM64)
  for (size_t n = 0; n + 8 <= code.size(); n += 4) {
    uint32_t word = ReadInsn<uint32_t>(code.data() + n), next = ReadInsn<uint32_t>(code.data() + n + 4);
    if ((word & 0x9f000000) != 0x90000000 || (next & 0xffc00000) != 0x91000000 ||
        (next & 31) != (word & 31) || ((next >> 5) & 31) != (word & 31)) continue;
    int32_t pages = static_cast<int32_t>((((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3)) << 11) >> 11;
    uint32_t pc = pe.text.rva + static_cast<uint32_t>(n);
    int64_t target = static_cast<int64_t>(pc & ~0xfffu) + int64_t{pages} * 4096 + ((next >> 10) & 0xfff);
    for (auto& query : queries) if (query.complete && target == query.literal && !query.found.push_back(pc)) query.complete = false;
  }
#else
  auto examine = [&](size_t n) {
#if defined(AUTOSCAN_X64)
    if ((code[n - 1] & 0xc7) != 5) return;
    uint8_t op = code[n - 2];
    if (op != 0x8d && !(n >= 3 && code[n - 3] == 0x0f &&
        (op == 0x10 || op == 0x11 || op == 0x28 || op == 0x29 || op == 0x6f || op == 0x7f))) return;
    int64_t end = static_cast<int64_t>(pe.text.rva) + n + 4;
    int64_t target = end + ReadInsn<int32_t>(code.data() + n);
#else
    int64_t target = int64_t{ReadInsn<uint32_t>(code.data() + n)} - static_cast<int64_t>(pe.imageBase);
    int64_t end = static_cast<int64_t>(pe.text.rva) + n + 4;
#endif
    RefQuery* matching = nullptr;
    for (auto& query : queries) if (query.complete && query.literal == target) { matching = &query; break; }
    if (!matching) return;
    auto& found = matching->found;
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
      if (!found.push_back(pc)) { matching->complete = false; break; }
    }
  };
  size_t n = 2;
#if defined(AUTOSCAN_X86)
  if (queries.size() <= 17) {
    FixedList<uint16_t, 17> pairs;
    for (const auto& query : queries) {
      uint64_t absolute = pe.imageBase + query.literal;
      if (absolute > UINT32_MAX) continue;
      uint16_t pair = static_cast<uint16_t>(absolute >> 16); bool present = false;
      for (auto existing : pairs) present |= existing == pair;
      if (!present) pairs.push_back(pair);
    }
    for (; n + 19 <= code.size(); n += 16) {
      auto lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(code.data() + n + 2));
      auto hi = _mm_loadu_si128(reinterpret_cast<const __m128i*>(code.data() + n + 3));
      auto matches = _mm_setzero_si128();
      for (auto pair : pairs) matches = _mm_or_si128(matches, _mm_and_si128(
        _mm_cmpeq_epi8(lo, _mm_set1_epi8(static_cast<char>(pair & 255))),
        _mm_cmpeq_epi8(hi, _mm_set1_epi8(static_cast<char>(pair >> 8)))));
      unsigned mask = static_cast<unsigned>(_mm_movemask_epi8(matches));
      while (mask) { examine(n + std::countr_zero(mask)); mask &= mask - 1; }
    }
  }
#endif
#if defined(AUTOSCAN_X64)
  for (; n + 19 <= code.size(); n += 16) {
    auto bytes = _mm_loadu_si128(reinterpret_cast<const __m128i*>(code.data() + n - 1));
    auto matches = _mm_cmpeq_epi8(_mm_and_si128(bytes, _mm_set1_epi8(-57)), _mm_set1_epi8(5));
    auto ops = _mm_loadu_si128(reinterpret_cast<const __m128i*>(code.data() + n - 2));
    auto paired = _mm_and_si128(ops, _mm_set1_epi8(-2));
    auto opMatch = _mm_or_si128(_mm_cmpeq_epi8(paired, _mm_set1_epi8(0x10)), _mm_cmpeq_epi8(paired, _mm_set1_epi8(0x28)));
    opMatch = _mm_or_si128(opMatch, _mm_cmpeq_epi8(_mm_and_si128(ops, _mm_set1_epi8(static_cast<char>(0xef))), _mm_set1_epi8(0x6f)));
    opMatch = _mm_or_si128(opMatch, _mm_cmpeq_epi8(ops, _mm_set1_epi8(static_cast<char>(0x8d))));
    matches = _mm_and_si128(matches, opMatch);
    unsigned mask = static_cast<unsigned>(_mm_movemask_epi8(matches));
    while (mask) { examine(n + std::countr_zero(mask)); mask &= mask - 1; }
  }
#endif
  for (; n + 4 <= code.size(); ++n) examine(n);
#endif
}
bool references(const PeImage& pe, uint32_t literal, FixedList<uint32_t, 64>& found, RefBatch& batch) {
  if (!batch.scanned) { batch.scanned = true; scanReferences(pe, {batch.queries.items.data(), batch.queries.size()}); }
  for (const auto& query : batch.queries) if (query.literal == literal) { found = query.found; return query.complete; }
  RefQuery query; query.literal = literal; scanReferences(pe, {&query, 1}); found = query.found; return query.complete;
}

#if defined(AUTOSCAN_X64)
bool providerProgram(const PeImage& pe, const Boundaries& boundaries, Program& program, Range range) {
  if (!program.build(pe, range)) return false;
  if (!pe.isEdge()) return true;
  // shortcut: merge forward x64 cold blocks only; extend with ownership tests if Edge moves them before the provider.
  for (unsigned pass = 0; pass < 4; ++pass) {
    FixedList<uint32_t, 16> entries;
    for (const auto& n : program.nodes) {
      const auto& i = n.insn;
      if ((i.op != Op::Jmp && !i.conditional()) || program.at(i.target()) || !boundaries.chainedTo(i.target(), range.begin)) continue;
      bool seen = false; for (auto pc : entries) seen |= pc == i.target();
      if (!seen && !entries.push_back(i.target())) return false;
    }
    if (entries.empty()) return true;
    for (auto pc : entries) {
      auto body = boundaries.find(pc, true);
      Program cold;
      if (pc < range.begin || !cold.build(pe, {pc, body.end})) return false;
      for (const auto& n : cold.nodes) {
        bool present = false;
        for (const auto& old : program.nodes) if (n.pc < old.pc + old.insn.length() && old.pc < n.pc + n.insn.length()) {
          if (n.pc != old.pc || n.insn.length() != old.insn.length()) return false;
          present = true;
        }
        if (!present && !program.nodes.push_back(n)) return false;
      }
      for (auto call : cold.noReturns) if (!program.noReturns.push_back(call)) return false;
      program.range.end = std::max(program.range.end, body.end);
    }
    std::sort(program.nodes.begin(), program.nodes.end(), [](const Node& a, const Node& b) { return a.pc < b.pc; });
  }
  return false;
}
bool trueReturn(const PeImage& pe, const Boundaries& boundaries, uint32_t pc, uint32_t function) {
  if (!boundaries.chainedTo(pc, function)) return false;
  auto i = Lift(pe.code(pc), pc);
  if (i.op != Op::MovReg || i.dst != 0 || i.src != NoReg || i.imm != 1 || i.detail || (i.width() != 1 && i.width() != 4)) return false;
  for (unsigned steps = 0; steps < 8; ++steps) {
    pc += i.length(); i = Lift(pe.code(pc), pc);
    if (!i.length() || !boundaries.chainedTo(pc, function)) return false;
    if (i.op == Op::Ret) return true;
    if ((i.op != Op::AddImm || i.dst != StackReg || i.src != StackReg || i.imm <= 0) &&
        (i.op != Op::Other || i.other() != Other::Pop || i.dst == StackReg || i.dst == 0)) return false;
  }
  return false;
}
#endif

#if defined(AUTOSCAN_X86)
bool providerStackArgument(const PeImage& pe, const Program& program, uint32_t pc, unsigned reg) {
  // DCHECK providers reload their Extension* parameter after calls. Require a
  // fixed EBP frame, an exact input-slot load, and untouched/unexposed inputs on
  // every incoming path; arbitrary writes and hidden frame aliases still decline.
  const auto* load = program.predecessor(pc);
  const auto* push = program.at(program.range.begin);
  const auto* frame = push ? program.at(push->pc + push->insn.length()) : nullptr;
  int64_t address = 0;
  if (!load || load->insn.op != Op::LoadField || load->insn.width() != 4 || load->insn.dst != reg || load->insn.src != 5 ||
      !push || push->insn.op != Op::Other || push->insn.other() != Other::Push || push->insn.dst != 5 ||
      !frame || frame->insn.op != Op::MovReg || frame->insn.dst != 5 || frame->insn.src != StackReg || frame->insn.width() != 4 ||
      !program.stackAddress(load->pc, 5, address, true) || address + load->insn.disp != 4) return false;
  uint32_t cookie = 0;
  const auto& config = pe.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
  constexpr uint32_t cookieOffset = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie);
  if (config.Size >= cookieOffset + 4) pe.rvaRead(config.VirtualAddress + cookieOffset, cookie);
  FixedList<uint32_t, 512> todo, seen; todo.push_back(load->pc); bool entry = false;
  while (!todo.empty()) {
    auto at = todo.back(); --todo.count;
    if (at == program.range.begin) { entry = true; continue; }
    bool repeat = false; for (auto old : seen) repeat |= old == at;
    if (repeat) continue;
    if (!seen.push_back(at)) return false;
    bool previous = false;
    for (const auto& node : program.nodes) if (program.follows(node, at)) {
      previous = true; const auto& i = node.insn;
      if (i.op == Op::Other && (i.other() == Other::Unknown || (i.other() == Other::Overwrite && i.memory()))) return false;
      if ((i.op == Op::MovReg || i.op == Op::AddImm) && i.dst != StackReg &&
          program.stackAddress(node.pc, i.src, address, true)) {
        address += i.op == Op::AddImm ? i.imm : 0;
        if (node.pc != frame->pc && (i.width() != 4 || address >= -4)) return false;
      }
      if (i.op == Op::Other && i.other() == Other::Push && !i.memory() &&
          program.stackAddress(node.pc, i.dst, address, true) && address >= -4) return false;
      bool store = i.op == Op::Other && (i.other() == Other::Store || (i.memory() &&
        (i.other() == Other::AtomicAdd || i.other() == Other::AndReg || i.other() == Other::OrReg ||
         i.other() == Other::XorReg || i.other() == Other::AndImm || i.other() == Other::OrImm)));
      if (store) {
        unsigned base = i.other() == Other::AtomicAdd ? i.src : i.dst;
        if (base == NoReg) {
          if (static_cast<uint32_t>(i.disp) < pe.imageBase || pe.at(static_cast<uint32_t>(i.disp - pe.imageBase), StoreWidth(i)).empty()) return false;
        } else if (!program.stackAddress(node.pc, base, address, true) || address + i.disp + StoreWidth(i) > -4) return false;
        if (i.src < 32 && program.stackAddress(node.pc, i.src, address, true) && address >= -4) return false;
      }
      if (i.op == Op::Other && !i.memory() &&
          (i.other() == Other::AndReg || i.other() == Other::OrReg || i.other() == Other::XorReg ||
           i.other() == Other::AndImm || i.other() == Other::OrImm || i.other() == Other::Cmov) &&
          (program.stackAddress(node.pc, i.dst, address, true) || program.stackAddress(node.pc, i.src, address, true))) {
        // A compiler security-cookie XOR is scalar data, not an escaped frame.
        const auto* before = program.predecessor(node.pc);
        const auto* after = program.at(node.pc + i.length());
        if (i.other() != Other::XorReg || i.src != 5 || !cookie || !before || before->insn.op != Op::LoadField ||
            before->insn.src != NoReg || before->insn.dst != i.dst || before->insn.width() != 4 ||
            static_cast<uint32_t>(before->insn.disp) != cookie || !after || after->insn.op != Op::Other ||
            after->insn.other() != Other::Store || after->insn.dst != 5 || after->insn.src != i.dst ||
            after->insn.width() != 4 || after->insn.disp >= 0) return false;
      }
      if (!todo.push_back(node.pc)) return false;
    }
    if (!previous) return false;
  }
  return entry;
}
#endif

void installVerifier(const PeImage& pe, const Boundaries& boundaries, Program& program, const std::array<int64_t, 5>& layout, Report& report, RefBatch& batch) {
  // Find the optional decision that keeps off-store extensions disabled; ambiguous matches are left out of the plan.
  auto data = pe.at(pe.rdata.rva, pe.rdata.size), code = pe.at(pe.text.rva, pe.text.size);
  FixedList<uint32_t, 16> literals, getters;
  auto unique = [](auto& list, uint32_t value) {
    for (auto n : list) if (n == value) return true;
    return list.push_back(value);
  };
  if (batch.providerAmbiguous) { report.installVerifier = "ambiguous provider name"; return; }
  for (unsigned n = 0; n < batch.providerCount; ++n) literals.push_back(batch.queries[n].literal);
  if (literals.empty()) { report.installVerifier = "provider name absent"; return; }
  for (auto literal : literals) {
    FixedList<uint32_t, 64> refs;
    if (!references(pe, literal, refs, batch)) { report.installVerifier = "too many provider references"; return; }
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
  struct ProviderCall { uint32_t target; Gate gate; };
  FixedList<ProviderCall, 16> helpers;
  for (auto start : methods) {
    auto range = boundaries.find(start);
    if (!range) continue;
#if defined(AUTOSCAN_X64)
    if (!providerProgram(pe, boundaries, program, range)) continue;
#else
    if (!program.build(pe, range)) continue;
#endif
    bool reason = false;
    for (const auto& n : program.nodes) {
      const auto& i = n.insn;
      if (i.op != Op::Other || i.other() != Other::Store || i.width() != 4 || (i.detail & 0x400)) continue;
      auto value = i.src == NoReg ? SymVal::constant(static_cast<uint32_t>(i.imm)) : program.constantBefore(pe, n.pc, i.src);
      reason |= value.kind == SymKind::Const && value.value == 0x100 &&
        (!pe.isEdge() || program.fromArgument(n.pc, i.dst, 8));
    }
    if (!reason) continue;
#if defined(AUTOSCAN_X64)
    if (pe.isEdge()) for (const auto& n : program.nodes) {
      const auto& call = n.insn;
      if (call.op != Op::Other || call.other() != Other::Call || !call.target() || !program.fromArgument(n.pc, 1, 2)) continue;
      const auto* test = program.at(n.pc + call.length());
      const auto* jump = test ? program.at(test->pc + test->insn.length()) : nullptr;
      if (!test || test->insn.op != Op::Other || test->insn.other() != Other::TestReg || test->insn.memory() ||
          test->insn.width() != 1 || test->insn.dst != 0 || test->insn.src != 0 || !jump || !jump->insn.conditional() ||
          (jump->insn.condition() != 4 && jump->insn.condition() != 5)) continue;
      bool zero = jump->insn.condition() == 4;
      Gate gate; gate.compare = test->pc; gate.rva = jump->pc; gate.function = range.begin;
      gate.affected = zero ? jump->insn.target() : jump->pc + jump->insn.length();
      gate.unaffected = zero ? jump->pc + jump->insn.length() : jump->insn.target(); gate.optional = InstallVerifier;
      bool seen = false; for (const auto& old : helpers) seen |= old.gate.rva == gate.rva;
      if (!seen && (!makePatch(pe, gate, zero) || !helpers.push_back({call.target(), gate}))) { report.installVerifier = "too many provider helpers"; return; }
    }
#endif
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
      if (!program.fromArgument(n.pc, test.dst, NoReg, 4) && !providerStackArgument(pe, program, n.pc, test.dst)) continue;
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
#if defined(AUTOSCAN_X64)
  // Reuse the caller's Program for helpers to keep analysis within its bounded stack reserve.
  for (const auto& helper : helpers) {
    auto body = boundaries.find(helper.target);
    if (!body || body.begin != helper.target || body.end - body.begin > 256 || !program.build(pe, body)) continue;
    for (const auto& node : program.nodes) {
      const auto& test = node.insn;
      const auto* jump = program.at(node.pc + test.length());
      if (test.op != Op::Other || test.other() != Other::TestImm || !test.memory() || test.width() != 1 || test.imm != 8 ||
          !program.fromArgument(node.pc, test.dst, 1) || !jump || !jump->insn.conditional() || jump->insn.condition() != 5 ||
          !trueReturn(pe, boundaries, jump->insn.target(), body.begin)) continue;
      // Change only the "must remain disabled" decision; the shared store check also controls content verification.
      bool seen = false; for (const auto& old : candidates) seen |= old.rva == helper.gate.rva;
      if (!seen && !candidates.push_back(helper.gate)) { report.installVerifier = "too many provider candidates"; return; }
    }
  }
#endif
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
    // Larger helpers still need a complete, bounded walk of every returning path.
    FixedList<uint32_t, 4096> todo, seen; todo.push_back(target); bool found = false;
    auto accept = [&](int32_t value) { if (found && value != pop) return false; found = true; pop = value; return true; };
    while (!todo.empty()) {
      auto pc = todo.back(); --todo.count;
      bool repeat = false; for (auto old : seen) repeat |= old == pc;
      if (repeat) continue;
      if (!seen.push_back(pc)) return false;
      if (!range.contains(pc)) {
        // Function trimming can stop just before the security-cookie failure
        // path's terminal INT3. It cannot return or change a returning path's
        // cleanup; other out-of-range destinations still need bounded entries.
        auto terminal = Lift(pe.code(pc), pc);
        if (pc == range.end && terminal.op == Op::Other && terminal.other() == Other::Trap) continue;
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
    // Accept this callback only when its caller visibly cleans up the arguments; otherwise its effect is unknown.
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
    // Unmodeled arithmetic may retain a stack alias (for example, a zero
    // shift). Reject it before forgetting an address needed for the slot proof.
    if (i.op == Op::Other && i.other() == Other::Overwrite && i.setsFlags() &&
        ((i.dst < 8 && state.addresses[i.dst] != unknown) ||
         (!i.memory() && i.src < 8 && state.addresses[i.src] != unknown))) return false;
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

bool externalVerifierZero(const PeImage& pe, const Boundaries& boundaries, uint32_t start) {
  // The external verifier's format is zero. Recognize its complete leaf return;
  // x86 DCHECK builds retain a fixed frame even for this constant helper.
  uint32_t pc = start;
  bool framed = false;
#if defined(AUTOSCAN_X86)
  auto push = Lift(pe.code(pc), pc);
  if (push.op == Op::Other && push.other() == Other::Push && push.dst == 5 && !push.memory() && push.width() == 4) {
    auto frame = Lift(pe.code(pc + push.length()), pc + push.length());
    auto range = boundaries.find(start);
    if (!range || range.begin != start || frame.op != Op::MovReg || frame.dst != 5 || frame.src != StackReg || frame.width() != 4) return false;
    pc += push.length() + frame.length(); framed = true;
  }
#endif
  auto zero = Lift(pe.code(pc), pc);
  if (zero.width() != 4 || zero.dst != 0 ||
      !((zero.op == Op::Other && zero.other() == Other::XorReg && zero.src == 0) ||
        (zero.op == Op::MovReg && zero.src == NoReg && !zero.imm && !zero.detail))) return false;
  pc += zero.length();
  if (framed) {
    auto pop = Lift(pe.code(pc), pc);
    if (pop.op != Op::Other || pop.other() != Other::Pop || pop.dst != 5 || pop.width() != 4) return false;
    pc += pop.length();
  }
  auto ret = Lift(pe.code(pc), pc);
  return ret.op == Op::Ret && (!framed || !ret.imm);
}

void crxDownload(const PeImage& pe, const Boundaries& boundaries, Program& program, Report& report, RefBatch& batch) {
  // Recognize the optional CRX extension-package download decision without changing package verification or confirmation.
  auto data = pe.at(pe.rdata.rva, pe.rdata.size), code = pe.at(pe.text.rva, pe.text.size);
  constexpr unsigned argumentReg = StackReg == 31 ? 0 : 1;
  uint32_t literal = 0, installer = 0; int32_t reasonOffset = 0;
  if (batch.galleryAmbiguous) { report.crxDownload = "ambiguous gallery switch"; return; }
  literal = batch.gallery;
  if (!literal) { report.crxDownload = "gallery switch absent"; return; }
  auto call = [](const Node* n) { return n && n->insn.op == Op::Other && n->insn.other() == Other::Call && n->insn.target(); };
  FixedList<uint32_t, 64> refs;
  if (!references(pe, literal, refs, batch)) { report.crxDownload = "too many gallery references"; return; }
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
      if (!externalVerifierZero(pe, boundaries, external->insn.target())) continue;
      bool format = false;
      for (uint32_t at = join->insn.target(), steps = 0; steps < 24; ++steps) {
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
    if constexpr (StackReg != 31) {
      auto found = static_cast<const uint8_t*>(memchr(code.data() + n, 0xe8, code.size() - n - 4));
      if (!found) break;
      n = static_cast<size_t>(found - code.data());
    }
    if (StackReg == 31 ? (ReadInsn<uint32_t>(code.data() + n) & 0xfc000000) != 0x94000000 : code[n] != 0xe8) continue;
    uint32_t pc = pe.text.rva + static_cast<uint32_t>(n);
    if constexpr (StackReg != 31) {
      uint32_t target = 0;
      if (!RelativeTarget(pc, 5, ReadInsn<int32_t>(code.data() + n + 1), target) || target != installer) continue;
    }
    if (Lift(pe.code(pc), pc).target() != installer) continue;
    auto range = boundaries.find(pc);
    if (!range || !program.build(pe, range) || !call(program.at(pc))) continue;
    const Node* argument = program.predecessor(pc);
    unsigned installerReg = argumentReg;
#if defined(AUTOSCAN_X64)
    for (unsigned steps = 0; argument && steps < 64; ++steps) {
      const auto& i = argument->insn;
      if (i.op == Op::LoadField && i.dst == installerReg) break;
      if (i.conditional() || i.op == Op::Jmp || Writes(i, StackReg) ||
          (i.op == Op::Other && i.other() == Other::Call && VolatileReg(installerReg))) { argument = nullptr; break; }
      if (Writes(i, installerReg)) {
        if (i.op != Op::MovReg || i.width() != sizeof(void*) || i.src >= 16) { argument = nullptr; break; }
        installerReg = i.src;
      }
      argument = program.predecessor(argument->pc);
    }
#else
    for (unsigned steps = 0; argument && steps < 4 && !Writes(argument->insn, argumentReg); ++steps) {
      bool push = sizeof(void*) == 4 && argument->insn.op == Op::Other && argument->insn.other() == Other::Push;
      if (call(argument) || argument->insn.conditional() || argument->insn.op == Op::Jmp || (!push && Writes(argument->insn, StackReg))) { argument = nullptr; break; }
      argument = program.predecessor(argument->pc);
    }
#endif
    if (!argument || argument->insn.op != Op::LoadField || argument->insn.dst != installerReg ||
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
      // Select the browser's existing permission-to-open path; package verification and user confirmation still run.
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
  // SHA-256 produces a local file fingerprint for the report; this calculation sends no network requests.
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
HashValue Blake3(std::span<const uint8_t> bytes) {
  // BLAKE3 fingerprints the file quickly so a patch plan can be matched to the exact browser file.
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update_tbb(&hasher, bytes.data(), bytes.size());
  std::array<uint8_t, 32> digest{};
  blake3_hasher_finalize(&hasher, digest.data(), digest.size());
  constexpr char hex[] = "0123456789abcdef";
  HashValue result{};
  for (size_t n = 0; n < digest.size(); ++n) { result[n * 2] = hex[digest[n] >> 4]; result[n * 2 + 1] = hex[digest[n] & 15]; }
  return result;
}
Report Analyze(std::span<const uint8_t> bytes) {
  // A damaged file or a different processor type cannot supply a usable patch plan.
  Report report; PeImage pe(bytes);
  if (!pe.valid()) { report.error = pe.error; return report; }
  if (pe.machine != NativeMachine()) { report.error = "scanner architecture differs from PE machine"; return report; }
  Boundaries boundaries(pe);
  if (boundaries.error) { report.error = boundaries.error; return report; }
  Program program;
  if (pe.isEdge()) {
    // Edge uses a separate recognized layout: both installer decisions are required, and only x64 is supported.
#if defined(AUTOSCAN_X64)
    RefBatch batch(pe);
    installVerifier(pe, boundaries, program, {}, report, batch);
    crxDownload(pe, boundaries, program, report, batch);
    if (report.gates.size() != 2 || report.gates[0].optional != InstallVerifier || report.gates[1].optional != CrxDownload)
      report.error = "need both verified Edge source and CRX download gates";
    std::sort(report.gates.begin(), report.gates.end(), [](const Gate& a, const Gate& b) { return a.rva < b.rva; });
#else
    report.error = "Edge installer recognition requires x64";
#endif
    return report;
  }
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
#if !defined(AUTOSCAN_ARM64)
      if (!cmpStart(pe.code(cp)[0])) continue;
#endif
      auto cmp = Lift(pe.code(cp), cp);
      if (cp + cmp.length() != jumpPc || !threshold(cmp, jump)) continue;
      bool inverted = jump.condition() == 12 || jump.condition() == 14;
      Head head{cp, jumpPc, inverted ? jump.target() : jumpPc + jump.length(),
                inverted ? jumpPc + jump.length() : jump.target(), inverted};
#if defined(AUTOSCAN_X64)
      // shortcut: prescreen raw x64 table bounds; extend only after native architecture parity.
      auto raw = boundaries.find(cp, true); bool complete = true;
      if (raw && !prefilter(pe, head, raw, &complete) && complete) continue;
#endif
      auto bounds = boundaries.find(cp); if (!bounds) continue;
      if (!prefilter(pe, head, bounds)) continue;
      plausible = true;
      if (program.range.begin != bounds.begin || program.range.end != bounds.end) program.build(pe, bounds);
      if (program.complete && program.at(cp) && program.at(jumpPc)) variants.push_back({head, bounds});
    }
    if (!plausible) { ++report.rejected; return; }
    ++report.screened;
    // A plausible but unproven MV2 decision blocks the report instead of being silently ignored.
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
    // Match both widths of unshifted CMP #2/#3; CMP with SP remains unsupported.
    auto word = ReadInsn<uint32_t>(text.data() + p);
    if ((word & 0x7ffff81f) == 0x7100081f && (word & 0x3e0) != 0x3e0)
      consider(pe.text.rva + static_cast<uint32_t>(p) + 4);
  }
#else
  auto probe = [&](size_t n) {
    if (n < text.size() && text.size() - n >= 2 && ((text[n] >= 0x7c && text[n] <= 0x7f) ||
        (text[n] == 0x0f && text[n + 1] >= 0x8c && text[n + 1] <= 0x8f)))
      consider(pe.text.rva + static_cast<uint32_t>(n));
  };
  auto examine = [&](size_t p) {
    probe(p + 1);
    if (text.size() - p > 4 && !text[p + 1] && !text[p + 2] && !text[p + 3]) probe(p + 4);
  };
  size_t p = 0;
  for (; text.size() - p >= 16; p += 16) {
    auto bytes = _mm_loadu_si128(reinterpret_cast<const __m128i*>(text.data() + p));
    auto matched = _mm_cmpeq_epi8(_mm_and_si128(bytes, _mm_set1_epi8(-2)), _mm_set1_epi8(2));
    unsigned mask = static_cast<unsigned>(_mm_movemask_epi8(matched));
    while (mask) { examine(p + std::countr_zero(mask)); mask &= mask - 1; }
  }
  for (; p < text.size(); ++p) if (text[p] == 2 || text[p] == 3) examine(p);
#endif
  std::sort(report.gates.begin(), report.gates.end(), [](const Gate& a, const Gate& b) { return a.rva < b.rva; });
  bool free = false, hasLayout = false, coherent = true;
  // Require independent evidence that the matches describe the same extension data, rather than coincidental comparisons.
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
    // Optional installer changes are considered only after the core MV2 decisions have passed their checks.
    RefBatch batch(pe);
    installVerifier(pe, boundaries, program, layout, report, batch);
    if (report.gates.size() < 64) crxDownload(pe, boundaries, program, report, batch);
    std::sort(report.gates.begin(), report.gates.end(), [](const Gate& a, const Gate& b) { return a.rva < b.rva; });
  }
  return report;
}
Report Discover(std::span<const uint8_t> bytes) {
  auto hash = Hash(bytes); Report report;
  if (!hash[0]) { report.error = "SHA-256 failed"; return report; }
  report = Analyze(bytes); report.sha256 = hash; report.blake3 = Blake3(bytes); return report;
}
} // namespace autoscan
