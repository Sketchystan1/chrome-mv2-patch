"""Experimental, read-only Windows x64 MV2 discovery without signatures or symbols.

Capstone recovers candidate control flow; Z3 checks its predicate routing.
This proves the decoded local model, not complete enforcement coverage or the
purpose of every caller. Review the report before using an emitted runtime plan.

    uv run --with capstone --with z3-solver scripts/scan_windows.py chrome.exe
"""

import argparse
import bisect
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

try:
    import capstone as cs
    import z3 as z
except ImportError as exc:
    raise SystemExit("This analysis tool needs capstone and z3-solver; run it with "
                     "uv run --with capstone --with z3-solver.") from exc

from derive_milestone import open_images


def reg_name(md, reg):
    name = md.reg_name(reg)
    for full, aliases in (("rax", ("eax", "ax", "al", "ah")),
                          ("rbx", ("ebx", "bx", "bl", "bh")),
                          ("rcx", ("ecx", "cx", "cl", "ch")),
                          ("rdx", ("edx", "dx", "dl", "dh")),
                          ("rsi", ("esi", "si", "sil")),
                          ("rdi", ("edi", "di", "dil")),
                          ("rsp", ("esp", "sp", "spl")),
                          ("rbp", ("ebp", "bp", "bpl"))):
        if name == full or name in aliases:
            return full
    return re.sub(r"^r(\d+)[dwb]$", r"r\1", name)


def low(value, bits):
    return z.simplify(z.Extract(bits - 1, 0, value)) if bits < value.size() else value


def wide(value):
    return z.simplify(z.ZeroExt(64 - value.size(), value)) if value.size() < 64 else value


def number(value):
    value = z.simplify(value)
    return value.as_long() if z.is_bv_value(value) else None


def condition(mnemonic, flags):
    suffix = mnemonic[3:] if mnemonic.startswith("set") else mnemonic[4:] if mnemonic.startswith("cmov") else mnemonic[1:]
    cf, zf, sf, of = (flags[n] for n in ("c", "z", "s", "o"))
    choices = {"e": zf, "z": zf, "ne": z.Not(zf), "nz": z.Not(zf),
               "b": cf, "c": cf, "nae": cf, "ae": z.Not(cf), "nb": z.Not(cf), "nc": z.Not(cf),
               "a": z.And(z.Not(cf), z.Not(zf)), "nbe": z.And(z.Not(cf), z.Not(zf)),
               "be": z.Or(cf, zf), "na": z.Or(cf, zf),
               "g": z.And(z.Not(zf), sf == of), "le": z.Or(zf, sf != of),
               "ge": sf == of, "l": sf != of, "s": sf, "ns": z.Not(sf),
               "o": of, "no": z.Not(of)}
    return choices.get(suffix)


def arithmetic_flags(a, b=None):
    result = a if b is None else a - b
    sign = lambda v: z.Extract(v.size() - 1, v.size() - 1, v) == 1
    return {"z": result == 0, "s": sign(result),
            "c": z.BoolVal(False) if b is None else z.ULT(a, b),
            "o": z.BoolVal(False) if b is None else z.And(sign(a) != sign(b), sign(result) != sign(a))}


class Scanner:
    def __init__(self, img):
        if img.container != "pe":
            raise ValueError("this experiment currently supports Windows x64 only")
        self.img, self.text = img, img.text
        if img.text_raw < 0 or img.text_raw + img.text_size > len(img.data):
            raise ValueError(".text exceeds the file")
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.md.detail = True
        self.instructions, self.graphs = {}, {}
        self.functions = self.unwind_ranges()
        self.starts = [a for a, b in self.functions]

    def unwind_ranges(self):
        data = self.img.data
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        if struct.unpack_from("<H", data, nt + 4)[0] != 0x8664:
            raise ValueError("expected an AMD64 PE image")
        count = struct.unpack_from("<H", data, nt + 6)[0]
        size = struct.unpack_from("<H", data, nt + 20)[0]
        if nt + 24 + size + count * 40 > len(data):
            raise ValueError("section table exceeds the file")
        ranges = []
        for i in range(count):
            off = nt + 24 + size + i * 40
            if data[off:off + 8].rstrip(b"\0") != b".pdata":
                continue
            virtual, _, raw_size, raw = struct.unpack_from("<IIII", data, off + 8)
            end = raw + min(virtual, raw_size)
            if end > len(data):
                raise ValueError(".pdata exceeds the file")
            for pos in range(raw, end - 11, 12):
                begin, finish, _ = struct.unpack_from("<III", data, pos)
                begin, finish = self.img.off(begin), self.img.off(finish)
                if 0 <= begin < finish <= len(self.text):
                    ranges.append((begin, finish))
        if ranges != sorted(ranges):
            raise ValueError("unsorted exception-function table")
        return ranges

    def insn(self, pos):
        if pos not in self.instructions:
            self.instructions[pos] = next(self.md.disasm(self.text[pos:pos + 15], pos, count=1), None) if 0 <= pos < len(self.text) else None
        return self.instructions[pos]

    def bounds(self, pos):
        i = bisect.bisect_right(self.starts, pos) - 1
        if i >= 0 and pos < self.functions[i][1]:
            return (*self.functions[i], "unwind")
        begin = pos & ~15
        if begin and self.text[begin - 1] != 0xCC:
            return None
        # shortcut: leaf boundaries require aligned padding; unknown layouts remain unresolved.
        end = self.text.find(b"\xCC\xCC\xCC\xCC", begin, min(begin + 4096, len(self.text)))
        return (begin, end, "aligned-padding") if end > pos else None

    def heads(self):
        for match in re.finditer(b"[\x02\x03](?:[\x7c-\x7f]|\x0f[\x8c-\x8f])", self.text):
            jp = match.start() + 1
            for cp in range(max(0, jp - 10), jp - 2):
                compare = self.insn(cp)
                if not compare or compare.mnemonic != "cmp" or cp + compare.size != jp:
                    continue
                jump = self.insn(jp)
                if not jump or len(compare.operands) != 2 or compare.operands[1].type != cs.CS_OP_IMM:
                    continue
                if compare.operands[0].size != 4:
                    continue
                value = compare.operands[1].imm
                if (value, jump.mnemonic) not in ((2, "jg"), (2, "jle"), (3, "jge"), (3, "jl")):
                    continue
                taken, fall = jump.operands[0].imm, jp + jump.size
                inverted = jump.mnemonic in ("jle", "jl")
                yield cp, jp, taken if inverted else fall, fall if inverted else taken, inverted

    def successors(self, ins):
        if ins.group(cs.CS_GRP_RET) or ins.mnemonic in ("int3", "ud2"):
            return []
        if ins.group(cs.CS_GRP_JUMP):
            targets = [ins.operands[0].imm] if ins.operands and ins.operands[0].type == cs.CS_OP_IMM else []
            return targets + ([] if ins.mnemonic == "jmp" else [ins.address + ins.size])
        return [ins.address + ins.size]

    def graph(self, bounds):
        begin, end, _ = bounds
        if (begin, end) not in self.graphs:
            todo, seen, previous = [begin], set(), collections.defaultdict(set)
            complete = True
            while todo and len(seen) < 20000:
                pos = todo.pop()
                if pos in seen or not begin <= pos < end:
                    continue
                ins = self.insn(pos)
                if not ins or pos + ins.size > end:
                    complete = False
                    continue
                seen.add(pos)
                if ins.group(cs.CS_GRP_JUMP) and (not ins.operands or ins.operands[0].type != cs.CS_OP_IMM):
                    complete = False
                for target in self.successors(ins):
                    if begin <= target < end:
                        previous[target].add(pos)
                        todo.append(target)
            self.graphs[begin, end] = seen, previous, complete and not todo
        return self.graphs[begin, end]

    def constant_before(self, reg, pos, bounds):
        _, previous, complete = self.graph(bounds)
        if not complete:
            return None
        todo = [(p, reg) for p in previous[pos]]
        seen, values = set(), set()
        while todo and len(seen) < 4096:
            at, name = todo.pop()
            if (at, name) in seen:
                continue
            seen.add((at, name))
            ins = self.insn(at)
            ops = ins.operands
            writes = {reg_name(self.md, r) for r in ins.regs_access()[1]}
            if ins.group(cs.CS_GRP_CALL) and name in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                values.add(None)
                continue
            if name in writes:
                if ins.mnemonic in ("mov", "movabs") and ops[0].type == cs.CS_OP_REG and ops[0].size >= 4:
                    if ops[1].type == cs.CS_OP_IMM:
                        values.add(ops[1].imm & ((1 << (ops[0].size * 8)) - 1))
                        continue
                    if ops[1].type == cs.CS_OP_REG:
                        name = reg_name(self.md, ops[1].reg)
                    else:
                        values.add(None)
                        continue
                elif ins.mnemonic == "xor" and ops[0].type == ops[1].type == cs.CS_OP_REG and ops[0].reg == ops[1].reg and ops[0].size >= 4:
                    values.add(0)
                    continue
                else:
                    values.add(None)
                    continue
            if not previous[at]:
                values.add(None)
            todo.extend((p, name) for p in previous[at])
        return next(iter(values)) if not todo and len(values) == 1 else None

    def prefilter(self, affected, unaffected, bounds):
        begin, end, _ = bounds
        todo, seen, constants, bit = [affected], set(), set(), False
        while todo and len(seen) < 256:
            pos = todo.pop()
            if pos in seen or pos == unaffected or not begin <= pos < end:
                continue
            seen.add(pos)
            ins = self.insn(pos)
            if not ins or ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_RET):
                continue
            ops = ins.operands
            if ins.mnemonic == "cmp" and len(ops) == 2 and ops[1].type == cs.CS_OP_IMM:
                constants.add(ops[1].imm)
            bit |= ins.mnemonic == "bt"
            if ops and ops[0].type == cs.CS_OP_MEM and ops[0].access & cs.CS_AC_WRITE:
                continue
            todo.extend(self.successors(ins))
        return {5, 10} <= constants and ({1, 3, 8} <= constants or (bit and 8 in constants))

    def scan(self):
        gates, unresolved, count, checked = [], [], 0, 0
        by_jump = collections.defaultdict(list)
        for head in self.heads():
            by_jump[head[1]].append(head)
        for variants in by_jump.values():
            count += 1
            possible, plausible = [], False
            for head in variants:
                cp, jp, affected, unaffected, inverted = head
                bounds = self.bounds(cp)
                if not bounds or not self.prefilter(affected, unaffected, bounds):
                    continue
                plausible = True
                if cp in self.graph(bounds)[0]:
                    possible.append((head, bounds))
            if not plausible:
                continue
            checked += 1
            if len(possible) != 1:
                unresolved.append({"rva": hex(self.img.rva(jp)), "reason": "instruction boundary missing or ambiguous"})
                continue
            head, bounds = possible[0]
            cp, jp, affected, unaffected, inverted = head
            proof = Predicate(self, head, bounds)
            result = proof.verify()
            if result.get("verified"):
                jump = self.insn(jp)
                result.update(compare_rva=hex(self.img.rva(cp)), rva=hex(self.img.rva(jp)),
                              kind=("short" if jump.size == 2 else "near") + ("-nop" if inverted else ""),
                              boundary=bounds[2], function_rva=hex(self.img.rva(bounds[0])))
                gates.append(result)
            else:
                unresolved.append({"rva": hex(self.img.rva(jp)), **result})
        return {"architecture": "windows-x64", "heads": count, "checked": checked,
                "gates": gates, "unresolved": unresolved, "complete_enforcement_coverage_proven": False}


class Predicate:
    def __init__(self, scanner, head, bounds):
        self.s, self.head, self.bounds = scanner, head, bounds
        self.memories, self.fields, self.comparisons, self.bit_tests = {}, {}, {}, []
        self.unsupported = {}
        self.roots = {name: z.BitVec(name, 64) for name in
                      ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", *('r%d' % i for i in range(8, 16)))}
        self.initial = dict(self.roots)
        cp = head[0]
        for name in self.initial:
            value = scanner.constant_before(name, cp, bounds)
            if value in (0, 1, 0x10A):
                self.initial[name] = z.BitVecVal(value, 64)
        self.mv = low(self.read(scanner.insn(cp).operands[0], self.initial, scanner.insn(cp)), 32)
        self.checkpoints = self.false_checkpoints()

    def read(self, op, regs, ins):
        if op.type == cs.CS_OP_IMM:
            return z.BitVecVal(op.imm & ((1 << 64) - 1), 64)
        if op.type == cs.CS_OP_REG:
            name = reg_name(self.s.md, op.reg)
            value = regs.get(name, z.BitVec(name, 64))
            if self.s.md.reg_name(op.reg) in ("ah", "bh", "ch", "dh"):
                value = z.LShR(value, 8)
            return wide(low(value, op.size * 8))
        if op.type != cs.CS_OP_MEM or op.size not in (1, 2, 4, 8):
            raise ValueError("unsupported operand")
        address, base = self.address(op, regs, ins)
        return self.memory(address, base, op.mem.disp, op.size, bool(op.mem.index))

    def address(self, op, regs, ins):
        base_name = reg_name(self.s.md, op.mem.base) if op.mem.base else None
        base = z.BitVecVal(ins.address + ins.size, 64) if base_name == "rip" else regs[base_name] if base_name else z.BitVecVal(0, 64)
        index = regs[reg_name(self.s.md, op.mem.index)] * op.mem.scale if op.mem.index else z.BitVecVal(0, 64)
        address = z.simplify(base + index + op.mem.disp)
        return address, base

    def memory(self, address, base, offset, size, indexed=False):
        key = address.sexpr(), size
        if key not in self.memories:
            value = z.BitVec("load%d" % len(self.memories), size * 8)
            self.memories[key] = value
            self.fields[value.sexpr()] = {"base": base, "offset": offset, "size": size,
                                          "indexed": indexed, "value": value}
        return wide(self.memories[key])

    def write(self, op, value, regs):
        name = reg_name(self.s.md, op.reg)
        bits = op.size * 8
        value = low(value, bits)
        if self.s.md.reg_name(op.reg) in ("ah", "bh", "ch", "dh"):
            regs[name] = z.simplify(z.Concat(z.Extract(63, 16, regs[name]), value, z.Extract(7, 0, regs[name])))
        elif bits < 32:
            regs[name] = z.simplify(z.Concat(z.Extract(63, bits, regs[name]), value))
        else:
            regs[name] = wide(value)

    def unknown_flags(self, pos):
        return {name: z.Bool('flag_%x_%s' % (pos, name)) for name in "czso"}

    def false_checkpoints(self):
        pos, regs, changed, out = self.head[3], dict(self.initial), {}, {}
        for _ in range(12):
            ins = self.s.insn(pos)
            if not ins:
                break
            if ins.group(cs.CS_GRP_RET):
                # A C++ bool returns in AL; the remaining RAX bits can contain a pointer.
                out[pos] = {**{n: v for n, v in changed.items() if n != 'rax'},
                            "al": low(regs['rax'], 8)}
                break
            out[pos] = dict(changed)
            ops = ins.operands
            if ins.mnemonic == "jmp" and ops[0].type == cs.CS_OP_IMM:
                if ops[0].imm in out:
                    break
                pos = ops[0].imm
                continue
            if ins.mnemonic == "xor" and ops[0].type == ops[1].type == cs.CS_OP_REG and ops[0].reg == ops[1].reg:
                self.write(ops[0], z.BitVecVal(0, 64), regs)
            elif ins.mnemonic in ("mov", "movabs") and ops[0].type == cs.CS_OP_REG and ops[1].type == cs.CS_OP_IMM:
                self.write(ops[0], self.read(ops[1], regs, ins), regs)
            elif ins.mnemonic != "nop":
                break
            if ops and ops[0].type == cs.CS_OP_REG:
                name = reg_name(self.s.md, ops[0].reg)
                changed[name] = regs[name]
            pos += ins.size
        return out

    def walk(self):
        cp, jp, affected, unaffected, inverted = self.head
        entry = self.mv < 3
        todo = [(affected, dict(self.initial), self.unknown_flags(cp), entry, 0)]
        true_paths, unknown_paths, terminals, decoded = [], [], [], set()
        work = 0
        while todo and work < 2048:
            pos, regs, flags, path, steps = todo.pop()
            work += 1
            if z.is_false(z.simplify(path)):
                continue
            if steps >= 128 or not self.bounds[0] <= pos < self.bounds[1]:
                unknown_paths.append(path)
                continue
            if pos in self.checkpoints:
                tests = [low(regs['rax'], 8) == value if name == 'al' else regs[name] == value
                         for name, value in self.checkpoints[pos].items()]
                same = z.And(*tests)
                terminals.append(z.And(path, same))
                path = z.simplify(z.And(path, z.Not(same)))
                if z.is_false(path):
                    continue
            ins = self.s.insn(pos)
            if not ins:
                unknown_paths.append(path)
                continue
            decoded.add(pos)
            ops, mn = ins.operands, ins.mnemonic
            if ins.group(cs.CS_GRP_RET) or ins.group(cs.CS_GRP_CALL) or (ops and ops[0].type == cs.CS_OP_MEM and ops[0].access & cs.CS_AC_WRITE):
                true_paths.append(path)
                terminals.append(path)
                continue
            if ins.group(cs.CS_GRP_JUMP):
                if not ops or ops[0].type != cs.CS_OP_IMM:
                    unknown_paths.append(path)
                    continue
                target = ops[0].imm
                if mn == "jmp":
                    todo.append((target, regs, flags, path, steps + 1))
                else:
                    test = condition(mn, flags)
                    if test is None:
                        unknown_paths.append(path)
                        continue
                    todo.append((target, dict(regs), flags, z.And(path, test), steps + 1))
                    todo.append((pos + ins.size, regs, flags, z.And(path, z.Not(test)), steps + 1))
                continue
            try:
                if mn == "cmp":
                    bits = ops[0].size * 8
                    a, b = low(self.read(ops[0], regs, ins), bits), low(self.read(ops[1], regs, ins), bits)
                    flags = arithmetic_flags(a, b)
                    if ops[1].type == cs.CS_OP_IMM:
                        key = a.sexpr()
                        self.comparisons.setdefault(key, (a, set()))[1].add(ops[1].imm)
                elif mn == "test":
                    bits = ops[0].size * 8
                    flags = arithmetic_flags(low(self.read(ops[0], regs, ins) & self.read(ops[1], regs, ins), bits))
                elif mn == "bt":
                    bits = ops[0].size * 8
                    mask = low(self.read(ops[0], regs, ins), bits)
                    index = low(self.read(ops[1], regs, ins), bits)
                    flags = self.unknown_flags(pos)
                    flags['c'] = z.Extract(0, 0, z.LShR(mask, index & (bits - 1))) == 1
                    self.bit_tests.append((mask, index))
                elif mn in ("mov", "movabs", "movzx", "movsx", "movsxd"):
                    value = self.read(ops[1], regs, ins)
                    if mn in ("movsx", "movsxd"):
                        short = low(value, ops[1].size * 8)
                        value = z.SignExt(64 - short.size(), short)
                    self.write(ops[0], value, regs)
                elif mn == "lea":
                    self.write(ops[0], self.address(ops[1], regs, ins)[0], regs)
                elif mn == "pop" and ops[0].type == cs.CS_OP_REG:
                    value = self.memory(regs['rsp'], regs['rsp'], 0, 8)
                    regs['rsp'] = z.simplify(regs['rsp'] + 8)
                    self.write(ops[0], value, regs)
                elif mn.startswith("set"):
                    test = condition(mn, flags)
                    if test is None:
                        raise ValueError("unsupported setcc")
                    self.write(ops[0], z.If(test, z.BitVecVal(1, 64), z.BitVecVal(0, 64)), regs)
                elif mn.startswith("cmov"):
                    test = condition(mn, flags)
                    if test is None:
                        raise ValueError("unsupported cmov")
                    self.write(ops[0], z.If(test, self.read(ops[1], regs, ins), self.read(ops[0], regs, ins)), regs)
                elif mn in ("and", "or", "xor"):
                    a, b = self.read(ops[0], regs, ins), self.read(ops[1], regs, ins)
                    value = a & b if mn == 'and' else a | b if mn == 'or' else a ^ b
                    self.write(ops[0], value, regs)
                    flags = arithmetic_flags(low(value, ops[0].size * 8))
                elif mn in ("add", "sub"):
                    bits = ops[0].size * 8
                    a, b = low(self.read(ops[0], regs, ins), bits), low(self.read(ops[1], regs, ins), bits)
                    value = a + b if mn == 'add' else a - b
                    self.write(ops[0], value, regs)
                    flags = arithmetic_flags(a, b) if mn == 'sub' else arithmetic_flags(value)
                    if mn == 'add':
                        flags['c'] = z.ULT(value, a)
                        sign = lambda v: z.Extract(bits - 1, bits - 1, v)
                        flags['o'] = z.And(sign(a) == sign(b), sign(value) != sign(a))
                elif mn == "nop":
                    pass
                else:
                    raise ValueError("unsupported instruction " + mn)
            except (ValueError, KeyError) as exc:
                self.unsupported[hex(self.s.img.rva(pos))] = str(exc)
                unknown_paths.append(path)
                continue
            todo.append((pos + ins.size, regs, flags, path, steps + 1))
        unknown_paths.extend(item[3] for item in todo)
        return z.Or(*true_paths), z.Or(*unknown_paths), z.Or(*terminals), len(decoded)

    def roles(self):
        types = {key: value for key, (value, values) in self.comparisons.items() if {1, 3, 8} <= values and value.size() == 32}
        for mask, value in self.bit_tests:
            if number(mask) == 0x10A and value.size() == 32:
                types[value.sexpr()] = value
        locations = [value for value, values in self.comparisons.values() if {5, 10} <= values and value.size() == 32]
        mv_field = self.fields.get(self.mv.sexpr())
        for typ in types.values():
            for loc in locations:
                if len({typ.sexpr(), loc.sexpr(), self.mv.sexpr()}) != 3:
                    continue
                if mv_field:
                    tf, lf = self.fields.get(typ.sexpr()), self.fields.get(loc.sexpr())
                    if not tf or not lf or tf['indexed'] or lf['indexed'] or not z.eq(tf['base'], lf['base']):
                        continue
                    parent = self.fields.get(tf['base'].sexpr())
                    if not parent or parent['size'] != 8 or not z.eq(parent['base'], mv_field['base']):
                        continue
                    flags = [f for f in self.fields.values() if f['size'] == 1 and not f['indexed'] and z.eq(f['base'], mv_field['base'])]
                    if len(flags) != 1:
                        continue
                    flag = flags[0]['value']
                    fields = {"manifest_version": mv_field['offset'], "manifest": parent['offset'],
                              "type": tf['offset'], "location": lf['offset'], "converted_user_script": flags[0]['offset']}
                    yield typ, loc, flag, fields
                elif typ.sexpr() not in self.fields and loc.sexpr() not in self.fields:
                    yield typ, loc, None, None

    def verify(self):
        actual, unknown, coverage, decoded = self.walk()
        valid, failures = [], []
        for typ, loc, flag, fields in self.roles():
            member = z.Or(typ == 1, typ == 3, typ == 8)
            assumptions = z.BoolVal(True)
            if flag is not None:
                member = z.Or(flag != 0, member)
                assumptions = z.Or(flag == 0, flag == 1)
            expected = z.And(self.mv < 3, member, loc != 5, loc != 10)
            solver = z.Solver()
            solver.set(timeout=3000)
            solver.add(assumptions, z.Or(unknown, z.Xor(actual, expected), z.And(self.mv < 3, z.Not(coverage))))
            result = solver.check()
            if result == z.unsat:
                valid.append({"verified": True, "proof": "Z3: no counterexample to decoded MV2 predicate routing",
                              "fields": fields, "decoded_instructions": decoded})
            else:
                failure = {"reason": "solver timeout" if result == z.unknown else "predicate or supported control flow differs"}
                if self.unsupported:
                    failure['unsupported'] = self.unsupported
                if result == z.sat:
                    model = solver.model()
                    failure['counterexample'] = {name: str(model.eval(value, model_completion=True))
                                                 for name, value in (("manifest_version", self.mv), ("type", typ), ("location", loc))}
                failures.append(failure)
        if len(valid) == 1:
            return valid[0]
        return {"reason": "ambiguous roles"} if valid else (failures[0] if failures else {"reason": "type/location data flow not recovered"})


def resolve_binary(path):
    path = Path(path).resolve(strict=True)
    if path.suffix.lower() == '.exe':
        candidates = [p for p in [path.parent / 'chrome.dll', *path.parent.glob('*/chrome.dll')] if p.is_file()]
        if len(candidates) != 1:
            raise ValueError("expected one adjacent/versioned chrome.dll; pass its path explicitly")
        return candidates[0]
    return path


def runtime_plan(img, report):
    from derive_milestone import masked_match_count
    from port_milestone import harden
    if not report['gates'] or report['unresolved']:
        raise ValueError("cannot emit a plan with no gates or unresolved candidates")
    decisions = {int(g['rva'], 16) for g in report['gates']}
    sites, covered = [], set()
    for gate in report['gates']:
        cp, jp, kind = img.off(int(gate['compare_rva'], 16)), img.off(int(gate['rva'], 16)), gate['kind']
        jump = bytes(img.text[jp:jp + (2 if kind.startswith('short') else 6)])
        if kind.endswith('-nop') and jump[:1] != b'\x7e' and jump[:2] != b'\x0f\x8e':
            raise ValueError("this inverted branch needs runtime support before plan export")
        if img.rva(jp) in covered:
            continue
        start, off, sig, count, anchor = harden(img, cp, jp, kind)
        matches = {img.rva(p) + off for p in masked_match_count(img.text, sig, off, kind)}
        if not matches or not matches <= decisions or matches & covered:
            raise ValueError("generated runtime window includes an unverified or duplicate decision")
        covered.update(matches)
        site = {"name": "MV2 predicate at " + gate['rva'], "kind": kind,
                "jgRVA": gate['rva'], "jgOff": off, "sig": sig.hex().upper(), "expectedMatches": len(matches)}
        if kind == 'short' and jump[0] != 0x7F:
            site['stockOpcode'] = '0x%02X' % jump[0]
        if kind == 'near' and jump[:2] != b'\x0f\x8f':
            site['stockOpcode'] = '0x' + jump[:2].hex().upper()
        sites.append(site)
    if covered != decisions:
        raise ValueError("runtime plan does not cover the discovered decisions")
    return {"_comment": "Locally discovered research plan; enforce this exact binary hash before use.",
            "binary_sha256": report['sha256'], "milestones": [],
            "milestones_v2": [{"name": "scan-" + report['sha256'][:12], "container": "pe", "sites": sites}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('binary', help='chrome.exe or chrome.dll')
    parser.add_argument('--json', type=Path, help='write the analysis report')
    parser.add_argument('--plan', type=Path, help='emit a local runtime plan for a reviewed experiment')
    args = parser.parse_args()
    try:
        binary = resolve_binary(args.binary)
        img = open_images(str(binary))[0]
        report = Scanner(img).scan()
        report.update(binary=str(binary), sha256=hashlib.sha256(img.data).hexdigest())
        output = json.dumps(report, indent=2)
        print(output)
        if args.json:
            args.json.write_text(output + '\n', encoding='utf-8')
        if args.plan:
            args.plan.write_text(json.dumps(runtime_plan(img, report), indent=2) + '\n', encoding='utf-8')
        return 0 if report['gates'] and not report['unresolved'] else 1
    except (OSError, ValueError, struct.error) as exc:
        print('scan failed: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
