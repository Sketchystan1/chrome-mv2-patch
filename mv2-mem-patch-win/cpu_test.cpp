// Test-only simulated Windows CPU replies check that hashing respects the CPUs available to it.
#define NOMINMAX
#include <windows.h>
#include <array>
#include <cstdio>
#include <cstdlib>

namespace {
struct Cpu {
  DWORD_PTR mask, system;
  DWORD active, perGroup;
  USHORT groups;
  ULONG selected;
  bool affinity = true, groupQuery = true, setsQuery = true;
};
Cpu cpu{};
BOOL WINAPI testAffinity(HANDLE, PDWORD_PTR mask, PDWORD_PTR system) { *mask = cpu.mask; *system = cpu.system; return cpu.affinity; }
DWORD WINAPI testActive(WORD group) { return group == ALL_PROCESSOR_GROUPS ? cpu.active : cpu.perGroup; }
BOOL WINAPI testGroups(HANDLE, PUSHORT count, PUSHORT values) {
  if (!cpu.groupQuery || cpu.groups > *count) { *count = cpu.groups; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
  *count = cpu.groups; for (USHORT n = 0; n < cpu.groups; ++n) values[n] = n; return TRUE;
}
BOOL WINAPI testSets(HANDLE, PULONG, ULONG, PULONG count) {
  *count = cpu.selected;
  SetLastError(cpu.setsQuery ? ERROR_INSUFFICIENT_BUFFER : ERROR_ACCESS_DENIED);
  return cpu.setsQuery && !cpu.selected;
}
}
#define GetProcessAffinityMask testAffinity
#define GetActiveProcessorCount testActive
#define GetProcessGroupAffinity testGroups
#define GetProcessDefaultCpuSets testSets
#include "blake3_threads.cpp"
#undef GetProcessAffinityMask
#undef GetActiveProcessorCount
#undef GetProcessGroupAffinity
#undef GetProcessDefaultCpuSets

int main() {
  struct Case { Cpu cpu; unsigned expected; };
  constexpr DWORD_PTR all = ~DWORD_PTR{0};
  constexpr unsigned bits = sizeof(DWORD_PTR) * 8;
  const Case cases[] = {
    {{0xffff, 0xffff, 16, 16, 1, 0}, 16},
    {{all, all, bits * 2, bits, 2, 0}, bits * 2},
    {{3, all, bits * 2, bits, 2, 0}, 2},
    {{all, all, bits * 2, bits, 2, 3}, 3},
    {{0xffff, 0xffff, 64, 16, 2, 0, true, false}, 16},
    {{0, 0, 24, 24, 1, 0, false}, 24},
    {{0, 0, 0, 0, 0, 0, false}, 1},
    {{0xffff, 0xffff, 16, 16, 1, 1, true, true, false}, 16}
  };
  for (const auto& test : cases) {
    cpu = test.cpu;
    if (autoscan::HashThreadCount() != test.expected) { std::fputs("CPU budget policy failed\n", stderr); return 1; }
  }
  std::puts("PASS: CPU budgets above eight, processor groups, affinity, CPU sets and query failures");
}
