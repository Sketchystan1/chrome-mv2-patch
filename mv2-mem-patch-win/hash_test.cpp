#define NOMINMAX
#include <windows.h>
#include "autoscan.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <string_view>
#include <vector>
#include <thread>
#include <bit>
#include "blake3.h"

// BLAKE3 1.8.7 official vectors: input[i] = i % 251.
int main() {
  struct Case { size_t size; std::string_view expected; };
  constexpr Case cases[] = {
    {0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
    {1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"},
    {2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"},
    {3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"},
    {4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"},
    {5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"},
    {6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"},
    {7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"},
    {8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"},
    {63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"},
    {64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"},
    {65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"},
    {127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"},
    {128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"},
    {129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"},
    {1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"},
    {1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"},
    {1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"},
    {2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"},
    {2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"},
    {3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"},
    {3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"},
    {4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"},
    {4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"},
    {5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"},
    {5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"},
    {6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"},
    {6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"},
    {7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"},
    {7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"},
    {8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"},
    {8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"},
    {16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"},
    {31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"},
    {102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"},
  };
  std::array<uint8_t, 102401> input{};
  for (const auto& test : cases) for (size_t alignment : {0, 1}) {
    for (size_t n = 0; n < test.size; ++n) input[n + alignment] = static_cast<uint8_t>(n % 251);
    auto digest = autoscan::Blake3(std::span(input).subspan(alignment, test.size));
    if (std::string_view(digest.data(), digest.size()) != test.expected) {
      std::fprintf(stderr, "BLAKE3 vector failed: length=%zu alignment=%zu\n", test.size, alignment); return 1;
    }
  }
  constexpr uint8_t abc[] = {97, 98, 99};
  auto sha = autoscan::Hash(abc);
  if (std::string_view(sha.data(), sha.size()) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") return 1;
  sha = autoscan::Hash({});
  if (std::string_view(sha.data(), sha.size()) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") return 1;
  constexpr Case cacheCases[] = {
    {128, "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"},
    {1536, "cd9d357900c9d8d8c1e812631ee1fe738a734ad07254f97cadacf7c8a602fbb4"}
  };
  for (size_t n = 0; n < 1536; ++n) input[n] = static_cast<uint8_t>(n % 251);
  for (const auto& test : cacheCases) {
    sha = autoscan::Hash(std::span(input).first(test.size));
    if (std::string_view(sha.data(), sha.size()) != test.expected) return 1;
  }
  if constexpr (sizeof(size_t) > sizeof(ULONG)) {
    const size_t oversized = static_cast<size_t>(ULONG_MAX) + 1;
    auto inaccessible = static_cast<uint8_t*>(VirtualAlloc(nullptr, oversized, MEM_RESERVE, PAGE_NOACCESS));
    if (!inaccessible) return 1;
    bool declined = autoscan::Hash({inaccessible, oversized}) == autoscan::HashValue{};
    if (!VirtualFree(inaccessible, 0, MEM_RELEASE) || !declined) return 1;
  }
  std::vector<uint8_t> large(32 * 1024 * 1024 + 2);
  for (size_t n = 0; n < large.size(); ++n) large[n] = static_cast<uint8_t>(n % 251);
  for (size_t size : {size_t{16 * 1024 * 1024 - 1}, size_t{16 * 1024 * 1024}, size_t{16 * 1024 * 1024 + 1}, size_t{32 * 1024 * 1024 + 1}}) {
    auto bytes = std::span(large).subspan(1, size);
    blake3_hasher serial; blake3_hasher_init(&serial); blake3_hasher_update(&serial, bytes.data(), bytes.size());
    std::array<uint8_t, 32> expected{}; blake3_hasher_finalize(&serial, expected.data(), expected.size());
    constexpr char hex[] = "0123456789abcdef";
    autoscan::HashValue encoded{};
    for (size_t n = 0; n < expected.size(); ++n) { encoded[n * 2] = hex[expected[n] >> 4]; encoded[n * 2 + 1] = hex[expected[n] & 15]; }
    std::array<autoscan::HashValue, 2> concurrent{};
    std::thread other([&] { concurrent[0] = autoscan::Blake3(bytes); });
    concurrent[1] = autoscan::Blake3(bytes); other.join();
    if (concurrent[0] != encoded || concurrent[1] != encoded) { std::fputs("Parallel BLAKE3 differs from serial\n", stderr); return 1; }
    if (size == 32 * 1024 * 1024 + 1) {
      DWORD_PTR original = 0, system = 0;
      if (!GetProcessAffinityMask(GetCurrentProcess(), &original, &system) || !original) return 1;
      DWORD_PTR remaining = original, limited = 0;
      for (unsigned n = 1; n <= 3 && remaining; ++n) {
        DWORD_PTR next = remaining & (~remaining + 1); remaining &= ~next; limited |= next;
        if (!SetProcessAffinityMask(GetCurrentProcess(), limited)) return 1;
        auto count = autoscan::HashThreadCount();
        if (!count || count > n || autoscan::Blake3(bytes) != encoded) {
          std::fputs("Affinity-limited hashing differs or exceeds its CPU budget\n", stderr); return 1;
        }
      }
      if (!SetProcessAffinityMask(GetCurrentProcess(), original)) return 1;
      if (!autoscan::HashThreadCount() || autoscan::HashThreadCount() > GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)) return 1;
      alignas(void*) std::array<uint8_t, 8192> cpuData{};
      std::array<ULONG, 256> saved{}; ULONG required = 0, savedCount = 0;
      GROUP_AFFINITY group{};
      if (GetSystemCpuSetInformation(reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(cpuData.data()), static_cast<ULONG>(cpuData.size()), &required, GetCurrentProcess(), 0) &&
          required <= cpuData.size() && GetThreadGroupAffinity(GetCurrentThread(), &group) &&
          GetProcessDefaultCpuSets(GetCurrentProcess(), saved.data(), static_cast<ULONG>(saved.size()), &savedCount) && savedCount <= saved.size()) {
        for (size_t offset = 0; offset + sizeof(SYSTEM_CPU_SET_INFORMATION) <= required;) {
          SYSTEM_CPU_SET_INFORMATION cpu{}; memcpy(&cpu, cpuData.data() + offset, sizeof(cpu));
          if (cpu.Size < sizeof(cpu) || cpu.Size > required - offset) return 1;
          if (cpu.Type == CpuSetInformation && cpu.CpuSet.Group == group.Group &&
              cpu.CpuSet.LogicalProcessorIndex < sizeof(original) * 8 &&
              (original & (DWORD_PTR{1} << cpu.CpuSet.LogicalProcessorIndex)) &&
              (!cpu.CpuSet.Allocated || cpu.CpuSet.AllocatedToTargetProcess)) {
            ULONG id = cpu.CpuSet.Id;
            if (!SetProcessDefaultCpuSets(GetCurrentProcess(), &id, 1)) return 1;
            bool ok = autoscan::HashThreadCount() == 1 && autoscan::Blake3(bytes) == encoded;
            if (!SetProcessDefaultCpuSets(GetCurrentProcess(), saved.data(), savedCount) || !ok) return 1;
            break;
          }
          offset += cpu.Size;
        }
      }
    }
  }
  std::puts("PASS: 70 BLAKE3 vectors, concurrent boundaries, adaptive CPU budgets and SHA-256 cache vectors/bounds");
  return 0;
}
