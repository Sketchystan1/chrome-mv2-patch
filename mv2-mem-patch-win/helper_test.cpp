// Run the deployed scanner through Windows' small-stack x86 rundll32 host.
// The fabricated browser file and both cold/cached scans stay in an owned temp folder.
#include "autoscan_runtime.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
static void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
template<class T> static void put(Bytes& bytes, size_t offset, T value) {
  memcpy(bytes.data() + offset, &value, sizeof(value));
}
static Bytes fixture() {
  Bytes bytes(0x1000);
  put<uint16_t>(bytes, 0, IMAGE_DOS_SIGNATURE); put<uint32_t>(bytes, 0x3c, 0x80);
  put<uint32_t>(bytes, 0x80, IMAGE_NT_SIGNATURE); put<uint16_t>(bytes, 0x84, IMAGE_FILE_MACHINE_I386);
  put<uint16_t>(bytes, 0x86, 2); put<uint16_t>(bytes, 0x94, 0xe0); put<uint16_t>(bytes, 0x98, 0x10b);
  put<uint32_t>(bytes, 0xb4, 0x400000); put<uint32_t>(bytes, 0xd0, 0x3000);
  put<uint32_t>(bytes, 0xd4, 0x400); put<uint32_t>(bytes, 0xf4, 16);
  for (unsigned n = 0; n < 2; ++n) {
    IMAGE_SECTION_HEADER section{};
    memcpy(section.Name, n ? ".rdata" : ".text", n ? 6 : 5);
    section.Misc.VirtualSize = section.SizeOfRawData = 0x400;
    section.VirtualAddress = n ? 0x2000 : 0x1000;
    section.PointerToRawData = n ? 0x800 : 0x400;
    section.Characteristics = n ? 0x40000040 : 0x60000020;
    put(bytes, 0x178 + n * sizeof(section), section);
  }
  std::fill(bytes.begin() + 0x400, bytes.begin() + 0x800, 0xcc);
  for (auto [offset, text] : {
      std::pair{0x440u, "837c2404027f278b44240883f801740a83f803740583f80875148b44240c83f805740b83f80a7406b801000000c331c0c3"},
      std::pair{0x500u, "5589e58b4d08837950027f378b916401000080b94c0100000075128b424483f801740a83f803740583f80875168b422883f805740e83f80a7409b8010000005dc2040031c05dc20400"}}) {
    auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (; *text; text += 2) bytes[offset++] = static_cast<uint8_t>(digit(text[0]) * 16 + digit(text[1]));
  }
  IMAGE_LOAD_CONFIG_DIRECTORY32 config{};
  config.Size = sizeof(config); config.GuardCFFunctionTable = 0x402300; config.GuardCFFunctionCount = 2;
  put(bytes, 0x800, config); put<uint32_t>(bytes, 0x148, 0x2000); put<uint32_t>(bytes, 0x14c, sizeof(config));
  put<uint32_t>(bytes, 0xb00, 0x1040); put<uint32_t>(bytes, 0xb04, 0x1100);
  return bytes;
}
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
  void close() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = nullptr; }
};
static autoscan::WirePlan scan(const std::filesystem::path& dll, HANDLE mapping,
                               size_t size, const autoscan::HashValue& hash) {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  Handle read, write;
  check(CreatePipe(&read.value, &write.value, &security, 4096) &&
        SetHandleInformation(read.value, HANDLE_FLAG_INHERIT, 0), "create helper reply pipe");
  std::array<wchar_t, MAX_PATH> system{};
  check(GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size())) != 0, "resolve rundll32");
  auto exe = std::filesystem::path(system.data()) / L"rundll32.exe";
  std::array<wchar_t, 32768> command{};
  check(_snwprintf_s(command.data(), command.size(), _TRUNCATE,
        L"\"%ls\" \"%ls\",VersionMV2Scan %llu %llu %llu %.*hs", exe.c_str(), dll.c_str(),
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mapping)), static_cast<unsigned long long>(size),
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(write.value)), 64, hash.data()) > 0,
        "format helper command");
  STARTUPINFOW startup{}; startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION process{};
  check(CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &startup, &process), "start deployed scan helper");
  Handle child{process.hProcess}, thread{process.hThread}; write.close();
  DWORD waited = WaitForSingleObject(child.value, 30000);
  if (waited != WAIT_OBJECT_0) {
    TerminateProcess(child.value, ERROR_TIMEOUT); WaitForSingleObject(child.value, 5000);
    check(false, "scan helper timed out");
  }
  DWORD code = 1; check(GetExitCodeProcess(child.value, &code) != 0, "read scan helper exit status");
  if (code) std::fprintf(stderr, "scan helper exit status: 0x%08lx\n", code);
  check(code == 0, "scan helper crashed");
  autoscan::WirePlan plan;
  DWORD received = 0;
  check(ReadFile(read.value, &plan, sizeof(plan), &received, nullptr) && received == sizeof(plan), "complete scan reply");
  DWORD extra = 0; check(!PeekNamedPipe(read.value, nullptr, 0, nullptr, &extra, nullptr) || !extra, "one scan reply");
  check(plan.magic == 0x32564d41 && plan.protocol == 5 && !plan.status && plan.blake3 == hash && plan.count == 2 &&
        plan.sites[0].rva == 0x1045 && plan.sites[1].rva == 0x110a && !plan.offstoreRva && !plan.crxDownloadRva,
        "helper recognizes both fabricated core decisions");
  return plan;
}
int wmain(int argc, wchar_t** argv) {
  if (argc != 2) return 2;
  auto temp = std::filesystem::canonical(std::filesystem::temp_directory_path());
  auto root = temp / (L"mv2-helper-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
  std::array<wchar_t, 32768> local{};
  DWORD localLength = GetEnvironmentVariableW(L"LOCALAPPDATA", local.data(), static_cast<DWORD>(local.size()));
  bool created = false; int result = 1;
  try {
    check(localLength < local.size() && std::filesystem::create_directory(root), "create private helper workspace");
    created = true;
    check(std::filesystem::canonical(root).parent_path() == temp, "helper workspace stays beneath temp");
    auto bytes = fixture(); auto hash = autoscan::Blake3(bytes);
    auto path = root / L"chrome.dll";
    { std::ofstream file(path, std::ios::binary); file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); check(bool(file), "write fabricated browser"); }
    Handle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)};
    check(file.value != INVALID_HANDLE_VALUE, "open fabricated browser read-only");
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle mapping{CreateFileMappingW(file.value, &security, PAGE_READONLY, 0, 0, nullptr)};
    check(mapping.value && SetEnvironmentVariableW(L"LOCALAPPDATA", root.c_str()), "isolate helper cache");
    auto dll = std::filesystem::absolute(argv[1]);
    auto cold = scan(dll, mapping.value, bytes.size(), hash);
    auto cached = scan(dll, mapping.value, bytes.size(), hash);
    check(!cold.cacheHit && cached.cacheHit == 1, "cold worker scan and cached reply both succeed");
    auto expected = cold; expected.cacheHit = 1;
    check(memcmp(&expected, &cached, sizeof(expected)) == 0, "cache preserves the exact helper plan");
    std::puts("PASS: small-stack rundll32 cold scan and protected cache reuse"); result = 0;
  } catch (const std::exception& error) { std::fprintf(stderr, "FAIL: %s\n", error.what()); }
  SetEnvironmentVariableW(L"LOCALAPPDATA", localLength ? local.data() : nullptr);
  if (created && std::filesystem::canonical(root).parent_path() == temp) std::filesystem::remove_all(root);
  return result;
}
