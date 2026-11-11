// Read-only diagnostic using the same bounded recognizer as version.dll.
#define NOMINMAX
#include <windows.h>
#include <cstring>
#include "autoscan.h"

namespace {
struct Json {
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  std::array<char, 1024> buffer{}; size_t used = 0; bool ok = true;
  void flush() {
    size_t sent = 0;
    while (ok && sent < used) {
      DWORD n = 0;
      ok = WriteFile(output, buffer.data() + sent, static_cast<DWORD>(used - sent), &n, nullptr) && n;
      sent += n;
    }
    used = 0;
  }
  void character(char c) { if (used == buffer.size()) flush(); buffer[used++] = c; }
  void text(std::string_view value) { for (auto c : value) character(c); }
  void string(std::string_view value) {
    character('"');
    for (unsigned char c : value) { if (c == '"' || c == '\\') character('\\'); character(c >= 32 ? c : '?'); }
    character('"');
  }
  void number(int64_t n) {
    if (n < 0) character('-');
    uint64_t value = n < 0 ? 0ull - static_cast<uint64_t>(n) : static_cast<uint64_t>(n);
    std::array<char, 24> digits{}; size_t size = 0;
    do { digits[size++] = static_cast<char>('0' + value % 10); value /= 10; } while (value);
    while (size) character(digits[--size]);
  }
  void field(std::string_view name, int64_t value) { character(','); string(name); character(':'); number(value); }
  void hex(std::span<const uint8_t> bytes) {
    constexpr char digits[] = "0123456789ABCDEF"; character('"');
    for (auto b : bytes) { character(digits[b >> 4]); character(digits[b & 15]); }
    character('"');
  }
};
bool reportJson(const autoscan::Report& report) {
  Json out;
  out.text("{\"protocol\":1,\"sha256\":"); out.string({report.sha256.data(), report.sha256[0] ? report.sha256.size() : 0});
  out.text(",\"blake3\":"); out.string({report.blake3.data(), report.blake3[0] ? report.blake3.size() : 0});
  out.text(",\"ready\":"); out.text(report.ready() ? "true" : "false");
  out.text(",\"complete_enforcement_coverage_proven\":false,\"error\":"); out.string(report.error);
  out.text(",\"install_verifier\":"); out.string(report.installVerifier);
  out.text(",\"crx_download\":"); out.string(report.crxDownload);
  out.field("heads", report.heads); out.field("screened", report.screened); out.field("rejected", report.rejected);
  out.text(",\"gates\":["); bool first = true;
  for (auto& gate : report.gates) {
    if (!first) out.character(','); first = false;
    out.text("{\"compare\":"); out.number(gate.compare);
    out.field("rva", gate.rva); out.field("function", gate.function); out.field("affected", gate.affected);
    out.field("unaffected", gate.unaffected); out.field("affected_exit", gate.exit);
    out.field("kind", gate.kind); out.field("width", gate.width); out.field("decoded", gate.decoded);
    out.text(",\"free\":"); out.text(gate.freePredicate ? "true" : "false");
    out.text(",\"optional\":"); out.text(gate.optional ? "true" : "false");
    out.field("optional_kind", gate.optional);
    out.text(",\"stock\":"); out.hex(std::span(gate.stock).first(gate.width));
    out.text(",\"patch\":"); out.hex(std::span(gate.patch).first(gate.width));
    out.text(",\"fields\":[");
    for (size_t n = 0; n < gate.fields.size(); ++n) { if (n) out.character(','); out.number(gate.fields[n]); }
    out.text("]}");
  }
  out.text("],\"unresolved\":["); first = true;
  for (auto& issue : report.unresolved) {
    if (!first) out.character(','); first = false;
    out.text("{\"rva\":"); out.number(issue.rva); out.text(",\"reason\":"); out.string(issue.reason); out.character('}');
  }
  out.text("]}\n"); out.flush(); return out.ok;
}
void error(const char* message) { DWORD written; WriteFile(GetStdHandle(STD_ERROR_HANDLE), message, static_cast<DWORD>(strlen(message)), &written, nullptr); }
}
int wmain(int argc, wchar_t** argv) {
  if (argc != 2) { error("usage: mv2-scan.exe <chrome.dll>\n"); return 2; }
  HANDLE file = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  if (file == INVALID_HANDLE_VALUE) { error("cannot open binary\n"); return 2; }
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > ULONG_MAX) { CloseHandle(file); return 2; }
  HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  auto bytes = static_cast<const uint8_t*>(mapping ? MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) : nullptr);
  if (!bytes) { if (mapping) CloseHandle(mapping); CloseHandle(file); return 2; }
  auto report = autoscan::Discover({bytes, static_cast<size_t>(size.QuadPart)});
  bool written = reportJson(report);
  UnmapViewOfFile(bytes); CloseHandle(mapping); CloseHandle(file);
  return !written ? 2 : report.ready() ? 0 : 1;
}
