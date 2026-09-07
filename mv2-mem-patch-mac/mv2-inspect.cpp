// mv2-inspect.cpp — offline inspector for the macOS MV2 mem-patch.
//
// Reports whether a Chrome framework Mach-O matches a milestone in signatures.json
// and where the gate branches are, WITHOUT modifying anything or launching Chrome.
// install.sh --offline calls this. It reads the on-disk file, which the mem-patch
// deliberately leaves stock, so gates always read "stock" here — the point is to
// confirm the Chrome version is covered and to print the gate map.
//
// Built universal; the running (native) arch selects which slice/container it
// inspects — the same slice the dylib will patch in memory on this machine.
//
//   mv2-inspect <framework-macho> [signatures.json]
//
// Exit 0 if a milestone was located (full or partial), 1 otherwise, 2 on usage/read
// error. Uses only mv2_core.hpp (no Mach/ObjC), so it is host-portable.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mv2_core.hpp"

#if defined(__arm64__) || defined(__aarch64__)
static const uint32_t    kHostCpu       = mv2::MV2_CPU_ARM64;
static const std::string kHostContainer = "macho-arm64";
#elif defined(__x86_64__)
static const uint32_t    kHostCpu       = mv2::MV2_CPU_X86_64;
static const std::string kHostContainer = "macho-x64";
#else
#error "unsupported target architecture"
#endif

static std::vector<uint8_t> ReadFile(const std::string& path) {
  std::vector<uint8_t> out;
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) return out;
  struct stat st{};
  if (fstat(fd, &st) == 0 && st.st_size > 0) {
    out.resize((size_t)st.st_size);
    size_t off = 0;
    while (off < out.size()) {
      ssize_t got = read(fd, out.data() + off, out.size() - off);
      if (got <= 0) { out.clear(); break; }
      off += (size_t)got;
    }
  }
  close(fd);
  return out;
}

static std::string SelfDir(const char* argv0) {
  std::string p = argv0 ? argv0 : "";
  size_t s = p.find_last_of('/');
  return s == std::string::npos ? "." : p.substr(0, s);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: mv2-inspect <framework-macho> [signatures.json]\n");
    return 2;
  }
  std::string macho = argv[1];
  std::string sigPath = (argc >= 3) ? argv[2] : SelfDir(argv[0]) + "/signatures.json";

  std::vector<uint8_t> buf = ReadFile(macho);
  if (buf.empty()) {
    fprintf(stderr, "cannot read %s\n", macho.c_str());
    return 2;
  }
  std::vector<uint8_t> sig = ReadFile(sigPath);
  if (sig.empty()) {
    fprintf(stderr, "cannot read signatures: %s\n", sigPath.c_str());
    return 2;
  }

  mv2::HostSlice slice;
  if (!mv2::ParseMachO(buf.data(), buf.size(), kHostCpu, slice) || !slice.ok) {
    fprintf(stderr, "no %s slice in this Mach-O\n", kHostContainer.c_str());
    return 1;
  }

  std::vector<mv2::Milestone> milestones;
  try {
    mv2::JV doc = mv2::JParser(std::string((const char*)sig.data(), sig.size())).val();
    milestones = mv2::ParseMilestones(doc);
  } catch (...) {
    fprintf(stderr, "signatures.json is unparseable\n");
    return 2;
  }

  uint64_t scanStart = slice.sliceFileOffset + slice.textFileOff;
  uint64_t scanEnd = scanStart + slice.textSize;
  mv2::Milestone winner;
  std::vector<mv2::SiteHit> per;
  bool full = false;
  if (!mv2::Locate(buf.data(), buf.size(), scanStart, scanEnd, milestones,
                   kHostContainer, winner, per, full)) {
    printf("no milestone located (%s) — this Chrome version may not be in "
           "signatures.json yet\n", kHostContainer.c_str());
    return 1;
  }

  printf("milestone: %s  [%s, %s match]\n", winner.name.c_str(),
         kHostContainer.c_str(), full ? "full" : "partial");
  int n = 0;
  for (const auto& sh : per) {
    for (uint64_t off : sh.branchOffsets) {
      uint8_t cur[2] = {buf[off], off + 1 < buf.size() ? buf[off + 1] : (uint8_t)0};
      mv2::ApplyRes a = mv2::ComputeApply(sh.site.kind, cur);
      const char* state = a.isStock ? "stock" : a.isDone ? "already-patched" : "UNEXPECTED";
      printf("  %-28s file 0x%llX  %s\n", sh.site.name.c_str(),
             (unsigned long long)off, state);
      n++;
    }
  }
  printf("%d gate(s). (disk is inspected read-only; the dylib patches memory at "
         "launch — the on-disk file stays stock)\n", n);
  return 0;
}
