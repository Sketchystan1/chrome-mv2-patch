// mv2-mem-patch.mm — in-process Manifest V2 re-enabler for macOS Chrome.
//
// This is the macOS analogue of mv2-mem-patch-win/mv2-mem-patch.cpp (the Windows
// version.dll proxy). It is a .dylib that Chrome's main executable is made to load
// (install.sh injects an LC_LOAD_DYLIB and re-signs the app). Once loaded into the
// browser process it patches the MV2 gate branches in the *Google Chrome Framework*
// MEMORY image, leaving the framework file byte-for-byte stock on disk — so anything
// that hashes the on-disk framework (Widevine VMP) still sees Google's bytes.
//
// Why in-process at all: the sibling out-of-process launcher (task_for_pid +
// mach_vm_write) is blocked on production Chrome — task_for_pid is denied for a
// hardened, notarized, Google-signed target with no get-task-allow, and a cross-task
// write to a signed page triggers CS_KILL. A process patching its OWN memory needs no
// task port, and a VM_PROT_COPY (copy-on-write) reprotect detaches the page from the
// signed file mapping so the write is never re-validated. That is the whole trick.
//
// Flow:
//   1. constructor runs in every process our host executable spawns; it no-ops in
//      Chrome's child processes (they carry --type= and don't link us anyway).
//   2. In the browser process it scans the already-mapped images (dyld maps every
//      LC_LOAD_DYLIB dependency before any initializer runs, so the framework is
//      normally present already) and patches the framework. If the framework is not
//      mapped yet (Chrome dlopen'd it), a short background poll waits for it. No dyld
//      add-image callback is used, so there is no loader re-entrancy risk.
//   3. Gate location reuses mv2_core.hpp verbatim: map the STOCK on-disk framework,
//      ParseMachO the host slice, Locate the milestone from signatures.json, then
//      translate each branch file-offset to a runtime address and flip it in memory.
//
// signatures.json is read from the payload dir (Frameworks/mv2/ beside the dylib's
// MacOS/ home; see PayloadDir). No network (parity with the mac launchers); refresh
// signatures.json out of band and relaunch.

#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>
#include <dlfcn.h>
#include <crt_externs.h>
#include <cstdio>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "mv2_core.hpp"

// --------------------------------------------------------------------------- //
// Host arch. Built universal (-arch arm64 -arch x86_64); each slice compiles with
// its own macros and reads its own container from signatures.json.
#if defined(__arm64__) || defined(__aarch64__)
static const uint32_t    kHostCpu       = mv2::MV2_CPU_ARM64;
static const std::string kHostContainer = "macho-arm64";
#elif defined(__x86_64__)
static const uint32_t    kHostCpu       = mv2::MV2_CPU_X86_64;
static const std::string kHostContainer = "macho-x64";
#else
#error "unsupported target architecture (arm64 / x86_64 only)"
#endif

// Failure traces to stderr. Silent unless MV2_MEMPATCH_DEBUG is set. Chrome's
// stderr is empty on a normal (Finder/Spotlight) launch, so to see these, launch
// the executable from a terminal with MV2_MEMPATCH_DEBUG=1 (README shows how).
static bool DebugOn() {
  static int v = -1;
  if (v < 0) v = getenv("MV2_MEMPATCH_DEBUG") ? 1 : 0;
  return v == 1;
}
#define DBG(fmt, ...)                                                          \
  do {                                                                         \
    if (DebugOn())                                                             \
      fprintf(stderr, "[mv2patch] " fmt "\n", ##__VA_ARGS__);                  \
  } while (0)

// --------------------------------------------------------------------------- //
// Only the browser process patches. Chrome's children carry --type= (renderer,
// gpu-process, utility, …). They are separate executables and won't carry our
// load command, but this guard is cheap insurance and mirrors the Windows build.
static bool IsBrowserProcess() {
  int* argcp = _NSGetArgc();
  char*** argvp = _NSGetArgv();
  if (!argcp || !argvp || !*argvp) return true;  // unknown → assume browser
  int argc = *argcp;
  char** argv = *argvp;
  for (int i = 1; i < argc; i++)
    if (argv[i] && strncmp(argv[i], "--type=", 7) == 0) return false;
  return true;
}

// The gate lives in "<Name> Framework.framework/Versions/<v>/<Name> Framework".
// The leading space before "Framework.framework" is specific to Chrome-family
// bundles (Google Chrome / Chromium / etc.) and never matches an Apple framework.
static bool IsChromeFramework(const char* path) {
  return path && strstr(path, " Framework.framework/Versions/") != nullptr;
}

// Directory containing this dylib.
static std::string SelfDir() {
  Dl_info info{};
  if (dladdr((const void*)&SelfDir, &info) && info.dli_fname) {
    std::string p = info.dli_fname;
    size_t s = p.find_last_of('/');
    if (s != std::string::npos) return p.substr(0, s);
  }
  return ".";
}

static bool FileExists(const std::string& p) {
  struct stat st{};
  return stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

// Where signatures.json / config.txt live. The dylib installs to Contents/MacOS/
// (so the injected LC_LOAD_DYLIB path stays short), but its sidecars stay in
// Contents/Frameworks/mv2/ — never a non-code file in MacOS/. Prefer whichever
// candidate actually holds them; fall back to the Frameworks/mv2 sibling so the
// debug message points at the intended location. A co-located layout (dylib +
// json in one dir, e.g. a test bundle) still works via the SelfDir candidate.
static std::string PayloadDir() {
  std::string self = SelfDir();
  std::string sibling = self + "/../Frameworks/mv2";
  for (const std::string& d : {self, sibling})
    if (FileExists(d + "/signatures.json") || FileExists(d + "/config.txt"))
      return d;
  return sibling;
}

static std::vector<uint8_t> ReadFileBytes(const std::string& path) {
  std::vector<uint8_t> out;
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) return out;
  struct stat st{};
  if (fstat(fd, &st) == 0 && st.st_size > 0 && st.st_size < (1LL << 30)) {
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

// Read + parse signatures.json (from the payload dir). An optional config.txt in
// the same dir may name a different local signatures path.
static std::vector<mv2::Milestone> LoadSignatures() {
  std::string dir = PayloadDir();
  std::string sigPath = dir + "/signatures.json";

  std::vector<uint8_t> cfg = ReadFileBytes(dir + "/config.txt");
  if (!cfg.empty()) {
    std::string text((const char*)cfg.data(), cfg.size());
    size_t i = 0;
    while (i < text.size()) {
      size_t nl = text.find('\n', i);
      std::string line = text.substr(i, (nl == std::string::npos ? text.size() : nl) - i);
      i = (nl == std::string::npos) ? text.size() : nl + 1;
      size_t a = line.find_first_not_of(" \t\r");
      if (a == std::string::npos || line[a] == '#') continue;
      size_t eq = line.find('=', a);
      if (eq == std::string::npos) continue;
      std::string key = line.substr(a, eq - a);
      size_t kb = key.find_last_not_of(" \t\r");
      if (kb != std::string::npos) key = key.substr(0, kb + 1);
      if (key != "signatures") continue;
      std::string val = line.substr(eq + 1);
      size_t vb = val.find_first_not_of(" \t\r");
      if (vb != std::string::npos) val = val.substr(vb);
      std::string s;
      // A local path only; an https URL (or "auto") means "read the local file".
      if (mv2::TomlStr(val, s) && !s.empty() &&
          s.compare(0, 8, "https://") != 0 && s.compare(0, 7, "http://") != 0) {
        sigPath = (s[0] == '/') ? s : dir + "/" + s;
      }
    }
  }

  std::vector<uint8_t> bytes = ReadFileBytes(sigPath);
  if (bytes.empty()) {
    DBG("no signatures.json in the payload dir (%s)", sigPath.c_str());
    return {};
  }
  try {
    mv2::JV doc = mv2::JParser(std::string((const char*)bytes.data(), bytes.size())).val();
    return mv2::ParseMilestones(doc);
  } catch (...) {
    DBG("signatures.json unparseable");
    return {};
  }
}

// Flip every located gate in the live framework image. imageLoadAddr is the
// framework's mach_header address (== __TEXT load address), from dyld.
static int ApplyInProcess(const mv2::HostSlice& slice,
                          const std::vector<mv2::SiteHit>& per,
                          uint64_t imageLoadAddr) {
  const uintptr_t pageSize = (uintptr_t)getpagesize();
  int patched = 0, alreadyDone = 0;
  for (const auto& sh : per) {
    for (uint64_t branchFileOff : sh.branchOffsets) {
      uint64_t rt = mv2::RuntimeAddr(slice, branchFileOff, imageLoadAddr);
      uint8_t* addr = (uint8_t*)(uintptr_t)rt;
      uint8_t cur[2] = {addr[0], addr[1]};
      mv2::ApplyRes a = mv2::ComputeApply(sh.site.kind, cur);
      if (a.isDone) { alreadyDone++; continue; }
      if (!a.isStock) { DBG("unexpected gate bytes — skipped"); continue; }

      // VM_PROT_COPY forces a private copy-on-write of the signed, file-backed
      // page, so the write is not re-validated against the code signature (the
      // exact thing the cross-task route could not do → CS_KILL). Then restore
      // R|X. RW-not-RWX keeps us off the "unsigned executable memory" path.
      uintptr_t pageBase = (uintptr_t)addr & ~(pageSize - 1);
      mach_vm_size_t span = pageSize;
      if ((uintptr_t)addr + a.patch.size() > pageBase + pageSize) span = pageSize * 2;
      if (mach_vm_protect(mach_task_self(), (mach_vm_address_t)pageBase, span, FALSE,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        DBG("mach_vm_protect(RW,COPY) failed @%p", addr);
        continue;
      }
      memcpy(addr, a.patch.data(), a.patch.size());
      mach_vm_protect(mach_task_self(), (mach_vm_address_t)pageBase, span, FALSE,
                      VM_PROT_READ | VM_PROT_EXECUTE);
      sys_icache_invalidate(addr, a.patch.size());
      patched++;
    }
  }
  DBG("gates: %d patched, %d already done", patched, alreadyDone);
  return patched + alreadyDone;
}

// Map the STOCK on-disk framework, locate the milestone, patch the live image.
static void PatchFrameworkImage(const char* path, uint64_t imageLoadAddr) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) { DBG("cannot open framework on disk"); return; }
  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return; }
  size_t n = (size_t)st.st_size;
  const uint8_t* buf = (const uint8_t*)mmap(nullptr, n, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (buf == MAP_FAILED) { DBG("cannot mmap framework"); return; }

  mv2::HostSlice slice;
  if (mv2::ParseMachO(buf, n, kHostCpu, slice) && slice.ok) {
    std::vector<mv2::Milestone> milestones = LoadSignatures();
    if (milestones.empty()) {
      DBG("no usable signatures");
    } else {
      uint64_t scanStart = slice.sliceFileOffset + slice.textFileOff;
      uint64_t scanEnd = scanStart + slice.textSize;
      mv2::Milestone winner;
      std::vector<mv2::SiteHit> per;
      bool full = false;
      if (mv2::Locate(buf, n, scanStart, scanEnd, milestones, kHostContainer,
                      winner, per, full)) {
        int touched = ApplyInProcess(slice, per, imageLoadAddr);
        DBG("MV2 extensions ENABLED - %s, %d gate(s) patched in memory "
            "(disk stays stock) [%s match]",
            winner.name.c_str(), touched, full ? "full" : "partial");
      } else {
        DBG("no milestone matched this framework build");
      }
    }
  } else {
    DBG("framework has no %s slice", kHostContainer.c_str());
  }
  munmap((void*)buf, n);
}

// Scan currently-mapped images for the Chrome framework and patch it. Returns
// true once the framework has been handled (patched, or found already-patched),
// so callers can stop looking. Safe to call from an initializer or a worker
// thread — it uses only the public dyld enumeration API, never a dyld callback.
static std::atomic<bool> gHandled{false};

static bool TryPatchNow() {
  if (gHandled.load()) return true;
  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; i++) {
    const char* name = _dyld_get_image_name(i);
    if (!IsChromeFramework(name)) continue;
    const struct mach_header* mh = _dyld_get_image_header(i);
    if (!mh) return false;
    PatchFrameworkImage(name, (uint64_t)mh);
    gHandled.store(true);
    return true;
  }
  return false;  // framework not mapped yet
}

// Fallback for the case where Chrome dlopen's the framework after our initializer
// ran: poll briefly (no dyld add-image callback → no loader re-entrancy). The gate
// is evaluated lazily (when extensions/policies load), long after the framework
// maps, so a short poll always wins the race.
static void* PollThread(void*) {
  for (int i = 0; i < 600; i++) {  // ~15 s max (600 × 25 ms)
    if (TryPatchNow()) break;
    usleep(25 * 1000);
  }
  return nullptr;
}

__attribute__((constructor)) static void mv2_init() {
  if (!IsBrowserProcess()) return;
  if (TryPatchNow()) return;  // framework already mapped (the normal case)
  pthread_t t;
  if (pthread_create(&t, nullptr, PollThread, nullptr) == 0)
    pthread_detach(t);
}
