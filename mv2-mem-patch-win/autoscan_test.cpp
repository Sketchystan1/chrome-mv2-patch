// Test-only checks use made-up browser code to verify recognition, refusal and undoing failed edits.
// Edits stay in this test's memory and temporary cache folder; this test does not launch a browser.
#include "autoscan_runtime.h"
#include "solver.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <wincrypt.h>

using Bytes = std::vector<uint8_t>;
static unsigned checks = 0;
static void check(bool ok, const char* why) {
  ++checks;
  if (!ok) throw std::runtime_error(why);
}
// Turn readable hexadecimal examples into test bytes; these are invented inputs, not downloaded code.
static Bytes hex(const char* text) {
  Bytes out;
  auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  for (; *text; text += 2) out.push_back(static_cast<uint8_t>((digit(text[0]) << 4) | digit(text[1])));
  return out;
}
static void replace(Bytes& bytes, const char* before, const char* after) {
  auto a = hex(before), b = hex(after);
  auto it = std::search(bytes.begin(), bytes.end(), a.begin(), a.end());
  if (it == bytes.end() || a.size() != b.size()) throw std::runtime_error("bad test fixture replacement");
  std::copy(b.begin(), b.end(), it);
}
static const Bytes freeCode = hex("31c083f9027f1f83fa08771ab90a0100000fa3d173104183f8050f95c14183f80a0f95c020c8c3");
static const Bytes memberCode = hex("837a50027f37488b8a280200008b415080ba0802000000750b8b898800000083f901750f83f8050f95c183f80a0f95c020c8c383f90874ec83f90374e731c0ebf1");
static const Bytes invertedCode = hex("837a50027e0331c0c3488b82280200008b485080ba080200000075198b908800000031c083fa0877df41b80a010000410fa3d073d383f9050f95c283f90a0f95c020d0ebc3");

template<class T> static void put(Bytes& bytes, size_t offset, T value) { memcpy(bytes.data() + offset, &value, sizeof value); }
static Bytes image(const Bytes& leaf = freeCode, const Bytes& member = memberCode, const Bytes& callee = {}) {
  Bytes bytes(0x800);
  put<uint16_t>(bytes, 0, 0x5A4D); put<uint32_t>(bytes, 0x3C, 0x80);
  put<uint32_t>(bytes, 0x80, 0x4550); put<uint16_t>(bytes, 0x84, 0x8664);
  put<uint16_t>(bytes, 0x86, 1); put<uint16_t>(bytes, 0x94, 0xF0);
  put<uint16_t>(bytes, 0x98, 0x20B); put<uint32_t>(bytes, 0xD0, 0x2000); put<uint32_t>(bytes, 0xD4, 0x400);
  put<uint32_t>(bytes, 0x104, 16);
  memcpy(bytes.data() + 0x188, ".text", 5);
  put<uint32_t>(bytes, 0x190, 0x200); put<uint32_t>(bytes, 0x194, 0x1000);
  put<uint32_t>(bytes, 0x198, 0x200); put<uint32_t>(bytes, 0x19C, 0x400);
  put<uint32_t>(bytes, 0x1AC, 0x60000020);
  std::fill(bytes.begin() + 0x400, bytes.begin() + 0x600, 0xCC);
  std::copy(leaf.begin(), leaf.end(), bytes.begin() + 0x440);
  std::copy(member.begin(), member.end(), bytes.begin() + 0x500);
  std::copy(callee.begin(), callee.end(), bytes.begin() + 0x5C0);
  if (!member.empty()) {
    put<uint16_t>(bytes, 0x86, 2);
    memcpy(bytes.data() + 0x1B0, ".pdata", 6);
    put<uint32_t>(bytes, 0x120, 0x1800); put<uint32_t>(bytes, 0x124, 12);
    put<uint32_t>(bytes, 0x1B8, 0x200); put<uint32_t>(bytes, 0x1BC, 0x1800);
    put<uint32_t>(bytes, 0x1C0, 0x200); put<uint32_t>(bytes, 0x1C4, 0x600);
    put<uint32_t>(bytes, 0x1D4, 0x40000040);
    put<uint32_t>(bytes, 0x600, 0x1100);
    put<uint32_t>(bytes, 0x604, static_cast<uint32_t>(0x1100 + member.size()));
    put<uint32_t>(bytes, 0x608, 0x180C); bytes[0x60C] = 1;
  }
  return bytes;
}

static const Bytes providerCode = hex("4889d6f6865402000008750c4889f1e82c00000084c0740331c0c341c70100010000b001c3");
// Broken or overlapping instructions must be refused rather than guessed.
static void programDecodeTests() {
  autoscan::Program program;
  for (unsigned size : {255u, 1u, 64u, 2u, 128u, 4u, 31u, 16u}) {
    Bytes code(size, 0x90); code.back() = 0xc3;
    auto bytes = image({}, code); autoscan::PeImage pe(bytes);
    check(program.decode(pe, {0x1100, 0x1100 + size}) && program.nodes.size() == size,
          "reused occupancy storage clears every byte in short and changing ranges");
  }
  auto bytes = image({}, hex("7501b801000000c3")); autoscan::PeImage overlap(bytes);
  check(!program.decode(overlap, {0x1100, 0x1108}), "a conditional branch into an immediate still declines");
  bytes = image({}, {}); bytes.resize(0x10400);
  put<uint32_t>(bytes, 0x190, 65536); put<uint32_t>(bytes, 0x198, 65536); put<uint32_t>(bytes, 0xd0, 0x12000);
  auto code = hex("0f85f9ff0000c3"); std::copy(code.begin(), code.end(), bytes.begin() + 0x400); bytes.back() = 0xc3;
  autoscan::PeImage full(bytes);
  check(full.valid() && program.decode(full, {0x1000, 0x11000}) && program.nodes.size() == 3,
        "the 64 KiB occupancy limit includes the last byte and preserves branch ownership");
  check(!program.decode(full, {0x1000, 0x11001}), "ranges beyond the occupancy limit still decline");
}
static void argumentTests() {
  auto fromArgument = [](const Bytes& code) {
    auto bytes = image({}, code);
    autoscan::PeImage pe(bytes); autoscan::Program program;
    check(program.build(pe, {0x1100, 0x1100 + static_cast<uint32_t>(code.size())}), "argument fixture decodes completely");
    return program.fromArgument(0x1100 + static_cast<uint32_t>(code.size()) - 1, 0, 2);
  };
  auto spill = [&](const char* middle, const char* before = "") {
    auto code = hex("4883ec68"), prefix = hex(before), body = hex(middle);
    code.insert(code.end(), prefix.begin(), prefix.end());
    auto store = hex("4889542428"); code.insert(code.end(), store.begin(), store.end());
    code.insert(code.end(), body.begin(), body.end());
    auto reload = hex("488b442428c3"); code.insert(code.end(), reload.begin(), reload.end());
    return code;
  };
  check(fromArgument(hex("4889d0c3")) && !fromArgument(hex("89d0c3")), "argument copies must preserve pointer width");
  check(fromArgument(spill("e800000000")), "private local spill survives an ABI call");
  check(fromArgument(spill("488d7c24400f290748897708e800000000")), "disjoint SIMD and integer stores preserve a spill");
  check(fromArgument(hex("4883ec6885c974074889542428eb054889542428488b442428c3")), "every predecessor can save the same argument");
  check(!fromArgument(hex("4883ec6885c974074889542428eb0548894c2428488b442428c3")), "conflicting predecessor stores decline");
  check(!fromArgument(hex("4883ec6885c974054889542428488b442428c3")), "a path without a store declines");
  for (const char* middle : {
      "48894c2428", "c744242c01000000", "c644242701", "0f29442420", "f30f11442428", "f0ff4c2428",
      "488b442440488910", "4883ec08", "4883e4f0", "488d4c2428e800000000",
      "488d7c24404883ef18488907", "488d4c24404883e120e800000000", "4889540428"}) {
    // The byte just before the slot is disjoint; every other case destroys or exposes it.
    check(fromArgument(spill(middle)) == (std::string_view(middle) == "c644242701"), "overwrites, aliases and unsupported stack changes decline");
  }
  check(!fromArgument(spill("e800000000", "488d4c2428")), "an address exposed before the spill still declines");
  check(!fromArgument(spill("e800000000", "4889e1")), "escaping the whole frame before the spill declines");
  check(!fromArgument(spill("e800000000", "5459")), "push/pop cannot conceal an escaped frame address");
  check(!fromArgument(spill("480f44cce800000000")), "conditional frame-address copies decline");
  check(!fromArgument(hex("4883ec684889542418e800000000488b442418c3")), "callee shadow space cannot preserve a spill across calls");
  check(!fromArgument(hex("4889542428488b442428c3")), "caller-owned stack arguments are not private locals");
}
static Bytes providerImage(const Bytes& method = providerCode) {
  Bytes bytes = image(freeCode, memberCode, hex("b001c3"));
  bytes.resize(0xA00);
  put<uint16_t>(bytes, 0x86, 3); put<uint64_t>(bytes, 0xB0, 0x180000000);
  memcpy(bytes.data() + 0x1D8, ".rdata", 6);
  put<uint32_t>(bytes, 0x1E0, 0x200); put<uint32_t>(bytes, 0x1E4, 0x1A00);
  put<uint32_t>(bytes, 0x1E8, 0x200); put<uint32_t>(bytes, 0x1EC, 0x800);
  put<uint32_t>(bytes, 0x1FC, 0x40000040);
  memcpy(bytes.data() + 0x980, "InstallVerifier", 16);
  auto getter = hex("488d05790b0000c3");
  std::copy(getter.begin(), getter.end(), bytes.begin() + 0x400);
  std::copy(method.begin(), method.end(), bytes.begin() + 0x580);
  put<uint64_t>(bytes, 0x800, 0x180001000); put<uint64_t>(bytes, 0x808, 0x180001180);
  put<uint32_t>(bytes, 0x124, 24);
  put<uint32_t>(bytes, 0x608, 0x1820);
  put<uint32_t>(bytes, 0x60C, 0x1180); put<uint32_t>(bytes, 0x610, static_cast<uint32_t>(0x1180 + method.size()));
  put<uint32_t>(bytes, 0x614, 0x1820); bytes[0x620] = 1;
  return bytes;
}
static void providerTests() {
  auto report = autoscan::Discover(providerImage());
  check(report.ready() && report.gates.size() == 3 && report.gates.back().optional && report.gates.back().rva == 0x118A,
        "provider name, vtable, argument and reason corroborate the optional store gate");
  for (const char* code : {"0f1005790b0000c3", "0f1105790b0000c3", "0f2805790b0000c3", "0f2905790b0000c3",
                          "f30f6f05780b0000c3", "f30f7f05780b0000c3", "660f6f05780b0000c3", "660f7f05780b0000c3",
                          "4c8d35790b0000c3", "664c8d35780b0000c3"}) {
    auto bytes = providerImage(); auto getter = hex(code);
    std::copy(getter.begin(), getter.end(), bytes.begin() + 0x400);
    auto found = autoscan::Discover(bytes);
    if (found.gates.size() != 3) std::cerr << code << ": " << found.installVerifier << '\n';
    check(found.gates.size() == 3, "RIP prescreen retains supported SIMD loads, stores and prefixed LEA");
  }
  auto method = providerCode; replace(method, "54020000", "a4030000");
  check(autoscan::Discover(providerImage(method)).gates.size() == 3, "creation flags offset is inferred");
  method = providerCode;
  auto unrelated = hex("0f57c00f294424104d0f42c548634004f00fc144241083c804");
  method.insert(method.begin() + 3, unrelated.begin(), unrelated.end());
  replace(method, "e82c000000", "e813000000");
  check(autoscan::Discover(providerImage(method)).gates.size() == 3, "SIMD, CMOV, MOVSXD, OR and atomic updates preserve unrelated argument registers");
  method = hex("4889d6f68654020000080f850c0000004889f1e82800000084c0740331c0c341c70100010000b001c3");
  report = autoscan::Discover(providerImage(method));
  check(report.ready() && report.gates.back().optional && report.gates.back().width == 6,
        "optional near decision preserves its existing continuation");
  auto tiny = providerImage();
  auto noPadding = hex("90b001c3"); std::copy(noPadding.begin(), noPadding.end(), tiny.begin() + 0x42F);
  put<uint64_t>(tiny, 0x808, 0x180001030); put<uint64_t>(tiny, 0x810, 0x180001180);
  check(autoscan::Discover(tiny).gates.size() == 3, "unrelated tiny virtual methods do not end the provider vtable");
  for (unsigned test = 0; test < 8; ++test) {
    auto bytes = providerImage();
    if (test == 0) replace(bytes, "4889d6", "4889ce");
    if (test == 1) replace(bytes, "41c70100010000", "41c70100020000");
    if (test == 2) replace(bytes, "84c07403", "84c07503");
    if (test == 3) put<uint64_t>(bytes, 0x800, 0);
    if (test == 4) {
      auto duplicate = providerCode; replace(duplicate, "e82c000000", "e82c010000");
      std::copy(duplicate.begin(), duplicate.end(), bytes.begin() + 0x480);
      put<uint64_t>(bytes, 0x810, 0x180001080);
    }
    if (test == 5) for (unsigned n = 1; n <= 32; ++n) put<uint64_t>(bytes, 0x800 + n * 8, 0x180001180);
    if (test == 6) bytes[0x980] = 'X';
    if (test == 7) {
      method = hex("4889d6f6865402000008750e4889f1e82c00000031c084c0740331c0c341c70100010000b001c3");
      bytes = providerImage(method);
    }
    report = autoscan::Discover(bytes);
    check(report.ready() && report.gates.size() == 2, "unverified or ambiguous optional gates leave valid core gates intact");
  }
}

static const Bytes downloadCode = hex("4883ec58e8c7ffffff84c0740f488b442430c7800802000002000000488b4c2430488d542428e8d5feffff4883c458c3");
static Bytes crxImage() {
  auto bytes = providerImage(); bytes.resize(0x1000);
  std::copy_n(bytes.begin() + 0x800, 0x200, bytes.begin() + 0xE00);
  std::copy_n(bytes.begin() + 0x600, 0x200, bytes.begin() + 0xC00);
  std::fill(bytes.begin() + 0x600, bytes.begin() + 0xC00, 0xCC);
  put<uint32_t>(bytes, 0x190, 0x800); put<uint32_t>(bytes, 0x198, 0x800);
  put<uint32_t>(bytes, 0x1C4, 0xC00); put<uint32_t>(bytes, 0x1EC, 0xE00);
  memcpy(bytes.data() + 0xE40, "apps-gallery-url", 17);
  auto installer = hex("4889ce83b908020000007407e8af000000eb1be8b8000000488d15210800004889c1e8a900000089c1e8b2000000488d5c24204889d94889fa4189c0e88f000000c3");
  std::copy(installer.begin(), installer.end(), bytes.begin() + 0x600);
  std::copy(downloadCode.begin(), downloadCode.end(), bytes.begin() + 0x700);
  auto zero = hex("31c0c3"), two = hex("b802000000c3");
  std::copy(zero.begin(), zero.end(), bytes.begin() + 0x6C0);
  bytes[0x6D0] = 0xC3;
  std::copy(two.begin(), two.end(), bytes.begin() + 0x6E0);
  put<uint32_t>(bytes, 0x124, 48);
  put<uint32_t>(bytes, 0xC08, 0x1840); put<uint32_t>(bytes, 0xC14, 0x1840);
  put<uint32_t>(bytes, 0xC18, 0x1200); put<uint32_t>(bytes, 0xC1C, 0x1200 + static_cast<uint32_t>(installer.size()));
  put<uint32_t>(bytes, 0xC20, 0x1840);
  put<uint32_t>(bytes, 0xC24, 0x1300); put<uint32_t>(bytes, 0xC28, 0x1300 + static_cast<uint32_t>(downloadCode.size()));
  put<uint32_t>(bytes, 0xC2C, 0x1840); bytes[0xC40] = 1;
  return bytes;
}
static void crxTests() {
  auto report = autoscan::Discover(crxImage());
  check(report.ready() && report.gates.size() == 4 && report.gates.back().optional == autoscan::CrxDownload &&
        report.gates.back().rva == 0x130B && report.gates.back().patch[0] == 0x90,
        "download gate links the allow-reason field, normal CRX3 format and installer argument");
  auto prefixed = crxImage(); memcpy(prefixed.data() + 0xF50, "ms-apps-gallery-url", 20);
  check(autoscan::Discover(prefixed).gates.size() == 4, "a prefixed gallery switch is not a second standalone literal");
  auto delayed = crxImage();
  auto installerEnd = autoscan::ReadInsn<uint32_t>(delayed.data() + 0xC1C);
  auto constructor = hex("488d5c2420");
  auto insertion = std::search(delayed.begin() + 0x600, delayed.begin() + 0x680, constructor.begin(), constructor.end());
  check(insertion != delayed.begin() + 0x680, "find the installer constructor fixture");
  auto offset = insertion - delayed.begin();
  std::move_backward(insertion, delayed.begin() + 0x600 + installerEnd - 0x1200, delayed.begin() + 0x60C + installerEnd - 0x1200);
  std::fill_n(delayed.begin() + offset, 12, uint8_t{0x90}); put<uint32_t>(delayed, 0xC1C, installerEnd + 12);
  check(autoscan::Discover(delayed).gates.size() == 4, "longer constructor initialization preserves the CRX3 format argument");
  auto overwrite = hex("b801000000"); std::copy(overwrite.begin(), overwrite.end(), delayed.begin() + offset);
  check(autoscan::Discover(delayed).gates.size() == 3, "constructor setup cannot overwrite the verifier format");
  auto registered = crxImage();
  auto method = hex("4883ec58e8c7ffffff84c0740f488b442430c7800802000002000000488b5c2430e8aaffffff4889d9488d542428e8cdfeffff4883c458c3");
  std::copy(method.begin(), method.end(), registered.begin() + 0x700);
  put<uint32_t>(registered, 0xC28, 0x1300 + static_cast<uint32_t>(method.size()));
  check(autoscan::Discover(registered).gates.size() == 4, "a nonvolatile installer copy survives intervening calls");
  registered[0x728] = 0xC1;
  check(autoscan::Discover(registered).gates.size() == 3, "a volatile installer copy does not survive a call");
  auto shifted = crxImage();
  replace(shifted, "83b90802000000", "83b9b802000000");
  replace(shifted, "c7800802000002000000", "c780b802000002000000");
  check(autoscan::Discover(shifted).gates.size() == 4, "CRX installer field is inferred instead of pinned");
  auto nearImage = crxImage();
  method = hex("4883ec58e8c7ffffff84c00f840f000000488b442430c7800802000002000000488b4c2430488d542428e8d1feffff4883c458c3");
  std::copy(method.begin(), method.end(), nearImage.begin() + 0x700);
  put<uint32_t>(nearImage, 0xC28, 0x1300 + static_cast<uint32_t>(method.size()));
  report = autoscan::Discover(nearImage);
  check(report.gates.size() == 4 && report.gates.back().width == 6 &&
        std::all_of(report.gates.back().patch.begin(), report.gates.back().patch.end(), [](auto b) { return b == 0x90; }),
        "near download gate selects the same allow-reason store");
  auto referenceCount = crxImage(); replace(referenceCount, "488d542428", "f0ff490890");
  check(autoscan::Discover(referenceCount).gates.size() == 4, "reference-count updates preserve the installer frame");
  auto stackRead = crxImage(); replace(stackRead, "488d542428", "4c03742430");
  check(autoscan::Discover(stackRead).gates.size() == 4, "ADD may read the installer slot without overwriting it");
  replace(stackRead, "4c03742430", "4803642430");
  check(autoscan::Discover(stackRead).gates.size() == 3, "ADD that changes RSP cannot preserve the installer frame");
  auto aliasImage = crxImage(), aliasCode = downloadCode;
  overwrite = hex("4889e248894230");
  aliasCode.erase(aliasCode.begin() + 0x21, aliasCode.begin() + 0x26);
  aliasCode.insert(aliasCode.begin() + 0x21, overwrite.begin(), overwrite.end());
  put<int32_t>(aliasCode, 0x29, 0x1200 - 0x132D);
  std::copy(aliasCode.begin(), aliasCode.end(), aliasImage.begin() + 0x700);
  put<uint32_t>(aliasImage, 0xC28, 0x1300 + static_cast<uint32_t>(aliasCode.size()));
  check(autoscan::Discover(aliasImage).gates.size() == 3, "aliased writes cannot replace the installer stack slot");
  for (unsigned test = 0; test < 13; ++test) {
    auto bytes = crxImage();
    if (test == 0) bytes[0xE40] = 'X';
    if (test == 1) { bytes[0x6C0] = 0xB0; bytes[0x6C1] = 1; }
    if (test == 2) replace(bytes, "c7800802000002000000", "c7800802000003000000");
    if (test == 3) replace(bytes, "c7800802000002000000", "c7800c02000002000000");
    if (test == 4) replace(bytes, "488b442430", "488b442438");
    if (test == 5) replace(bytes, "84c0740f", "84c0750f");
    if (test == 6) replace(bytes, "84c0740f", "84c07410");
    if (test == 7) replace(bytes, "e8d5feffff", "e8a5ffffff");
    if (test == 8) replace(bytes, "83b90802000000", "83ba0802000000");
    if (test == 9) {
      auto duplicate = downloadCode;
      put<int32_t>(duplicate, 5, 0x12D0 - 0x1389); put<int32_t>(duplicate, 0x27, 0x1200 - 0x13AB);
      std::copy(duplicate.begin(), duplicate.end(), bytes.begin() + 0x780);
      put<uint32_t>(bytes, 0x124, 60);
      put<uint32_t>(bytes, 0xC30, 0x1380); put<uint32_t>(bytes, 0xC34, 0x13B0); put<uint32_t>(bytes, 0xC38, 0x1840);
    }
    if (test == 10) replace(bytes, "488d542428", "4883ec0890");
    if (test == 11) replace(bytes, "488d542428", "f0ff4c2430");
    if (test == 12) replace(bytes, "488d542428", "4889442430");
    report = autoscan::Discover(bytes);
    check(report.ready() && report.gates.size() == 3 && report.gates.back().optional == autoscan::InstallVerifier,
          "unknown or ambiguous download layouts preserve core and InstallVerifier gates");
  }
}

static Bytes edgeImage(bool zeroGuard = false) {
  auto bytes = crxImage();
  std::fill_n(bytes.begin() + 0x440, freeCode.size(), uint8_t{0xCC});
  std::fill_n(bytes.begin() + 0x500, memberCode.size(), uint8_t{0xCC});
  put<uint32_t>(bytes, 0x108, 0x1B00); put<uint32_t>(bytes, 0x10C, sizeof(IMAGE_EXPORT_DIRECTORY));
  put<uint32_t>(bytes, 0xF0C, 0x1B40); memcpy(bytes.data() + 0xF40, "msedge.dll", 11);
  memcpy(bytes.data() + 0xF50, "ms-apps-gallery-url", 20);
  auto method = hex("4883ec284889d74c89c685c00f850000000031c04883c428c3");
  auto cold = hex("4889f9e80000000084c00f8500000000c70600010000b001e900000000");
  auto helper = hex("564883ec284889cef68654020000080f850000000031c04883c4285ec3");
  auto verified = hex("b0014883c4285ec3");
  put<int32_t>(method, 14, 0x1440 - 0x1192);
  put<int32_t>(cold, 4, 0x14C0 - 0x1448); put<int32_t>(cold, 12, 0x1192 - 0x1450); put<int32_t>(cold, 25, 0x1194 - 0x145D);
  if (zeroGuard) {
    cold = hex("4889f9e87800000084c00f8405000000e900000000c70600010000b001e900000000");
    put<int32_t>(cold, 17, 0x1192 - 0x1455); put<int32_t>(cold, 30, 0x1194 - 0x1462);
  }
  put<int32_t>(helper, 17, 0x1520 - 0x14D5);
  std::fill_n(bytes.begin() + 0x580, 0x80, uint8_t{0xCC});
  std::copy(method.begin(), method.end(), bytes.begin() + 0x580);
  std::copy(cold.begin(), cold.end(), bytes.begin() + 0x840);
  std::copy(helper.begin(), helper.end(), bytes.begin() + 0x8C0);
  std::copy(verified.begin(), verified.end(), bytes.begin() + 0x920);
  put<uint32_t>(bytes, 0xC10, 0x1180 + static_cast<uint32_t>(method.size()));
  for (unsigned n = 0; n < 4; ++n) put<uint32_t>(bytes, 0xC08 + n * 12, 0x18F0);
  put<uint32_t>(bytes, 0x124, 84); bytes[0xCF0] = 1;
  for (auto entry : {std::array<uint32_t, 4>{4, 0x1440, 0x1440 + static_cast<uint32_t>(cold.size()), 0x1880},
                     std::array<uint32_t, 4>{5, 0x14C0, 0x14C0 + static_cast<uint32_t>(helper.size()), 0x18F0},
                     std::array<uint32_t, 4>{6, 0x1520, 0x1520 + static_cast<uint32_t>(verified.size()), 0x1890}}) {
    for (unsigned n = 1; n < 4; ++n) put<uint32_t>(bytes, 0xC00 + entry[0] * 12 + (n - 1) * 4, entry[n]);
  }
  bytes[0xC80] = bytes[0xC90] = 0x21;
  put<uint32_t>(bytes, 0xC84, 0x1180); put<uint32_t>(bytes, 0xC88, 0x1180 + static_cast<uint32_t>(method.size())); put<uint32_t>(bytes, 0xC8C, 0x18F0);
  put<uint32_t>(bytes, 0xC94, 0x14C0); put<uint32_t>(bytes, 0xC98, 0x14C0 + static_cast<uint32_t>(helper.size())); put<uint32_t>(bytes, 0xC9C, 0x18F0);
  return bytes;
}
static void edgeTests() {
  auto report = autoscan::Discover(edgeImage());
  if (!report.ready()) std::cerr << report.error << "; " << report.installVerifier << "; " << report.crxDownload << '\n';
  check(report.ready() && report.gates.size() == 2 && !autoscan::MakePlan(report).status && report.unresolved.empty() && report.gates[1].rva == 0x144A,
        "provider vtable, chained disable reason, extension argument and true return identify Edge's shared store helper");
  report = autoscan::Discover(edgeImage(true));
  check(report.ready() && report.gates[1].rva == 0x144A && report.gates[1].patch[0] == 0x90,
        "the provider's zero-result branch selects its verified fall-through");
  for (unsigned test = 0; test < 14; ++test) {
    auto bytes = edgeImage();
    if (test == 0) bytes[0xF40] = 'x';
    if (test == 1) put<uint32_t>(bytes, 0x10C, 0);
    if (test == 2) replace(bytes, "84c0740f", "84c0750f");
    if (test == 3) bytes[0xF80] = 'X';
    if (test == 4) { put<uint32_t>(bytes, 0xC84, 0x1200); put<uint32_t>(bytes, 0xC88, 0x1243); }
    if (test == 5) { put<uint32_t>(bytes, 0xC94, 0x1180); put<uint32_t>(bytes, 0xC98, 0x1199); }
    if (test == 6) bytes[0x921] = 0;
    if (test == 7) replace(bytes, "c70600010000", "c70600020000");
    if (test == 8) replace(bytes, "4c89c6", "4889ce");
    if (test == 9) replace(bytes, "4889f9e8", "4889f1e8");
    if (test == 10) replace(bytes, "f6865402000008", "f6865402000010");
    if (test == 11) bytes[0x8D0] = 0x84;
    if (test == 12) bytes[0x926] = 0x58;
    if (test == 13) {
      std::move_backward(bytes.begin() + 0xC3C, bytes.begin() + 0xC54, bytes.begin() + 0xC60);
      put<uint32_t>(bytes, 0x124, 96); put<uint32_t>(bytes, 0xC3C, 0x1440);
      put<uint32_t>(bytes, 0xC40, 0x1440); put<uint32_t>(bytes, 0xC44, 0x1880);
    }
    check(!autoscan::Discover(bytes).ready(), "incomplete Edge gates, foreign unwind chains and changed verifier semantics decline");
  }
}
static DWORD WINAPI edgeStackTest(void*) {
  try { edgeTests(); return 0; }
  catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

// Pretend selected Windows calls fail so the test can check that earlier edits are undone.
static unsigned protectCalls = 0, failProtect = 0, flushCalls = 0, failFlush = 0;
static BOOL WINAPI testProtect(LPVOID address, SIZE_T size, DWORD mode, PDWORD old) {
  check(mode == PAGE_READWRITE || mode == PAGE_EXECUTE_READ, "code edits never request RWX");
  if (++protectCalls == failProtect) return FALSE;
  return VirtualProtect(address, size, mode, old);
}
static BOOL WINAPI testFlush(HANDLE process, LPCVOID address, SIZE_T size) {
  if (++flushCalls == failFlush) return FALSE;
  return FlushInstructionCache(process, address, size);
}
// This imitation of a loaded browser lives only in memory allocated by the test.
struct LiveImage {
  Bytes disk;
  autoscan::WirePlan plan;
  uint8_t* base = nullptr;
  explicit LiveImage(bool includeOptional = false, bool includeDownload = false) : disk(image()) {
    put<uint16_t>(disk, 0x86, 1); put<uint32_t>(disk, 0x120, 0); put<uint32_t>(disk, 0x124, 0);  // This layout uses aligned leaf bounds on two code pages.
    disk.resize(0x2800);
    std::fill(disk.begin() + 0x400, disk.begin() + 0x2600, 0xCC);
    std::copy(freeCode.begin(), freeCode.end(), disk.begin() + 0x440);
    std::copy(memberCode.begin(), memberCode.end(), disk.begin() + 0x1440);
    put<uint32_t>(disk, 0xD0, 0x4000);
    put<uint32_t>(disk, 0x190, 0x2200); put<uint32_t>(disk, 0x198, 0x2200);
    plan = autoscan::MakePlan(autoscan::Discover(disk));
    if (plan.status || plan.count != 2) throw std::runtime_error("bad application fixture");
    base = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!base) throw std::runtime_error("test allocation failed");
    memcpy(base, disk.data(), 0x400); memcpy(base + 0x1000, disk.data() + 0x400, 0x2200);
    DWORD old;
    if (!VirtualProtect(base, 0x4000, PAGE_EXECUTE_READ, &old)) throw std::runtime_error("test protection failed");
    if (includeOptional) {
      std::copy(providerCode.begin(), providerCode.end(), disk.begin() + 0x480);
      change(0x1080, providerCode.data(), providerCode.size());
      auto provider = autoscan::MakePlan(autoscan::Discover(providerImage()));
      plan.sites[2] = provider.sites[2]; plan.sites[2].rva = plan.offstoreRva = 0x108A; plan.count = 3;
    }
    if (includeDownload) {
      std::copy(downloadCode.begin(), downloadCode.end(), disk.begin() + 0x4C0);
      change(0x10C0, downloadCode.data(), downloadCode.size());
      auto download = autoscan::MakePlan(autoscan::Discover(crxImage()));
      if (download.status || !download.crxDownloadRva) throw std::runtime_error("bad download application fixture");
      for (unsigned n = 0; n < download.count; ++n) if (download.sites[n].rva == download.crxDownloadRva) {
        plan.sites[plan.count] = download.sites[n];
        plan.sites[plan.count++].rva = plan.crxDownloadRva = 0x10CB;
      }
    }
    if (includeOptional || includeDownload) {
      std::sort(plan.sites.begin(), plan.sites.begin() + plan.count, [](auto a, auto b) { return a.rva < b.rva; });
      plan.blake3 = autoscan::Blake3(disk);
    }
    protectCalls = flushCalls = failProtect = failFlush = 0;
  }
  ~LiveImage() { if (base) VirtualFree(base, 0, MEM_RELEASE); }
  autoscan::ApplyResult apply() {
    std::string_view reason;
    return autoscan::ApplyPlan({base, 0x4000}, autoscan::StockImage(disk), plan, reason, {testProtect, testFlush});
  }
  bool bytesMatch(bool patched) const {
    for (unsigned n = 0; n < plan.count; ++n) {
      const auto& site = plan.sites[n];
      if (memcmp(base + site.rva, (patched ? site.patch : site.stock).data(), site.width)) return false;
    }
    return true;
  }
  bool protectedAgain() const {
    for (unsigned n = 0; n < plan.count; ++n) {
      MEMORY_BASIC_INFORMATION info{};
      if (!VirtualQuery(base + plan.sites[n].rva, &info, sizeof info) || info.Protect != PAGE_EXECUTE_READ) return false;
    }
    return true;
  }
  void change(size_t offset, const uint8_t* data, size_t size) {
    DWORD old, ignored;
    if (!VirtualProtect(base + offset, size, PAGE_READWRITE, &old)) throw std::runtime_error("test write failed");
    memcpy(base + offset, data, size);
    VirtualProtect(base + offset, size, old, &ignored);
  }
};
static void applicationTests() {
  using Result = autoscan::ApplyResult;
  {
    LiveImage live;
    check(live.apply() == Result::applied && live.bytesMatch(true), "all decisions are applied");
    check(live.protectedAgain(), "original page protections restored");
    check(live.apply() == Result::alreadyApplied, "complete already-patched state is idempotent");
  }
  for (unsigned test = 0; test < 6; ++test) {
    LiveImage live;
    if (test == 0) ++live.plan.protocol;
    if (test == 1) live.plan.blake3[0] ^= 1;
    if (test == 2) live.plan.sites[0].patch[1] ^= 1;
    if (test == 3) live.plan.sites[1].rva = 0x31FF;
    if (test == 4) live.plan.count = 65;
    if (test == 5) live.plan.cacheHit = 2;
    check(live.apply() == Result::declined && protectCalls == 0, "invalid response declines before any protection change");
  }
  {
    LiveImage live; uint8_t nop = 0x90; live.change(0x1060, &nop, 1);
    check(live.apply() == Result::declined && live.bytesMatch(false), "unrelated live code change declines whole plan");
  }
  {
    LiveImage live; live.disk[0x300] ^= 1;
    check(live.apply() == Result::declined && protectCalls == 0, "identity includes file bytes outside the patch sites and .text");
  }
  {
    LiveImage live;
    put<uint32_t>(live.disk, 0xD0, 0x5000);
    live.plan = autoscan::MakePlan(autoscan::Discover(live.disk));
    std::string_view reason;
    check(autoscan::ApplyPlan({live.base, 0x5000}, autoscan::StockImage(live.disk), live.plan, reason, {testProtect, testFlush}) == Result::declined &&
          protectCalls == 0 && reason == "loaded image crosses allocation boundaries", "file image size cannot extend the actual allocation");
  }
  {
    LiveImage live; const auto& site = live.plan.sites[0]; live.change(site.rva, site.patch.data(), site.width);
    check(live.apply() == Result::declined && protectCalls == 0, "mixed patch state is rejected");
  }
  {
    LiveImage live; failProtect = 2;
    check(live.apply() == Result::declined && live.bytesMatch(false) && live.protectedAgain(), "second page failure leaves every decision stock");
  }
  {
    LiveImage live; failFlush = 1;
    check(live.apply() == Result::declined && live.bytesMatch(false) && live.protectedAgain(), "flush failure rolls back every decision");
  }
  {
    LiveImage live; failProtect = 3;
    check(live.apply() == Result::declined && live.bytesMatch(false) && live.protectedAgain(), "restore failure rolls back every decision");
  }
  {
    LiveImage live; failFlush = 1; failProtect = 5;
    check(live.apply() == Result::fatal, "irrecoverable rollback cannot be reported as a clean decline");
  }
}

static void relocationTests() {
  auto table = [](LiveImage& live, uint32_t page, uint16_t entry, uint32_t blockSize = 12) {
    put<uint16_t>(live.disk, 0x86, 2);
    std::copy_n(".reloc", 7, live.disk.begin() + 0x1B0);
    put<uint32_t>(live.disk, 0x1B8, 0x200); put<uint32_t>(live.disk, 0x1BC, 0x3800);
    put<uint32_t>(live.disk, 0x1C0, 0x200); put<uint32_t>(live.disk, 0x1C4, 0x2600);
    put<uint32_t>(live.disk, 0x1D4, 0x40000040);
    put<uint32_t>(live.disk, 0x130, 0x3800); put<uint32_t>(live.disk, 0x134, 12);
    put<uint32_t>(live.disk, 0x2600, page); put<uint32_t>(live.disk, 0x2604, blockSize);
    put<uint16_t>(live.disk, 0x2608, entry); put<uint16_t>(live.disk, 0x260A, 0);
    live.plan.blake3 = autoscan::Blake3(live.disk);
  };
  for (unsigned type : {IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64}) {
    LiveImage live;
    constexpr uint32_t rva = 0x10E0;
    uint64_t stock = 0x180001234, imageBase = 0x180000000;
    unsigned width = type == IMAGE_REL_BASED_HIGHLOW ? 4 : 8;
    put<uint64_t>(live.disk, 0xB0, imageBase);
    memcpy(live.disk.data() + 0x400 + rva - 0x1000, &stock, width);
    uint64_t relocated = stock + reinterpret_cast<uintptr_t>(live.base) - imageBase;
    live.change(rva, reinterpret_cast<uint8_t*>(&relocated), width);
    table(live, 0x1000, static_cast<uint16_t>((type << 12) | 0xE0));
    check(live.apply() == autoscan::ApplyResult::applied && live.protectedAgain(), "HIGHLOW and DIR64 relocation adjustments remain checked");
    check(live.apply() == autoscan::ApplyResult::alreadyApplied, "relocated code supports idempotent application");
  }
  for (unsigned test = 0; test < 6; ++test) {
    LiveImage live;
    if (test == 0) table(live, 0x5000, 0xF123); // Irrelevant unknown relocation types remain ignored.
    if (test == 1) table(live, 0xFFFFF000, 0xAFFF);
    if (test == 2) table(live, 0x5000, 0xF123, 6);
    if (test == 3) table(live, 0x5000, 0xF123, 14);
    if (test == 4) table(live, 0, 0xAFFF); // Crosses the first .text byte from the preceding page.
    if (test == 5) table(live, 0x1000, static_cast<uint16_t>(0xA000 | (live.plan.sites[0].rva - 0x1000 - 1)));
    auto result = live.apply();
    check(test < 2 ? result == autoscan::ApplyResult::applied : result == autoscan::ApplyResult::declined && protectCalls == 0,
          "skipping unrelated blocks retains block bounds and straddling relocation rejection");
  }
}

static void optionalPlanTests() {
  auto report = autoscan::Discover(providerImage());
  auto plan = autoscan::MakePlan(report);
  check(!plan.status && plan.offstoreRva == report.gates.back().rva, "IPC retains the verified optional site");
  report.gates[0].optional = autoscan::InstallVerifier;
  check(autoscan::MakePlan(report).status != 0, "multiple optional sites cannot form a plan");
  report.gates[0] = report.gates.back(); report.gates.count = 1;
  check(autoscan::MakePlan(report).status != 0, "an optional gate alone is not a core plan");
  {
    LiveImage live(true);
    check(live.apply() == autoscan::ApplyResult::applied && live.bytesMatch(true), "default application includes every verified core and off-store site");
    check(live.apply() == autoscan::ApplyResult::alreadyApplied, "automatic off-store application is idempotent");
  }
  {
    LiveImage live(true); const auto& site = live.plan.sites[1];
    live.change(site.rva, site.patch.data(), site.width);
    check(live.apply() == autoscan::ApplyResult::declined && protectCalls == 0, "an already patched optional gate cannot conceal a mixed plan");
  }
  for (unsigned test = 0; test < 5; ++test) {
    LiveImage live(true);
    if (test == 0) live.plan.offstoreRva = 0;
    if (test == 1) live.plan.offstoreRva = live.plan.sites[0].rva;
    if (test == 2) live.plan.offstoreRva = 0x1080;
    if (test == 3) live.plan.sites[1].stock[0] = 0x7F;
    if (test == 4) live.plan.sites[1].patch[1] ^= 1;
    check(live.apply() == autoscan::ApplyResult::declined && protectCalls == 0, "optional metadata and bytes are validated before any edits");
  }
  {
    LiveImage live(true, true);
    check(live.plan.offstoreRva && live.plan.crxDownloadRva && live.plan.count == 4 &&
          live.apply() == autoscan::ApplyResult::applied && live.bytesMatch(true), "both optional gates apply with the core plan");
    check(live.apply() == autoscan::ApplyResult::alreadyApplied, "download application is idempotent");
  }
  for (unsigned test = 0; test < 6; ++test) {
    LiveImage live(true, true);
    if (test == 0) live.plan.crxDownloadRva = 0;
    if (test == 1) live.plan.crxDownloadRva = live.plan.offstoreRva;
    if (test == 2) live.plan.crxDownloadRva = 0x1080;
    if (test == 3) live.plan.sites[2].patch[0] = 0xEB;
    if (test == 4) std::swap(live.plan.offstoreRva, live.plan.crxDownloadRva);
    if (test == 5) live.plan.protocol = 3;
    check(live.apply() == autoscan::ApplyResult::declined && protectCalls == 0, "download kind, direction and protocol are validated before any edits");
  }
  {
    LiveImage live(true, true); failFlush = 1;
    check(live.apply() == autoscan::ApplyResult::declined && live.bytesMatch(false) && live.protectedAgain(),
          "write failure rolls back download, off-store and core gates together");
  }
  for (unsigned test = 0; test < 4; ++test) {
    LiveImage live;
    live.disk = edgeImage(test == 3); put<uint32_t>(live.disk, 0xD0, 0x4000);
    live.plan = autoscan::MakePlan(autoscan::Discover(live.disk));
    live.change(0, live.disk.data(), 0x400); live.change(0x1000, live.disk.data() + 0x400, 0x800);
    live.change(0x1800, live.disk.data() + 0xC00, 0x200); live.change(0x1A00, live.disk.data() + 0xE00, 0x200);
    if (test == 1) { live.disk[0xF40] = 'x'; live.plan.blake3 = autoscan::Blake3(live.disk); }
    if (test == 2) failFlush = 1;
    check(test == 1 || test == 2 ? live.apply() == autoscan::ApplyResult::declined && live.bytesMatch(false) && live.protectedAgain() :
                 live.apply() == autoscan::ApplyResult::applied && live.bytesMatch(true),
          "optional-only application requires Edge identity and rolls back either gate on failure");
    check(!memcmp(live.base + 0x14CF, live.disk.data() + 0x8CF, 6), "Edge source checks never patch shared store detection");
    if (!test || test == 3) check(live.apply() == autoscan::ApplyResult::alreadyApplied, "Edge application is idempotent");
  }
}

// Write, damage and replace a plan in a new temporary folder; cleanup removes its file and folder.
static void cacheTests() {
  namespace fs = std::filesystem;
  auto cachePath = [](std::string_view scanner, std::string_view image) {
    std::array<wchar_t, 1024> path{};
    autoscan::CachePath(scanner, image, path);
    return std::wstring(path.data());
  };
  auto directory = fs::temp_directory_path() / (L"mv2-autoscan-test-" + std::to_wstring(GetCurrentProcessId()) +
                                               L"-" + std::to_wstring(GetTickCount64()));
  check(fs::create_directory(directory), "create isolated cache fixture");
  auto path = (directory / L"plan.bin").wstring();
  struct Cleanup {
    fs::path directory;
    ~Cleanup() { std::error_code error; fs::remove(directory / L"plan.bin", error); fs::remove(directory, error); }
  } cleanup{directory};
  LiveImage live(true, true);
  std::string scanner(64, '1'), different(64, '2'), hash(live.plan.blake3.data(), live.plan.blake3.size());
  autoscan::WirePlan restored;
  check(!autoscan::ReadCache(path.c_str(), scanner, hash, restored), "missing cache is a miss");
  check(autoscan::WriteCache(path.c_str(), scanner, live.plan), "complete scan can be cached");
  check(autoscan::ReadCache(path.c_str(), scanner, hash, restored) && restored.cacheHit == 1, "protected cache round trip");
  restored.cacheHit = 0;
  check(!memcmp(&restored, &live.plan, sizeof(restored)), "cache preserves the entire plan");
  check(!autoscan::ReadCache(path.c_str(), different, hash, restored), "different scanner cannot reuse a cache");
  check(!autoscan::ReadCache(path.c_str(), scanner, different, restored), "different browser cannot reuse a cache");
  check(cachePath(scanner, hash) != cachePath(different, hash), "scanner update selects a new cache path");
  check(cachePath(scanner, hash) != cachePath(scanner, different), "browser update selects a new cache path");
  check(cachePath("../invalid", hash).empty(), "invalid cache identity cannot form a path");
  for (unsigned test = 0; test < 5; ++test) {
    auto invalid = live.plan;
    if (test == 0) invalid.count = 0;
    if (test == 1) invalid.count = 65;
    if (test == 2) invalid.status = 1;
    if (test == 3) ++invalid.protocol;
    if (test == 4) invalid.blake3[0] = 'z';
    check(!autoscan::WriteCache(path.c_str(), scanner, invalid), "incomplete or incompatible results never replace a cache");
  }
  check(autoscan::ReadCache(path.c_str(), scanner, hash, restored), "rejected writes preserve the prior complete cache");
  check(!autoscan::WriteCache((fs::path(path) / L"unwritable.bin").wstring().c_str(), scanner, live.plan), "cache IO failure is reported");
  check(autoscan::ReadCache(path.c_str(), scanner, hash, restored), "IO failure preserves the prior cache");
  live.plan = restored;
  check(live.apply() == autoscan::ApplyResult::applied && live.bytesMatch(true), "cached plans automatically include the verified off-store gate");
  auto read = [&]() {
    std::ifstream file(fs::path(path), std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(file), {});
  };
  auto write = [&](const Bytes& bytes) {
    std::ofstream file(fs::path(path), std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    check(static_cast<bool>(file), "write corrupt cache fixture");
  };
  auto encrypted = read();
  {
    uint8_t message[] = {1, 2, 3}; DATA_BLOB input{sizeof(message), message}, output{};
    check(CryptProtectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output),
          "create authenticated non-plan cache fixture");
    Bytes invalid(output.pbData, output.pbData + output.cbData); LocalFree(output.pbData); write(invalid);
    check(!autoscan::ReadCache(path.c_str(), scanner, hash, restored), "authenticated blobs still require the exact plan size");
  }
  for (auto offset : {size_t(0), encrypted.size() / 2, encrypted.size() - 1}) {
    auto damaged = encrypted; damaged[offset] ^= 0x40; write(damaged);
    check(!autoscan::ReadCache(path.c_str(), scanner, hash, restored), "corrupted protected cache is a miss");
  }
  for (auto size : {size_t(0), size_t(32), size_t(16385)}) {
    write(Bytes(size));
    check(!autoscan::ReadCache(path.c_str(), scanner, hash, restored), "empty, truncated and oversized cache files are misses");
  }
  live.plan.cacheHit = 0;
  check(autoscan::WriteCache(path.c_str(), scanner, live.plan) && autoscan::ReadCache(path.c_str(), scanner, hash, restored),
        "a fresh scan atomically replaces a corrupt cache");
  check(std::distance(fs::directory_iterator(directory), fs::directory_iterator{}) == 1, "atomic writes leave no temporary files");
}

int wmain() {
  try {
    programDecodeTests();
    auto basic = autoscan::Discover(image());
    check(basic.ready() && basic.gates.size() == 2, "complete free/member plan");
    check(basic.gates[0].rva == 0x1045 && basic.gates[1].rva == 0x1104, "RVA rather than file offset");
    check(basic.gates[1].fields == std::array<int64_t, 5>{0x50, 0x228, 0x88, 0x50, 0x208}, "infer connected fields");
    check(basic.sha256 == autoscan::Hash(image()), "bind plan to current bytes");
    check(autoscan::MakePlan(autoscan::Analyze(image())).status != 0, "unbound analysis cannot produce a runtime plan");
    check(!autoscan::Discover(image(freeCode, {})).ready(), "a lone predicate is not a complete layout");

    auto changed = memberCode;
    replace(changed, "837a50", "837a70"); replace(changed, "28020000", "48030000");
    replace(changed, "8b4150", "8b4138"); replace(changed, "08020000", "00030000");
    replace(changed, "88000000", "a4000000");
    auto moved = autoscan::Discover(image(freeCode, changed));
    check(moved.ready() && moved.gates[1].fields == std::array<int64_t, 5>{0x70, 0x348, 0xA4, 0x38, 0x300}, "changed layout is inferred");

    changed = freeCode; replace(changed, "83f9027f", "83f9037d");
    check(autoscan::Discover(image(changed)).ready(), "equivalent signed >=3 threshold");
    changed = freeCode; changed[2] = 0x81; changed.insert(changed.begin() + 5, {0, 0, 0});
    auto immediate32 = autoscan::Discover(image(changed));
    check(immediate32.ready() && immediate32.gates[0].rva == 0x1048, "32-bit compare immediate is decoded without a byte signature");
    changed = freeCode; changed.insert(changed.begin() + 7, {0, 0, 0, 0});
    changed[5] = 0x0F; changed[6] = 0x8F; changed[7] = 0x1F;
    auto nearReport = autoscan::Discover(image(changed));
    check(nearReport.ready() && nearReport.gates[0].kind == 1 && nearReport.gates[0].width == 6, "near jump preserves target");
    check(nearReport.gates[0].patch[1] == 0xE9 && nearReport.gates[0].patch[2] == 0x1F, "near jump displacement preserved");
    for (const char* suffix : {"02", "03", "027f", "030000000f8d", "028d05", "030f6f05"}) {
      auto bytes = image(); auto tail = hex(suffix);
      std::copy(tail.begin(), tail.end(), bytes.begin() + 0x600 - tail.size());
      auto truncated = autoscan::Discover(bytes);
      check(truncated.ready() && truncated.gates.size() == 2, "prescreens ignore truncated instructions at the end of .text");
    }
    for (const char* marker : {"027f00", "030000000f8d00000000"}) for (size_t padding = 0; padding < 32; ++padding) {
      auto bytes = image(); auto tail = hex(marker);
      std::copy(tail.begin(), tail.end(), bytes.begin() + 0x600 - tail.size() - padding);
      auto report = autoscan::Analyze(bytes);
      check(report.ready() && report.gates.size() == 2 && report.heads == basic.heads + 1,
            "byte filters retain short and near candidates at every vector and tail alignment");
    }
    auto inverted = autoscan::Discover(image(freeCode, invertedCode));
    check(inverted.ready() && inverted.gates[1].kind == 6, "inverted predicate and Boolean AL return");
    changed = invertedCode; replace(changed, "837a50027e", "837a50037c");
    check(autoscan::Discover(image(freeCode, changed)).ready(), "inverted signed <3 threshold");

    changed = freeCode; replace(changed, "771a", "9090");
    auto rejected = autoscan::Discover(image(changed));
    check(!rejected.ready() && !rejected.unresolved.empty(), "BT must reject wrapped out-of-range types");
    changed = freeCode; replace(changed, "0f95c1", "0f94c1");
    check(!autoscan::Discover(image(changed)).ready(), "wrong location polarity");
    changed = memberCode; replace(changed, "83f80a", "83fa0a");
    check(!autoscan::Discover(image(freeCode, changed)).ready(), "constants from unrelated values");
    changed = freeCode; changed.insert(changed.begin() + 2, 0x66);
    check(!autoscan::Discover(image(changed)).ready(), "16-bit compare cannot represent manifest version");
    changed = freeCode; changed.pop_back();
    auto flagRead = hex("0f95c0c3"); changed.insert(changed.end(), flagRead.begin(), flagRead.end());
    check(!autoscan::Discover(image(changed)).ready(), "false path must not consume removed comparison flags");
    check(!autoscan::Discover(image(freeCode, hex("837a50027f0a488b8a2802000083798806c3"))).ready(), "CSP selector is not an MV2 predicate");
    changed = hex("31c085c0752e"); changed.insert(changed.end(), freeCode.begin() + 2, freeCode.end());
    auto prefix = autoscan::Discover(image(changed));
    check(prefix.ready() && prefix.gates[0].compare == 0x1046, "previous displacement is not an instruction prefix");
    changed = freeCode; replace(changed, "83f902", "83fe02");
    check(!autoscan::Discover(image(changed)).ready(), "unrelated loop is not the free predicate ABI");

    changed = hex("41b80a010000e800000000");
    put<int32_t>(changed, 7, 0x11C0 - 0x110B);
    auto body = invertedCode; replace(body, "41b80a010000", "909090909090");
    changed.insert(changed.end(), body.begin(), body.end());
    check(autoscan::Discover(image(freeCode, changed, hex("85c07401c34531c00f0b"))).ready(), "nonreturning clobber path preserves hoisted mask on normal return");
    check(!autoscan::Discover(image(freeCode, changed, hex("85c07401c34531c0c3"))).ready(), "returning call that clobbers mask is rejected");

    auto guarded = hex("488b4424204831e0488b0d000000004839c10f850000000041b80a010000");
    put<int32_t>(guarded, 11, 0x1300 - 0x110F);
    put<int32_t>(guarded, 20, static_cast<int32_t>(30 + body.size() - 24));
    guarded.insert(guarded.end(), body.begin(), body.end());
    auto failure = hex("488b4c24204831e1e800000000e900000000");
    size_t failureAt = guarded.size();
    put<int32_t>(failure, 9, static_cast<int32_t>(0x11C0 - (0x1100 + failureAt + 13)));
    put<int32_t>(failure, 14, static_cast<int32_t>(30 - (failureAt + 18)));
    guarded.insert(guarded.end(), failure.begin(), failure.end());
    auto cookie = hex("483b0d000000007501c30f0b");
    put<int32_t>(cookie, 3, 0x1300 - 0x11C7);
    check(autoscan::Discover(image(freeCode, guarded, cookie)).ready(), "caller mismatch contradicts callee normal-return requirement");
    changed = guarded; replace(changed, "4831e0", "4831d8");
    check(!autoscan::Discover(image(freeCode, changed, cookie)).ready(), "different compared value cannot prune call continuation");
    changed = cookie; changed[10] = 0xC3;
    check(!autoscan::Discover(image(freeCode, guarded, changed)).ready(), "returning failure arm cannot prune call continuation");
    auto ud1 = hex("483b0d000000007501c3670fb94001");
    put<int32_t>(ud1, 3, 0x1300 - 0x11C7);
    check(autoscan::Discover(image(freeCode, guarded, ud1)).ready(), "UD1 trap terminates decoding before its instruction payload");

    auto inlineCode = hex("837a50027f43488b8a280200008b415080ba080200000075178b898800000083f908772541b80a010000410fa3c8731983f805741483f80a740f0f2844242085c97406b801000000c331c0c3");
    auto inlined = autoscan::Discover(image(freeCode, inlineCode));
    check(inlined.ready() && inlined.gates[1].exit == 0x113A, "prove routing before arbitrary inlined caller work");
    changed = inlineCode; replace(changed, "8b8988000000", "0f2844242090");
    check(!autoscan::Discover(image(freeCode, changed)).ready(), "unsupported code inside the predicate still declines");
    changed = inlineCode; replace(changed, "83f80a740f", "83f80a750f");
    check(!autoscan::Discover(image(freeCode, changed)).ready(), "continuation proof preserves location polarity");
    auto paired = hex("85c07508837a50027e08eb3d837a50027f37");
    paired.insert(paired.end(), memberCode.begin() + 6, memberCode.end());
    auto diagnostic = autoscan::Discover(image(paired, paired));
    check(diagnostic.ready() && diagnostic.gates.size() == 4, "independent shared diagnostic bodies when free function is folded away");
    check(!autoscan::Discover(image({}, paired)).ready(), "one diagnostic body alone is not a layout cross-check");
    auto storedBool = hex("41837f50027e0431c0eb3b498b87280200008b48504180bf080200000075198b908800000031c083fa08771a41b80a010000410fa3d0730e83f9050f95c283f90a0f95c020d041888693030000490fbe8687030000c3");
    check(autoscan::Discover(image(freeCode, storedBool)).ready(), "Boolean property store ignores proven-dead upper register bits");
    changed = storedBool; replace(changed, "490fbe8687030000", "4885c09090909090");
    check(!autoscan::Discover(image(freeCode, changed)).ready(), "live upper bits at a Boolean store are not discarded");
    changed = storedBool; replace(changed, "41888693030000", "40888093030000");
    check(!autoscan::Discover(image(freeCode, changed)).ready(), "Boolean source register cannot also address the store");

    auto broken = image(); put<uint32_t>(broken, 0x198, 0xFFFFFFFF);
    check(!autoscan::Discover(broken).ready(), "truncated PE section");
    broken = image(); put<uint32_t>(broken, 0x1AC, 0x40000040);
    check(!autoscan::Discover(broken).ready(), "nonexecutable section");
    broken = image(); put<uint16_t>(broken, 0x84, 0xAA64);
    check(!autoscan::Discover(broken).ready(), "wrong machine");
    check(!autoscan::Discover({}).ready(), "empty input");
    argumentTests();
    providerTests();
    crxTests();
    HANDLE thread = CreateThread(nullptr, 512 * 1024, edgeStackTest, nullptr, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    check(thread && WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "Edge discovery completes within rundll32's stack budget");
    DWORD threadExit = 1; check(GetExitCodeThread(thread, &threadExit) && !threadExit, "Edge checks pass with a 512 KiB stack"); CloseHandle(thread);
    applicationTests();
    relocationTests();
    optionalPlanTests();
    cacheTests();
    std::cout << "PASS: " << checks << " native scanner checks\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL after " << checks << " checks: " << error.what() << '\n';
    return 1;
  }
}
