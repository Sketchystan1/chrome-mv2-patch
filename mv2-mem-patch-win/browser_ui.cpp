// Test-only: inspect or invoke one named button in an owned browser on a
// private desktop. Never switch the user's visible desktop or send global input.
#define NOMINMAX
#include <windows.h>
#include <UIAutomation.h>
#include <wrl/client.h>
#include <array>
#include <cstdio>
#include <cwchar>
#include <fcntl.h>
#include <io.h>

using Microsoft::WRL::ComPtr;
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value) CloseHandle(value); }
};
struct Desktop {
  HDESK value = nullptr;
  ~Desktop() { if (value) CloseDesktop(value); }
};
struct ComSession {
  HRESULT status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  ~ComSession() { if (SUCCEEDED(status)) CoUninitialize(); }
};
struct OwnedWindows {
  DWORD pid;
  std::array<HWND, 64> handles{};
  unsigned count = 0;
};
static BOOL CALLBACK collect(HWND window, LPARAM input) {
  auto& windows = *reinterpret_cast<OwnedWindows*>(input);
  DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
  if (pid == windows.pid) {
    if (windows.count == windows.handles.size()) return FALSE;
    windows.handles[windows.count++] = window;
  }
  return TRUE;
}
int wmain(int argc, wchar_t** argv) {
  if (argc != 5 || wcsncmp(argv[1], L"MV2Crx-", 7) != 0) return 2;
  wchar_t* end = nullptr;
  unsigned long parsed = wcstoul(argv[2], &end, 10);
  if (!parsed || !end || *end) return 2;
  DWORD pid = parsed;
  Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid)};
  std::array<wchar_t, 32768> expected{}, actual{};
  DWORD actualLength = static_cast<DWORD>(actual.size());
  DWORD expectedLength = GetFullPathNameW(argv[3], static_cast<DWORD>(expected.size()), expected.data(), nullptr);
  if (!process.value || !expectedLength || expectedLength >= expected.size() ||
      !QueryFullProcessImageNameW(process.value, 0, actual.data(), &actualLength) ||
      _wcsicmp(actual.data(), expected.data())) {
    std::fprintf(stderr, "browser PID does not match the owned executable\n"); return 2;
  }
  Desktop desktop{OpenDesktopW(argv[1], 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_ENUMERATE)};
  if (!desktop.value) {
    std::fprintf(stderr, "cannot open the private test desktop: %lu\n", GetLastError()); return 2;
  }
  // COM initializes on the client's original desktop. EnumDesktopWindows and
  // ElementFromHandle select only the private browser's windows explicitly.
  ComSession com;
  if (FAILED(com.status)) { std::fprintf(stderr, "COM initialization failed: 0x%08lx\n", com.status); return 2; }
  ComPtr<IUIAutomation> automation;
  auto created = CoCreateInstance(CLSID_CUIAutomation, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&automation));
  if (FAILED(created)) { std::fprintf(stderr, "UI Automation initialization failed: 0x%08lx\n", created); return 2; }
  ComPtr<IUIAutomationCondition> all;
  if (FAILED(automation->CreateTrueCondition(&all))) { std::fprintf(stderr, "cannot create UI condition\n"); return 2; }
  bool inspect = wcscmp(argv[4], L"inspect") == 0 || wcsncmp(argv[4], L"inspect:", 8) == 0;
  const wchar_t* sought = wcsncmp(argv[4], L"inspect:", 8) == 0 ? argv[4] + 8 : nullptr;
  _setmode(_fileno(stdout), _O_U8TEXT);
  ULONGLONG deadline = GetTickCount64() + 15000;
  while (GetTickCount64() < deadline && WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT) {
    bool found = false;
    OwnedWindows windows{pid};
    if (!EnumDesktopWindows(desktop.value, collect, reinterpret_cast<LPARAM>(&windows))) return 2;
    if (inspect) std::wprintf(L"owned_windows=%u\n", windows.count);
    for (unsigned n = 0; n < windows.count; ++n) {
      if (inspect) {
        std::array<wchar_t, 1024> title{};
        GetWindowTextW(windows.handles[n], title.data(), static_cast<int>(title.size()));
        std::wprintf(L"visible=%d window=%ls\n", IsWindowVisible(windows.handles[n]), title.data());
      }
      ComPtr<IUIAutomationElement> root;
      ComPtr<IUIAutomationElementArray> elements;
      if (FAILED(automation->ElementFromHandle(windows.handles[n], &root)) ||
          FAILED(root->FindAll(TreeScope_Subtree, all.Get(), &elements))) continue;
      int count = 0;
      if (FAILED(elements->get_Length(&count)) || count > 4096) continue;
      for (int index = 0; index < count; ++index) {
        ComPtr<IUIAutomationElement> element;
        BSTR name = nullptr; CONTROLTYPEID type = 0; BOOL enabled = FALSE;
        if (FAILED(elements->GetElement(index, &element)) || FAILED(element->get_CurrentName(&name))) continue;
        element->get_CurrentControlType(&type); element->get_CurrentIsEnabled(&enabled);
        bool invoked = false;
        if (inspect) {
          if (name && *name) std::wprintf(L"type=%d enabled=%d name=%ls\n", type, enabled, name);
          if (sought && name && wcsstr(name, sought)) found = true;
        } else if (name && enabled && type == UIA_ButtonControlTypeId && wcscmp(name, argv[4]) == 0) {
          DWORD owner = 0; GetWindowThreadProcessId(windows.handles[n], &owner);
          ComPtr<IUIAutomationInvokePattern> invoke;
          invoked = owner == pid && WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT &&
            SUCCEEDED(element->GetCurrentPatternAs(UIA_InvokePatternId, IID_PPV_ARGS(&invoke))) &&
            SUCCEEDED(invoke->Invoke());
          if (invoked) std::wprintf(L"invoked=%ls\n", name);
        }
        SysFreeString(name);
        if (invoked) return 0;
      }
    }
    if (inspect && (sought ? found : windows.count != 0)) return 0;
    Sleep(100);
  }
  return 1;
}
