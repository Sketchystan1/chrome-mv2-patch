// Test-only tool: start the browser named on the command line with the registry-isolation test DLL.
// Closing this tool stops that test browser and its remaining child processes.
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <string>
#include "detours.h"

static std::wstring quote(const wchar_t* text) {
  std::wstring result = L"\"";
  size_t slashes = 0;
  for (; *text; ++text) {
    if (*text == L'\\') { ++slashes; continue; }
    result.append(slashes * (*text == L'"' ? 2 : 1), L'\\'); slashes = 0;
    if (*text == L'"') result += L'\\';
    result += *text;
  }
  result.append(slashes * 2, L'\\'); result += L'"';
  return result;
}
int wmain(int argc, wchar_t** argv) {
  if (argc < 3) { std::cerr << "usage: test-launch <registry-test.dll> <chrome.exe> [arguments]\n"; return 2; }
  int length = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, argv[1], -1, nullptr, 0, nullptr, nullptr);
  std::string shim(length, '\0'); BOOL substituted = FALSE;
  if (!length || !WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, argv[1], -1, shim.data(), length, nullptr, &substituted) || substituted) return 2;
  std::wstring command;
  for (int n = 2; n < argc; ++n) { if (n != 2) command += L' '; command += quote(argv[n]); }
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits)) return 2;
  STARTUPINFOW start{}; start.cb = sizeof(start);
  PROCESS_INFORMATION process{};
  if (!DetourCreateProcessWithDllExW(argv[2], command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                    nullptr, nullptr, &start, &process, shim.c_str(), nullptr)) {
    std::cerr << "Cannot create test process: " << GetLastError() << '\n'; CloseHandle(job); return 2;
  }
  if (!AssignProcessToJobObject(job, process.hProcess)) {
    TerminateProcess(process.hProcess, 2); CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job); return 2;
  }
  std::cout << process.dwProcessId << std::endl;
  ResumeThread(process.hThread); CloseHandle(process.hThread);
  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD code = 1; GetExitCodeProcess(process.hProcess, &code);
  CloseHandle(process.hProcess); CloseHandle(job);
  return static_cast<int>(code);
}
