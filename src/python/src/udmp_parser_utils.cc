//
// This file is part of udmp-parser project
//
// Released under MIT License, by 0vercl0k - 2023
//
// With contribution from:
//  * hugsy - (github.com/hugsy)
//

#include "udmp-parser.h"

#include <memory>
#include <string>

#include <nanobind/nanobind.h>
#include <nanobind/stl/filesystem.h>
#include <nanobind/stl/string.h>

#if defined(_WIN32)
#include <DbgHelp.h>
#include <windows.h>
#else
#include <stdio.h>
#endif // _WIN32

namespace nb = nanobind;
using namespace nb::literals;

template <typename T, auto Deleter>
using GenericHandle = std::unique_ptr<T, decltype([](T *h) {
                                        if (h) {
                                          Deleter(h);
                                          h = nullptr;
                                        }
                                      })>;
#if defined(_WIN32)
using UniqueHandle = GenericHandle<void, ::CloseHandle>;
#else
using UniqueHandle = GenericHandle<FILE, ::fclose>;
#endif

#if defined(_WIN32)
static auto
GenerateMinidumpFromProcessId(uint32_t TargetPid,
                              std::filesystem::path &MiniDumpFilePath) -> int {
  auto hFile = UniqueHandle{
      ::CreateFileW(MiniDumpFilePath.wstring().c_str(), GENERIC_WRITE, 0,
                    nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
  if (!hFile) {
    return -1;
  }

  auto hProcess =
      UniqueHandle{::OpenProcess(PROCESS_ALL_ACCESS, false, TargetPid)};
  if (!hProcess) {
    return -2;
  }

  MINIDUMP_EXCEPTION_INFORMATION exceptionInfo{};
  MINIDUMP_TYPE flags = static_cast<MINIDUMP_TYPE>(
      MINIDUMP_TYPE::MiniDumpWithFullMemory |
      MINIDUMP_TYPE::MiniDumpWithDataSegs | MINIDUMP_TYPE::MiniDumpScanMemory |
      MINIDUMP_TYPE::MiniDumpWithHandleData |
      MINIDUMP_TYPE::MiniDumpWithFullMemoryInfo);

  const auto bSuccess =
      ::MiniDumpWriteDump(hProcess.get(), TargetPid, hFile.get(), flags,
                          &exceptionInfo, nullptr, nullptr);
  return bSuccess ? 0 : -3;
}
#endif

void udmp_parser_utils_module(nb::module_ &m) {

  auto utils = m.def_submodule("utils", "Helper functions");

  utils.def(
      "TypeToString",
      [](const uint32_t Type) -> std::string {
        switch (Type) {
        case 0x2'00'00: {
          return "MEM_PRIVATE";
        }
        case 0x4'00'00: {
          return "MEM_MAPPED";
        }
        case 0x1'00'00'00: {
          return "MEM_IMAGE";
        }
        }
        return "";
      },
      "Get a string representation of the memory type");

  utils.def(
      "StateToString",
      [](const uint32_t State) {
        switch (State) {
        case 0x10'00: {
          return "MEM_COMMIT";
        }

        case 0x20'00: {
          return "MEM_RESERVE";
        }

        case 0x1'00'00: {
          return "MEM_FREE";
        }
        }
        return "";
      },
      "Get a string representation of the memory state");

  utils.def(
      "ProtectionToString",
      [](const uint32_t Protection) {
        struct {
          const char *Name = nullptr;
          uint32_t Mask = 0;
        } Flags[] = {
            {"PAGE_NOACCESS", 0x01},
            {"PAGE_READONLY", 0x02},
            {"PAGE_READWRITE", 0x04},
            {"PAGE_WRITECOPY", 0x08},
            {"PAGE_EXECUTE", 0x10},
            {"PAGE_EXECUTE_READ", 0x20},
            {"PAGE_EXECUTE_READWRITE", 0x40},
            {"PAGE_EXECUTE_WRITECOPY", 0x80},
            {"PAGE_GUARD", 0x100},
            {"PAGE_NOCACHE", 0x200},
            {"PAGE_WRITECOMBINE", 0x400},
            {"PAGE_TARGETS_INVALID", 0x4000'0000},
        };
        std::stringstream ss;
        uint32_t KnownFlags = 0;

        for (const auto &Flag : Flags) {
          if ((Protection & Flag.Mask) == 0) {
            continue;
          }

          ss << Flag.Name << ",";
          KnownFlags |= Flag.Mask;
        }

        const uint32_t MissingFlags = (~KnownFlags) & Protection;
        if (MissingFlags) {
          ss << std::hex << "0x" << MissingFlags;
        }

        std::string ProtectionString = ss.str();
        if (ProtectionString.size() > 1 &&
            ProtectionString[ProtectionString.size() - 1] == ',') {
          ProtectionString =
              ProtectionString.substr(0, ProtectionString.size() - 1);
        }

        return ProtectionString;
      },
      "Get a string representation of the memory protection");

  utils.def(
      "generate_minidump", GenerateMinidumpFromProcessId, "TargetPid"_a,
      "MiniDumpFilePath"_a,
      "Generate a minidump for the target ProcessId, write it to the given "
      "path. Returns 0 on success, non-zero on error.");

  utils.def(
      "generate_minidump_from_command_line",
      []() -> int {
#if defined(_WIN32)
        nb::module_ sys = nb::module_::import_("sys");
        nb::list argv = sys.attr("argv");
        if (!argv.is_valid()) {
          return 1;
        }

        if (argv.size() != 3) {
          return 2;
        }

        auto a1 = nb::str(nb::handle(argv[1]));
        auto a2 = nb::str(nb::handle(argv[2]));

        uint32_t TargetPid = static_cast<uint32_t>(std::atol(a1.c_str()));
        std::filesystem::path MinidumpPath{a2.c_str()};
        return GenerateMinidumpFromProcessId(TargetPid, MinidumpPath);
#else
        ::puts("This command only works on Windows");
        return 0;
#endif // _WIN32
      },
      "Generate a minidump for the target ProcessId, write it to the given "
      "path. Returns 0 on success, non-zero on error.");
}
