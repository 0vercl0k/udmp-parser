//
// This file is part of udmp-parser project
//
// Released under MIT License, by 0vercl0k - 2023
//
// With contribution from:
//  * hugsy - (github.com/hugsy)
//

#include "udmp-parser.h"

#include <filesystem>
#include <memory>
#include <nanobind/nanobind.h>
#include <nanobind/stl/filesystem.h>
#include <nanobind/stl/string.h>

namespace nb = nanobind;

#ifdef _WIN32
#include <dbghelp.h>
#include <windows.h>

bool GenerateMinidumpFromProcessId(
    const uint32_t TargetPid, const std::filesystem::path &MiniDumpFilePath) {
  const HANDLE File =
      CreateFileA(MiniDumpFilePath.string().c_str(), GENERIC_WRITE, 0, nullptr,
                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (File == INVALID_HANDLE_VALUE) {
    return false;
  }

  const HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, false, TargetPid);
  if (Process == INVALID_HANDLE_VALUE) {
    CloseHandle(File);
    return false;
  }

  MINIDUMP_EXCEPTION_INFORMATION ExceptionInfo = {};
  const auto Flags = MINIDUMP_TYPE::MiniDumpWithFullMemory |
                     MINIDUMP_TYPE::MiniDumpWithDataSegs |
                     MINIDUMP_TYPE::MiniDumpScanMemory |
                     MINIDUMP_TYPE::MiniDumpWithHandleData |
                     MINIDUMP_TYPE::MiniDumpWithFullMemoryInfo;

  const auto Success =
      MiniDumpWriteDump(Process, TargetPid, File, MINIDUMP_TYPE(Flags),
                        &ExceptionInfo, nullptr, nullptr);

  CloseHandle(Process);
  CloseHandle(File);
  return Success;
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

#if defined(_WIN32)
  utils.def("generate_minidump", GenerateMinidumpFromProcessId, "TargetPid",
            "MiniDumpFilePath",
            "Generate a minidump for TargetPid and save it to the given path. "
            "Returns true on success.");

  utils.def(
      "generate_minidump_from_command_line",
      []() -> bool {
        nb::module_ sys = nb::module_::import_("sys");
        nb::list argv = sys.attr("argv");
        if (!argv.is_valid()) {
          return false;
        }

        if (argv.size() != 3) {
          return false;
        }

        auto a1 = nb::str(nb::handle(argv[1]));
        const auto TargetPid = uint32_t(std::atol(a1.c_str()));
        auto a2 = nb::str(nb::handle(argv[2]));
        return GenerateMinidumpFromProcessId(TargetPid, a2.c_str());
      },
      "Generate a minidump for the target TargetPid, write it to the given "
      "path. Returns true on success.");
#endif // _WIN32
}
