///
/// This file is part of udmp-parser project
///
/// Released under MIT License, by 0vercl0k - 2023
///
/// With contribution from:
///  * hugsy -(github.com / hugsy)
///

#include "udmp-parser.h"

#include <nanobind/nanobind.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/filesystem.h>
#include <nanobind/stl/map.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/pair.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unordered_map.h>
#include <nanobind/stl/unordered_set.h>
#include <nanobind/stl/variant.h>
#include <nanobind/stl/vector.h>

namespace nb = nanobind;

NB_MODULE(udmp_parser, m) {
  nb::enum_<udmpparser::ProcessorArch_t>(m, "ProcessorArch")
      .value("X86", udmpparser::ProcessorArch_t::X86)
      .value("ARM", udmpparser::ProcessorArch_t::ARM)
      .value("IA64", udmpparser::ProcessorArch_t::IA64)
      .value("AMD64", udmpparser::ProcessorArch_t::AMD64)
      .value("Unknown", udmpparser::ProcessorArch_t::Unknown)
      .export_values();

  nb::class_<udmpparser::FloatingSaveArea32_t>(m, "FloatingSaveArea32")
      .def_ro("ControlWord", &udmpparser::FloatingSaveArea32_t::ControlWord)
      .def_ro("StatusWord", &udmpparser::FloatingSaveArea32_t::StatusWord)
      .def_ro("TagWord", &udmpparser::FloatingSaveArea32_t::TagWord)
      .def_ro("ErrorOffset", &udmpparser::FloatingSaveArea32_t::ErrorOffset)
      .def_ro("ErrorSelector", &udmpparser::FloatingSaveArea32_t::ErrorSelector)
      .def_ro("DataOffset", &udmpparser::FloatingSaveArea32_t::DataOffset)
      .def_ro("DataSelector", &udmpparser::FloatingSaveArea32_t::DataSelector)
      .def_ro("RegisterArea", &udmpparser::FloatingSaveArea32_t::RegisterArea)
      .def_ro("Cr0NpxState", &udmpparser::FloatingSaveArea32_t::Cr0NpxState);

  nb::class_<udmpparser::Context32_t>(m, "Context32")
      .def_ro("ContextFlags", &udmpparser::Context32_t::ContextFlags)
      .def_ro("Dr0", &udmpparser::Context32_t::Dr0)
      .def_ro("Dr1", &udmpparser::Context32_t::Dr1)
      .def_ro("Dr2", &udmpparser::Context32_t::Dr2)
      .def_ro("Dr3", &udmpparser::Context32_t::Dr3)
      .def_ro("Dr6", &udmpparser::Context32_t::Dr6)
      .def_ro("Dr7", &udmpparser::Context32_t::Dr7)
      .def_ro("FloatSave", &udmpparser::Context32_t::FloatSave)
      .def_ro("SegGs", &udmpparser::Context32_t::SegGs)
      .def_ro("SegFs", &udmpparser::Context32_t::SegFs)
      .def_ro("SegEs", &udmpparser::Context32_t::SegEs)
      .def_ro("SegDs", &udmpparser::Context32_t::SegDs)
      .def_ro("Edi", &udmpparser::Context32_t::Edi)
      .def_ro("Esi", &udmpparser::Context32_t::Esi)
      .def_ro("Ebx", &udmpparser::Context32_t::Ebx)
      .def_ro("Edx", &udmpparser::Context32_t::Edx)
      .def_ro("Ecx", &udmpparser::Context32_t::Ecx)
      .def_ro("Eax", &udmpparser::Context32_t::Eax)
      .def_ro("Ebp", &udmpparser::Context32_t::Ebp)
      .def_ro("Eip", &udmpparser::Context32_t::Eip)
      .def_ro("SegCs", &udmpparser::Context32_t::SegCs)
      .def_ro("EFlags", &udmpparser::Context32_t::EFlags)
      .def_ro("Esp", &udmpparser::Context32_t::Esp)
      .def_ro("SegSs", &udmpparser::Context32_t::SegSs)
      .def_ro("ExtendedRegisters", &udmpparser::Context32_t::ExtendedRegisters);

  nb::class_<udmpparser::uint128_t>(m, "uint128")
      .def_ro("Low", &udmpparser::uint128_t::Low)
      .def_ro("High", &udmpparser::uint128_t::High);

  nb::class_<udmpparser::Context64_t>(m, "Context64")
      .def_ro("P1Home", &udmpparser::Context64_t::P1Home)
      .def_ro("P2Home", &udmpparser::Context64_t::P2Home)
      .def_ro("P3Home", &udmpparser::Context64_t::P3Home)
      .def_ro("P4Home", &udmpparser::Context64_t::P4Home)
      .def_ro("P5Home", &udmpparser::Context64_t::P5Home)
      .def_ro("P6Home", &udmpparser::Context64_t::P6Home)
      .def_ro("ContextFlags", &udmpparser::Context64_t::ContextFlags)
      .def_ro("MxCsr", &udmpparser::Context64_t::MxCsr)
      .def_ro("SegCs", &udmpparser::Context64_t::SegCs)
      .def_ro("SegDs", &udmpparser::Context64_t::SegDs)
      .def_ro("SegEs", &udmpparser::Context64_t::SegEs)
      .def_ro("SegFs", &udmpparser::Context64_t::SegFs)
      .def_ro("SegGs", &udmpparser::Context64_t::SegGs)
      .def_ro("SegSs", &udmpparser::Context64_t::SegSs)
      .def_ro("EFlags", &udmpparser::Context64_t::EFlags)
      .def_ro("Dr0", &udmpparser::Context64_t::Dr0)
      .def_ro("Dr1", &udmpparser::Context64_t::Dr1)
      .def_ro("Dr2", &udmpparser::Context64_t::Dr2)
      .def_ro("Dr3", &udmpparser::Context64_t::Dr3)
      .def_ro("Dr6", &udmpparser::Context64_t::Dr6)
      .def_ro("Dr7", &udmpparser::Context64_t::Dr7)
      .def_ro("Rax", &udmpparser::Context64_t::Rax)
      .def_ro("Rcx", &udmpparser::Context64_t::Rcx)
      .def_ro("Rdx", &udmpparser::Context64_t::Rdx)
      .def_ro("Rbx", &udmpparser::Context64_t::Rbx)
      .def_ro("Rsp", &udmpparser::Context64_t::Rsp)
      .def_ro("Rbp", &udmpparser::Context64_t::Rbp)
      .def_ro("Rsi", &udmpparser::Context64_t::Rsi)
      .def_ro("Rdi", &udmpparser::Context64_t::Rdi)
      .def_ro("R8", &udmpparser::Context64_t::R8)
      .def_ro("R9", &udmpparser::Context64_t::R9)
      .def_ro("R10", &udmpparser::Context64_t::R10)
      .def_ro("R11", &udmpparser::Context64_t::R11)
      .def_ro("R12", &udmpparser::Context64_t::R12)
      .def_ro("R13", &udmpparser::Context64_t::R13)
      .def_ro("R14", &udmpparser::Context64_t::R14)
      .def_ro("R15", &udmpparser::Context64_t::R15)
      .def_ro("Rip", &udmpparser::Context64_t::Rip)
      .def_ro("ControlWord", &udmpparser::Context64_t::ControlWord)
      .def_ro("StatusWord", &udmpparser::Context64_t::StatusWord)
      .def_ro("TagWord", &udmpparser::Context64_t::TagWord)
      .def_ro("Reserved1", &udmpparser::Context64_t::Reserved1)
      .def_ro("ErrorOpcode", &udmpparser::Context64_t::ErrorOpcode)
      .def_ro("ErrorOffset", &udmpparser::Context64_t::ErrorOffset)
      .def_ro("ErrorSelector", &udmpparser::Context64_t::ErrorSelector)
      .def_ro("Reserved2", &udmpparser::Context64_t::Reserved2)
      .def_ro("DataOffset", &udmpparser::Context64_t::DataOffset)
      .def_ro("DataSelector", &udmpparser::Context64_t::DataSelector)
      .def_ro("Reserved3", &udmpparser::Context64_t::Reserved3)
      .def_ro("MxCsr2", &udmpparser::Context64_t::MxCsr2)
      .def_ro("MxCsr_Mask", &udmpparser::Context64_t::MxCsr_Mask)
      .def_ro("FloatRegisters", &udmpparser::Context64_t::FloatRegisters)
      .def_ro("Xmm0", &udmpparser::Context64_t::Xmm0)
      .def_ro("Xmm1", &udmpparser::Context64_t::Xmm1)
      .def_ro("Xmm2", &udmpparser::Context64_t::Xmm2)
      .def_ro("Xmm3", &udmpparser::Context64_t::Xmm3)
      .def_ro("Xmm4", &udmpparser::Context64_t::Xmm4)
      .def_ro("Xmm5", &udmpparser::Context64_t::Xmm5)
      .def_ro("Xmm6", &udmpparser::Context64_t::Xmm6)
      .def_ro("Xmm7", &udmpparser::Context64_t::Xmm7)
      .def_ro("Xmm8", &udmpparser::Context64_t::Xmm8)
      .def_ro("Xmm9", &udmpparser::Context64_t::Xmm9)
      .def_ro("Xmm10", &udmpparser::Context64_t::Xmm10)
      .def_ro("Xmm11", &udmpparser::Context64_t::Xmm11)
      .def_ro("Xmm12", &udmpparser::Context64_t::Xmm12)
      .def_ro("Xmm13", &udmpparser::Context64_t::Xmm13)
      .def_ro("Xmm14", &udmpparser::Context64_t::Xmm14)
      .def_ro("Xmm15", &udmpparser::Context64_t::Xmm15)
      .def_ro("VectorRegister", &udmpparser::Context64_t::VectorRegister)
      .def_ro("VectorControl", &udmpparser::Context64_t::VectorControl)
      .def_ro("DebugControl", &udmpparser::Context64_t::DebugControl)
      .def_ro("LastBranchToRip", &udmpparser::Context64_t::LastBranchToRip)
      .def_ro("LastBranchFromRip", &udmpparser::Context64_t::LastBranchFromRip)
      .def_ro("LastExceptionToRip",
              &udmpparser::Context64_t::LastExceptionToRip)
      .def_ro("LastExceptionFromRip",
              &udmpparser::Context64_t::LastExceptionFromRip);

  nb::class_<udmpparser::dmp::Header_t>(m, "Header")
      .def_ro_static("ExpectedSignature",
                     &udmpparser::dmp::Header_t::ExpectedSignature)
      .def_ro_static("ValidFlagsMask",
                     &udmpparser::dmp::Header_t::ValidFlagsMask)
      .def_ro("Signature", &udmpparser::dmp::Header_t::Signature)
      .def_ro("Version", &udmpparser::dmp::Header_t::Version)
      .def_ro("ImplementationVersion",
              &udmpparser::dmp::Header_t::ImplementationVersion)
      .def_ro("NumberOfStreams", &udmpparser::dmp::Header_t::NumberOfStreams)
      .def_ro("StreamDirectoryRva",
              &udmpparser::dmp::Header_t::StreamDirectoryRva)
      .def_ro("CheckSum", &udmpparser::dmp::Header_t::CheckSum)
      .def_ro("Reserved", &udmpparser::dmp::Header_t::Reserved)
      .def_ro("TimeDateStamp", &udmpparser::dmp::Header_t::TimeDateStamp)
      .def_ro("Flags", &udmpparser::dmp::Header_t::Flags)
      .def("LooksGood", &udmpparser::dmp::Header_t::LooksGood);

  nb::class_<udmpparser::dmp::LocationDescriptor32_t>(m, "LocationDescriptor32")
      .def_ro("DataSize", &udmpparser::dmp::LocationDescriptor32_t::DataSize)
      .def_ro("Rva", &udmpparser::dmp::LocationDescriptor32_t::Rva);

  nb::class_<udmpparser::dmp::LocationDescriptor64_t>(m, "LocationDescriptor64")
      .def_ro("DataSize", &udmpparser::dmp::LocationDescriptor64_t::DataSize)
      .def_ro("Rva", &udmpparser::dmp::LocationDescriptor64_t::Rva);

  nb::enum_<udmpparser::dmp::StreamType_t>(m, "StreamType")
      .value("Unused", udmpparser::dmp::StreamType_t::Unused)
      .value("ThreadList", udmpparser::dmp::StreamType_t::ThreadList)
      .value("ModuleList", udmpparser::dmp::StreamType_t::ModuleList)
      .value("Exception", udmpparser::dmp::StreamType_t::Exception)
      .value("SystemInfo", udmpparser::dmp::StreamType_t::SystemInfo)
      .value("Memory64List", udmpparser::dmp::StreamType_t::Memory64List)
      .value("MemoryInfoList", udmpparser::dmp::StreamType_t::MemoryInfoList)
      .export_values();

  nb::class_<udmpparser::dmp::Directory_t>(m, "Directory")
      .def_ro("StreamType", &udmpparser::dmp::Directory_t::StreamType)
      .def_ro("Location", &udmpparser::dmp::Directory_t::Location);

  nb::class_<udmpparser::dmp::Memory64ListStreamHdr_t>(m,
                                                       "Memory64ListStreamHdr")
      .def_ro("NumberOfMemoryRanges",
              &udmpparser::dmp::Memory64ListStreamHdr_t::NumberOfMemoryRanges)
      .def_ro("BaseRva", &udmpparser::dmp::Memory64ListStreamHdr_t::BaseRva);

  nb::class_<udmpparser::dmp::MemoryDescriptor64_t>(m, "MemoryDescriptor64")
      .def_ro("StartOfMemoryRange",
              &udmpparser::dmp::MemoryDescriptor64_t::StartOfMemoryRange)
      .def_ro("DataSize", &udmpparser::dmp::MemoryDescriptor64_t::DataSize);

  nb::class_<udmpparser::dmp::FixedFileInfo_t>(m, "FixedFileInfo")
      .def_ro("Signature", &udmpparser::dmp::FixedFileInfo_t::Signature)
      .def_ro("StrucVersion", &udmpparser::dmp::FixedFileInfo_t::StrucVersion)
      .def_ro("FileVersionMS", &udmpparser::dmp::FixedFileInfo_t::FileVersionMS)
      .def_ro("FileVersionLS", &udmpparser::dmp::FixedFileInfo_t::FileVersionLS)
      .def_ro("ProductVersionMS",
              &udmpparser::dmp::FixedFileInfo_t::ProductVersionMS)
      .def_ro("ProductVersionLS",
              &udmpparser::dmp::FixedFileInfo_t::ProductVersionLS)
      .def_ro("FileFlagsMask", &udmpparser::dmp::FixedFileInfo_t::FileFlagsMask)
      .def_ro("FileFlags", &udmpparser::dmp::FixedFileInfo_t::FileFlags)
      .def_ro("FileOS", &udmpparser::dmp::FixedFileInfo_t::FileOS)
      .def_ro("FileType", &udmpparser::dmp::FixedFileInfo_t::FileType)
      .def_ro("FileSubtype", &udmpparser::dmp::FixedFileInfo_t::FileSubtype)
      .def_ro("FileDateMS", &udmpparser::dmp::FixedFileInfo_t::FileDateMS)
      .def_ro("FileDateLS", &udmpparser::dmp::FixedFileInfo_t::FileDateLS);

  nb::class_<udmpparser::dmp::MemoryInfo_t>(m, "MemoryInfo")
      .def_ro("BaseAddress", &udmpparser::dmp::MemoryInfo_t::BaseAddress)
      .def_ro("AllocationBase", &udmpparser::dmp::MemoryInfo_t::AllocationBase)
      .def_ro("AllocationProtect",
              &udmpparser::dmp::MemoryInfo_t::AllocationProtect)
      .def_ro("RegionSize", &udmpparser::dmp::MemoryInfo_t::RegionSize)
      .def_ro("State", &udmpparser::dmp::MemoryInfo_t::State)
      .def_ro("Protect", &udmpparser::dmp::MemoryInfo_t::Protect)
      .def_ro("Type", &udmpparser::dmp::MemoryInfo_t::Type);

  nb::class_<udmpparser::dmp::MemoryDescriptor_t>(m, "MemoryDescriptor")
      .def_ro("StartOfMemoryRange",
              &udmpparser::dmp::MemoryDescriptor_t::StartOfMemoryRange)
      .def_ro("Memory", &udmpparser::dmp::MemoryDescriptor_t::Memory);

  nb::class_<udmpparser::dmp::ThreadEntry_t>(m, "ThreadEntry")
      .def_ro("ThreadId", &udmpparser::dmp::ThreadEntry_t::ThreadId)
      .def_ro("SuspendCount", &udmpparser::dmp::ThreadEntry_t::SuspendCount)
      .def_ro("PriorityClass", &udmpparser::dmp::ThreadEntry_t::PriorityClass)
      .def_ro("Priority", &udmpparser::dmp::ThreadEntry_t::Priority)
      .def_ro("Teb", &udmpparser::dmp::ThreadEntry_t::Teb)
      .def_ro("Stack", &udmpparser::dmp::ThreadEntry_t::Stack)
      .def_ro("ThreadContext", &udmpparser::dmp::ThreadEntry_t::ThreadContext);

  nb::class_<udmpparser::dmp::SystemInfoStream_t>(m, "SystemInfoStream")
      .def_ro("ProcessorArchitecture",
              &udmpparser::dmp::SystemInfoStream_t::ProcessorArchitecture)
      .def_ro("ProcessorLevel ",
              &udmpparser::dmp::SystemInfoStream_t::ProcessorLevel)
      .def_ro("ProcessorRevision ",
              &udmpparser::dmp::SystemInfoStream_t::ProcessorRevision)
      .def_ro("NumberOfProcessors ",
              &udmpparser::dmp::SystemInfoStream_t::NumberOfProcessors)
      .def_ro("ProductType ", &udmpparser::dmp::SystemInfoStream_t::ProductType)
      .def_ro("MajorVersion ",
              &udmpparser::dmp::SystemInfoStream_t::MajorVersion)
      .def_ro("MinorVersion ",
              &udmpparser::dmp::SystemInfoStream_t::MinorVersion)
      .def_ro("BuildNumber ", &udmpparser::dmp::SystemInfoStream_t::BuildNumber)
      .def_ro("PlatformId ", &udmpparser::dmp::SystemInfoStream_t::PlatformId)
      .def_ro("CSDVersionRva ",
              &udmpparser::dmp::SystemInfoStream_t::CSDVersionRva)
      .def_ro("SuiteMask ", &udmpparser::dmp::SystemInfoStream_t::SuiteMask)
      .def_ro("Reserved2 ", &udmpparser::dmp::SystemInfoStream_t::Reserved2);

  nb::class_<udmpparser::dmp::ExceptionRecord_t>(m, "ExceptionRecord")
      .def_ro("ExceptionCode",
              &udmpparser::dmp::ExceptionRecord_t::ExceptionCode)
      .def_ro("ExceptionFlags",
              &udmpparser::dmp::ExceptionRecord_t::ExceptionFlags)
      .def_ro("ExceptionRecord",
              &udmpparser::dmp::ExceptionRecord_t::ExceptionRecord)
      .def_ro("ExceptionAddress",
              &udmpparser::dmp::ExceptionRecord_t::ExceptionAddress)
      .def_ro("NumberParameters",
              &udmpparser::dmp::ExceptionRecord_t::NumberParameters)
      .def_ro("ExceptionInformation",
              &udmpparser::dmp::ExceptionRecord_t::ExceptionInformation);

  nb::class_<udmpparser::dmp::ExceptionStream_t>(m, "ExceptionStream")
      .def(nb::init<>())
      .def_ro("ThreadId", &udmpparser::dmp::ExceptionStream_t::ThreadId)
      .def_ro("ExceptionRecord",
              &udmpparser::dmp::ExceptionStream_t::ExceptionRecord)
      .def_ro("ThreadContext",
              &udmpparser::dmp::ExceptionStream_t::ThreadContext);

  nb::class_<udmpparser::FileMap_t>(m, "FileMap")
      .def(nb::init<>())
      .def("ViewBase", &udmpparser::FileMap_t::ViewBase)
      .def("MapFile", &udmpparser::FileMap_t::MapFile)
      .def("InBounds", &udmpparser::FileMap_t::InBounds);

  nb::enum_<udmpparser::Arch_t>(m, "Arch")
      .value("X86", udmpparser::Arch_t::X86)
      .value("X64", udmpparser::Arch_t::X64)
      .export_values();

  nb::class_<udmpparser::MemBlock_t>(m, "MemBlock")
      .def(nb::init<const udmpparser::dmp::MemoryInfo_t &>())
      .def_ro("BaseAddress", &udmpparser::MemBlock_t::BaseAddress)
      .def_ro("AllocationBase", &udmpparser::MemBlock_t::AllocationBase)
      .def_ro("AllocationProtect", &udmpparser::MemBlock_t::AllocationProtect)
      .def_ro("RegionSize", &udmpparser::MemBlock_t::RegionSize)
      .def_ro("State", &udmpparser::MemBlock_t::State)
      .def_ro("Protect", &udmpparser::MemBlock_t::Protect)
      .def_ro("Type", &udmpparser::MemBlock_t::Type)
      .def_ro("Data", &udmpparser::MemBlock_t::Data, nb::rv_policy::reference)
      .def_ro("DataSize", &udmpparser::MemBlock_t::DataSize)
      .def("__repr__", &udmpparser::MemBlock_t::to_string);
  ;

  nb::class_<udmpparser::Module_t>(m, "Modules")
      .def(nb::init<const udmpparser::dmp::ModuleEntry_t &, const std::string &,
                    const void *, const void *>(),
           nb::rv_policy::take_ownership)
      .def_ro("BaseOfImage", &udmpparser::Module_t::BaseOfImage)
      .def_ro("SizeOfImage", &udmpparser::Module_t::SizeOfImage)
      .def_ro("CheckSum", &udmpparser::Module_t::CheckSum)
      .def_ro("TimeDateStamp", &udmpparser::Module_t::TimeDateStamp)
      .def_ro("ModuleName", &udmpparser::Module_t::ModuleName)
      .def_ro("VersionInfo", &udmpparser::Module_t::VersionInfo)
      .def_ro("CvRecord", &udmpparser::Module_t::CvRecord,
              nb::rv_policy::reference)
      .def_ro("CvRecordSize", &udmpparser::Module_t::CvRecordSize)
      .def_ro("MiscRecord", &udmpparser::Module_t::MiscRecord,
              nb::rv_policy::reference)
      .def_ro("MiscRecordSize", &udmpparser::Module_t::MiscRecordSize)
      .def("__repr__", &udmpparser::Module_t::to_string);

  nb::class_<udmpparser::UnknownContext_t>(m, "UnknownContext");

  nb::class_<udmpparser::Thread_t>(m, "Thread")
      .def(nb::init<const udmpparser::dmp::ThreadEntry_t &, const void *,
                    const std::optional<udmpparser::ProcessorArch_t> &>())
      .def_ro("ThreadId", &udmpparser::Thread_t::ThreadId)
      .def_ro("SuspendCount", &udmpparser::Thread_t::SuspendCount)
      .def_ro("PriorityClass", &udmpparser::Thread_t::PriorityClass)
      .def_ro("Priority", &udmpparser::Thread_t::Priority)
      .def_ro("Teb", &udmpparser::Thread_t::Teb)
      .def_ro("Context", &udmpparser::Thread_t::Context)
      .def("__repr__", &udmpparser::Thread_t::to_string);

  nb::class_<udmpparser::UserDumpParser>(m, "UserDumpParser")
      .def(nb::init<>())
      .def("Parse", &udmpparser::UserDumpParser::Parse,
           "Parse the minidump given in argument.")
      .def("Modules", &udmpparser::UserDumpParser::GetModules, nb::rv_policy::reference,
           "Get the minidump modules")
      .def("Memory", &udmpparser::UserDumpParser::GetMem,
           nb::rv_policy::reference)
      .def("Threads", &udmpparser::UserDumpParser::GetThreads,
           "Get the minidump threads")
      .def("ForegroundThreadId",
           &udmpparser::UserDumpParser::GetForegroundThreadId)
      .def("GetMemoryBlock", &udmpparser::UserDumpParser::GetMemBlock,
           "Access a specific MemoryBlock")
      .def("ReadMemory", &udmpparser::UserDumpParser::ReadMemory,
           "Read bytes from memory")
      .def("__repr__", &udmpparser::UserDumpParser::to_string);

  nb::class_<udmpparser::Version>(m, "version")
      .def_ro_static("major", &udmpparser::Version::Major)
      .def_ro_static("minor", &udmpparser::Version::Minor)
      .def_ro_static("release", &udmpparser::Version::Release)
      ;

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
      "Get a string representation of the memory state.");

  utils.def(
      "ProtectionToString",
      [](const uint32_t Protection) {
        std::stringstream ss;
        uint32_t KnownFlags = 0;

        if (Protection & 0x01) {
          ss << "PAGE_NOACCESS,";
          KnownFlags |= 0x01;
        }
        if (Protection & 0x02) {
          ss << "PAGE_READONLY,";
          KnownFlags |= 0x02;
        }
        if (Protection & 0x04) {
          ss << "PAGE_READWRITE,";
          KnownFlags |= 0x04;
        }
        if (Protection & 0x08) {
          ss << "PAGE_WRITECOPY,";
          KnownFlags |= 0x08;
        }
        if (Protection & 0x10) {
          ss << "PAGE_EXECUTE,";
          KnownFlags |= 0x10;
        }
        if (Protection & 0x20) {
          ss << "PAGE_EXECUTE_READ,";
          KnownFlags |= 0x20;
        }
        if (Protection & 0x40) {
          ss << "PAGE_EXECUTE_READWRITE,";
          KnownFlags |= 0x40;
        }
        if (Protection & 0x80) {
          ss << "PAGE_EXECUTE_WRITECOPY,";
          KnownFlags |= 0x80;
        }
        if (Protection & 0x100) {
          ss << "PAGE_GUARD,";
          KnownFlags |= 0x100;
        }
        if (Protection & 0x200) {
          ss << "PAGE_NOCACHE,";
          KnownFlags |= 0x200;
        }
        if (Protection & 0x400) {
          ss << "PAGE_WRITECOMBINE,";
          KnownFlags |= 0x400;
        }
        if (Protection & 0x4000'0000) {
          ss << "PAGE_TARGETS_INVALID,";
          KnownFlags |= 0x4000'0000;
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
      "Get a string representation of the memory state.");
}
