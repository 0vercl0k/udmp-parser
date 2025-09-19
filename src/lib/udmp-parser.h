// Axel '0vercl0k' Souchet - January 22 2022
#pragma once
#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace fs = std::filesystem;

#if defined(__i386__) || defined(_M_IX86)
#define ARCH_X86
#elif defined(__amd64__) || defined(_M_X64)
#define ARCH_X64
#elif defined(__arm__) || defined(_M_ARM)
#define ARCH_ARM
#elif defined(__aarch64__) || defined(_M_ARM64)
#define ARCH_AARCH64
#else
#error Platform not supported.
#endif

#if defined(_WIN32)

#define WINDOWS
#include <Windows.h>

#if defined(ARCH_X86)
#define WINDOWS_X86
#elif defined(ARCH_X64)
#define WINDOWS_X64
#elif defined(ARCH_ARM)
#define WINDOWS_ARM
#elif defined(ARCH_AARCH64)
#define WINDOWS_AARCH64
#endif // ARCH_XXX

#elif defined(linux) || defined(__linux) || defined(__FreeBSD__) ||            \
    defined(__FreeBSD_kernel__) || defined(__MACH__)

#define LINUX
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(ARCH_X86)
#define LINUX_X86
#elif defined(ARCH_X64)
#define LINUX_X64
#elif defined(ARCH_ARM)
#define LINUX_ARM
#elif defined(ARCH_AARCH64)
#define LINUX_AARCH64
#endif // ARCH_XXX

#else

#error Platform not supported.

#endif // _WIN32

namespace udmpparser {

#ifdef NDEBUG
static void DbgPrintf(const char *Format, ...) { (void)Format; }
#else
static void DbgPrintf(const char *Format, ...) {
  va_list ArgList;
  va_start(ArgList, Format);
  vfprintf(stderr, Format, ArgList);
  va_end(ArgList);
}
#endif

#pragma pack(push)
#pragma pack(1)

struct Version {
  static inline const uint16_t Major = 0;
  static inline const uint16_t Minor = 7;
  static inline const std::string Release = "";
};

enum class ProcessorArch_t : uint16_t {
  X86 = 0,
  ARM = 5,
  IA64 = 6,
  AMD64 = 9,
  Unknown = 0xffff
};

constexpr uint32_t kWOW64_SIZE_OF_80387_REGISTERS = 80;

struct FloatingSaveArea32_t {
  uint32_t ControlWord;
  uint32_t StatusWord;
  uint32_t TagWord;
  uint32_t ErrorOffset;
  uint32_t ErrorSelector;
  uint32_t DataOffset;
  uint32_t DataSelector;
  std::array<uint8_t, kWOW64_SIZE_OF_80387_REGISTERS> RegisterArea;
  uint32_t Cr0NpxState;
};

static_assert(sizeof(FloatingSaveArea32_t) == 0x70);

constexpr uint32_t kWOW64_MAXIMUM_SUPPORTED_EXTENSION = 512;

struct Context32_t {
  uint32_t ContextFlags;
  uint32_t Dr0;
  uint32_t Dr1;
  uint32_t Dr2;
  uint32_t Dr3;
  uint32_t Dr6;
  uint32_t Dr7;
  FloatingSaveArea32_t FloatSave;
  uint32_t SegGs;
  uint32_t SegFs;
  uint32_t SegEs;
  uint32_t SegDs;
  uint32_t Edi;
  uint32_t Esi;
  uint32_t Ebx;
  uint32_t Edx;
  uint32_t Ecx;
  uint32_t Eax;
  uint32_t Ebp;
  uint32_t Eip;
  uint32_t SegCs;
  uint32_t EFlags;
  uint32_t Esp;
  uint32_t SegSs;
  std::array<uint8_t, kWOW64_MAXIMUM_SUPPORTED_EXTENSION> ExtendedRegisters;
};

static_assert(sizeof(Context32_t) == 0x2cc);

struct uint128_t {
  uint64_t Low;
  uint64_t High;
};

static_assert(sizeof(uint128_t) == 0x10);

struct Context64_t {
  uint64_t P1Home;
  uint64_t P2Home;
  uint64_t P3Home;
  uint64_t P4Home;
  uint64_t P5Home;
  uint64_t P6Home;
  uint32_t ContextFlags;
  uint32_t MxCsr;
  uint16_t SegCs;
  uint16_t SegDs;
  uint16_t SegEs;
  uint16_t SegFs;
  uint16_t SegGs;
  uint16_t SegSs;
  uint32_t EFlags;
  uint64_t Dr0;
  uint64_t Dr1;
  uint64_t Dr2;
  uint64_t Dr3;
  uint64_t Dr6;
  uint64_t Dr7;
  uint64_t Rax;
  uint64_t Rcx;
  uint64_t Rdx;
  uint64_t Rbx;
  uint64_t Rsp;
  uint64_t Rbp;
  uint64_t Rsi;
  uint64_t Rdi;
  uint64_t R8;
  uint64_t R9;
  uint64_t R10;
  uint64_t R11;
  uint64_t R12;
  uint64_t R13;
  uint64_t R14;
  uint64_t R15;
  uint64_t Rip;
  uint16_t ControlWord;
  uint16_t StatusWord;
  uint8_t TagWord;
  uint8_t Reserved1;
  uint16_t ErrorOpcode;
  uint32_t ErrorOffset;
  uint16_t ErrorSelector;
  uint16_t Reserved2;
  uint32_t DataOffset;
  uint16_t DataSelector;
  uint16_t Reserved3;
  uint32_t MxCsr2;
  uint32_t MxCsr_Mask;
  std::array<uint128_t, 8> FloatRegisters;
  uint128_t Xmm0;
  uint128_t Xmm1;
  uint128_t Xmm2;
  uint128_t Xmm3;
  uint128_t Xmm4;
  uint128_t Xmm5;
  uint128_t Xmm6;
  uint128_t Xmm7;
  uint128_t Xmm8;
  uint128_t Xmm9;
  uint128_t Xmm10;
  uint128_t Xmm11;
  uint128_t Xmm12;
  uint128_t Xmm13;
  uint128_t Xmm14;
  uint128_t Xmm15;
  std::array<uint8_t, 0x60> Padding;
  std::array<uint128_t, 26> VectorRegister;
  uint64_t VectorControl;
  uint64_t DebugControl;
  uint64_t LastBranchToRip;
  uint64_t LastBranchFromRip;
  uint64_t LastExceptionToRip;
  uint64_t LastExceptionFromRip;
};

static_assert(offsetof(Context64_t, Xmm0) == 0x1a0);
static_assert(offsetof(Context64_t, VectorRegister) == 0x300);
static_assert(sizeof(Context64_t) == 0x4d0);

namespace dmp {

struct Header_t {
  static inline const uint32_t ExpectedSignature = 0x50'4d'44'4d; // 'PMDM';
  static inline const uint32_t ValidFlagsMask = 0x00'1f'ff'ff;
  uint32_t Signature;
  uint16_t Version;
  uint16_t ImplementationVersion;
  uint32_t NumberOfStreams;
  uint32_t StreamDirectoryRva;
  uint32_t CheckSum;
  uint32_t Reserved;
  uint32_t TimeDateStamp;
  uint32_t Flags;

  bool LooksGood() const {
    if (Signature != ExpectedSignature) {
      DbgPrintf("The signature (%" PRIx32
                ") does not match the expected signature.\n",
                Signature);
      return false;
    }

    if ((Flags & ValidFlagsMask) != Flags) {
      DbgPrintf("The flags have unknown bits set.\n");
      return false;
    }

    if (NumberOfStreams == 0) {
      DbgPrintf("There is no streams.\n");
      return false;
    }

    return true;
  }
};

static_assert(sizeof(Header_t) == 0x20);

struct LocationDescriptor32_t {
  uint32_t DataSize = 0;
  uint32_t Rva = 0;
};

static_assert(sizeof(LocationDescriptor32_t) == 0x8);

struct LocationDescriptor64_t {
  uint64_t DataSize = 0;
  uint64_t Rva = 0;
};

static_assert(sizeof(LocationDescriptor64_t) == 0x10);

enum class StreamType_t : uint32_t {
  Unused = 0,
  ThreadList = 3,
  ModuleList = 4,
  Exception = 6,
  SystemInfo = 7,
  Memory64List = 9,
  MemoryInfoList = 16,
};

struct Directory_t {
  StreamType_t StreamType = StreamType_t::Unused;
  LocationDescriptor32_t Location;
};

static_assert(sizeof(Directory_t) == 0x0c);

struct Memory64ListStreamHdr_t {
  uint64_t NumberOfMemoryRanges = 0;
  uint64_t BaseRva = 0;
};

static_assert(sizeof(Memory64ListStreamHdr_t) == 0x10);

struct MemoryDescriptor64_t {
  uint64_t StartOfMemoryRange = 0;
  uint64_t DataSize = 0;
};

static_assert(sizeof(MemoryDescriptor64_t) == 0x10);

struct FixedFileInfo_t {
  uint32_t Signature = 0;
  uint32_t StrucVersion = 0;
  uint32_t FileVersionMS = 0;
  uint32_t FileVersionLS = 0;
  uint32_t ProductVersionMS = 0;
  uint32_t ProductVersionLS = 0;
  uint32_t FileFlagsMask = 0;
  uint32_t FileFlags = 0;
  uint32_t FileOS = 0;
  uint32_t FileType = 0;
  uint32_t FileSubtype = 0;
  uint32_t FileDateMS = 0;
  uint32_t FileDateLS = 0;
};

static_assert(sizeof(FixedFileInfo_t) == 0x34);

struct ModuleEntry_t {
  uint64_t BaseOfImage = 0;
  uint32_t SizeOfImage = 0;
  uint32_t CheckSum = 0;
  uint32_t TimeDateStamp = 0;
  uint32_t ModuleNameRva = 0;
  FixedFileInfo_t VersionInfo;
  LocationDescriptor32_t CvRecord;
  LocationDescriptor32_t MiscRecord;
  uint64_t Reserved0 = 0;
  uint64_t Reserved1 = 0;
};

static_assert(sizeof(ModuleEntry_t) == 0x6c);

struct MemoryInfoListStream_t {
  uint32_t SizeOfHeader = 0;
  uint32_t SizeOfEntry = 0;
  uint64_t NumberOfEntries = 0;
};

static_assert(sizeof(MemoryInfoListStream_t) == 0x10);

struct MemoryInfo_t {
  uint64_t BaseAddress = 0;
  uint64_t AllocationBase = 0;
  uint32_t AllocationProtect = 0;
  uint32_t __alignment1 = 0;
  uint64_t RegionSize = 0;
  uint32_t State = 0;
  uint32_t Protect = 0;
  uint32_t Type = 0;
  uint32_t __alignment2 = 0;
};

static_assert(sizeof(MemoryInfo_t) == 0x30);

struct MemoryDescriptor_t {
  uint64_t StartOfMemoryRange = 0;
  LocationDescriptor32_t Memory;
};

static_assert(sizeof(MemoryDescriptor_t) == 0x10);

struct ThreadEntry_t {
  uint32_t ThreadId = 0;
  uint32_t SuspendCount = 0;
  uint32_t PriorityClass = 0;
  uint32_t Priority = 0;
  uint64_t Teb = 0;
  MemoryDescriptor_t Stack;
  LocationDescriptor32_t ThreadContext;
};

static_assert(sizeof(ThreadEntry_t) == 0x30);

struct SystemInfoStream_t {
  ProcessorArch_t ProcessorArchitecture = ProcessorArch_t::Unknown;
  uint16_t ProcessorLevel = 0;
  uint16_t ProcessorRevision = 0;
  uint8_t NumberOfProcessors = 0;
  uint8_t ProductType = 0;
  uint32_t MajorVersion = 0;
  uint32_t MinorVersion = 0;
  uint32_t BuildNumber = 0;
  uint32_t PlatformId = 0;
  uint32_t CSDVersionRva = 0;
  uint16_t SuiteMask = 0;
  uint16_t Reserved2 = 0;
};

static_assert(sizeof(SystemInfoStream_t) == 32);

constexpr uint32_t kEXCEPTION_MAXIMUM_PARAMETERS = 15;

struct ExceptionRecord_t {
  uint32_t ExceptionCode;
  uint32_t ExceptionFlags;
  uint64_t ExceptionRecord;
  uint64_t ExceptionAddress;
  uint32_t NumberParameters;
  uint32_t __unusedAlignment;
  std::array<uint64_t, kEXCEPTION_MAXIMUM_PARAMETERS> ExceptionInformation;
};

static_assert(sizeof(ExceptionRecord_t) == 0x98);

struct ExceptionStream_t {
  uint32_t ThreadId = 0;
  uint32_t __alignment = 0;
  ExceptionRecord_t ExceptionRecord;
  LocationDescriptor32_t ThreadContext;
};

static_assert(sizeof(ExceptionStream_t) == 0xa8);

} // namespace dmp
#pragma pack(pop)

class MemoryReader_t {
protected:
  std::span<uint8_t> View_;

public:
  MemoryReader_t() = default;
  virtual ~MemoryReader_t() = default;
  MemoryReader_t(const std::span<uint8_t> View) : View_(View) {}
  MemoryReader_t(MemoryReader_t &&) = default;
  MemoryReader_t(const MemoryReader_t &) = delete;
  MemoryReader_t &operator=(MemoryReader_t &&) = default;
  MemoryReader_t &operator=(const MemoryReader_t &) = delete;

  const uint8_t *ViewBase() const { return &View_.front(); }
  const uint8_t *ViewEnd() const { return &View_.back(); }
  const size_t ViewSize() const { return View_.size_bytes(); }

  bool Read(const size_t Offset, std::span<uint8_t> Dest) {
    const size_t EndOffset = Offset + Dest.size_bytes();
    if (EndOffset <= Offset) {
      DbgPrintf("Overflow detected for EndOffset.\n");
      return false;
    }

    if (EndOffset > View_.size_bytes()) {
      DbgPrintf("Read request would read OOB.\n");
      return false;
    }

    auto Subspan = View_.subspan(Offset, Dest.size());
    std::copy(Subspan.begin(), Subspan.end(), Dest.begin());
    return true;
  }

  template <typename Pod_t> bool ReadT(const size_t Offset, Pod_t &Dest) {
    std::span<uint8_t> Span((uint8_t *)&Dest, (uint8_t *)(&Dest + 1));
    return Read(Offset, Span);
  }

  bool ReadFromLocation32(const dmp::LocationDescriptor32_t &Location,
                          const size_t Offset, std::span<uint8_t> Dest) {
    if (Dest.size_bytes() == 0) {
      return true;
    }

    const size_t EndOffset = Offset + Dest.size_bytes();
    if (EndOffset <= Offset) {
      DbgPrintf("EndOffset overflow.\n");
      return false;
    }

    if (EndOffset > size_t(std::numeric_limits<uint32_t>::max())) {
      DbgPrintf("EndOffset is too large to be truncated to u32.\n");
      return false;
    }

    if (uint32_t(EndOffset) > Location.DataSize) {
      DbgPrintf("Reading more than what the directory contains.\n");
      return false;
    }

    const auto AbsoluteOffset = size_t(Location.Rva) + Offset;
    if (AbsoluteOffset <= Offset) {
      DbgPrintf("AbsoluteOffset overflow.\n");
      return false;
    }

    return Read(AbsoluteOffset, Dest);
  }

  template <typename Pod_t>
  bool ReadTFromDirectory(const dmp::Directory_t &Directory,
                          const size_t Offset, Pod_t &Dest) {
    std::span<uint8_t> Span((uint8_t *)&Dest, (uint8_t *)(&Dest + 1));
    return ReadFromLocation32(Directory.Location, Offset, Span);
  }
};

#if defined(WINDOWS)
class FileMap_t : public MemoryReader_t {

  //
  // Handle to the file mapping.
  //

  HANDLE FileMap_ = nullptr;

public:
  ~FileMap_t() override {
    //
    // Unmap the view of the mapping..
    //

    if (!View_.empty()) {
      UnmapViewOfFile(View_.data());
    }

    //
    // Close the handle to the file mapping.
    //

    if (FileMap_ != nullptr) {
      CloseHandle(FileMap_);
    }
  }

  bool MapFile(const char *PathFile) {

    //
    // Open the dump file in read-only.
    //

    HANDLE File = CreateFileA(PathFile, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, 0, nullptr);

    if (File == nullptr) {

      //
      // If we fail to open the file, let the user know.
      //

      const DWORD GLE = GetLastError();
      DbgPrintf("CreateFile failed with GLE=%lu.\n", GLE);

      if (GLE == ERROR_FILE_NOT_FOUND) {
        DbgPrintf("The file %s was not found.\n", PathFile);
      }

      return false;
    }

    DWORD High = 0;
    const DWORD Low = GetFileSize(File, &High);
    const DWORD FileSize = (DWORD64(High) << 32) | DWORD64(Low);

    //
    // Create the ro file mapping.
    //

    HANDLE FileMap =
        CreateFileMappingA(File, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(File);

    if (FileMap == nullptr) {

      //
      // If we fail to create a file mapping, let
      // the user know.
      //

      const DWORD GLE = GetLastError();
      DbgPrintf("CreateFileMapping failed with GLE=%lu.\n", GLE);
      return false;
    }

    //
    // Map a view of the file in memory.
    //

    PVOID ViewBase = MapViewOfFile(FileMap, FILE_MAP_READ, 0, 0, 0);

    if (ViewBase == nullptr) {

      CloseHandle(FileMap);

      //
      // If we fail to map the view, let the user know.
      //

      const DWORD GLE = GetLastError();
      DbgPrintf("MapViewOfFile failed with GLE=%lu.\n", GLE);
      return false;
    }

    PVOID ViewEnd = (uint8_t *)ViewBase + FileSize;

    View_ = std::span((uint8_t *)ViewBase, (uint8_t *)ViewEnd);

    //
    // Everything went well, so grab a copy of the handles for
    // our class and null-out the temporary variables.
    //

    return true;
  }
};

#elif defined(LINUX)

class FileMap_t : public MemoryView_t {
  int Fd_ = -1;

public:
  ~FileMap_t() {
    if (!View_.empty()) {
      munmap((void *)ViewBase(), ViewSize());
    }

    if (Fd_ != -1) {
      close(Fd_);
    }
  }

  bool MapFile(const char *PathFile) {
    Fd_ = open(PathFile, O_RDONLY);
    if (Fd_ < 0) {
      perror("Could not open dump file");
      return false;
    }

    struct stat Stat;
    if (fstat(Fd_, &Stat) < 0) {
      perror("Could not stat dump file");
      return false;
    }

    uint8_t *ViewBase =
        mmap(nullptr, Stat.st_size, PROT_READ, MAP_SHARED, Fd_, 0);
    if (ViewBase == MAP_FAILED) {
      perror("Could not mmap");
      return false;
    }

    uint8_t *ViewEnd = ViewBase + Stat.st_size;
    View_ = std::span(ViewBase, ViewEnd);
    return true;
  }
};

#endif

enum class Arch_t { X86, X64 };

struct MemBlock_t {
  uint64_t BaseAddress = 0;
  uint64_t AllocationBase = 0;
  uint32_t AllocationProtect = 0;
  uint64_t RegionSize = 0;
  uint32_t State = 0;
  uint32_t Protect = 0;
  uint32_t Type = 0;
  uint64_t DataOffset = 0;
  uint64_t DataSize = 0;

  MemBlock_t(const dmp::MemoryInfo_t &Info_)
      : BaseAddress(Info_.BaseAddress), AllocationBase(Info_.AllocationBase),
        AllocationProtect(Info_.AllocationProtect),
        RegionSize(Info_.RegionSize), State(Info_.State),
        Protect(Info_.Protect), Type(Info_.Type) {};

  std::string to_string() const {
    std::stringstream ss;
    ss << "[MemBlock_t(";
    ss << "BaseAddress=0x" << std::hex << BaseAddress;
    ss << ", AllocationBase=0x" << AllocationBase;
    ss << ", AllocationProtect=0x" << AllocationProtect;
    ss << ", RegionSize=0x" << RegionSize;
    ss << ")]";
    return ss.str();
  }
};

struct Module_t {
  uint64_t BaseOfImage = 0;
  uint32_t SizeOfImage = 0;
  uint32_t CheckSum = 0;
  uint32_t TimeDateStamp = 0;
  std::string ModuleName;
  dmp::FixedFileInfo_t VersionInfo;
  std::vector<uint8_t> CvRecord;
  std::vector<uint8_t> MiscRecord;

  Module_t(const dmp::ModuleEntry_t &M, const std::string &Name,
           std::vector<uint8_t> CvRecord_, std::vector<uint8_t> MiscRecord_)
      : BaseOfImage(M.BaseOfImage), SizeOfImage(M.SizeOfImage),
        CheckSum(M.CheckSum), TimeDateStamp(M.TimeDateStamp), ModuleName(Name),
        VersionInfo(M.VersionInfo), CvRecord(std::move(CvRecord_)),
        MiscRecord(std::move(MiscRecord_)) {}

  std::string to_string() const {
    std::stringstream ss;
    ss << "Module_t(";
    ss << "BaseOfImage=0x" << std::hex << BaseOfImage;
    ss << ", SizeOfImage=0x" << SizeOfImage;
    ss << ", ModuleName=" << ModuleName;
    ss << ")";
    return ss.str();
  }
};

class UnknownContext_t {};

struct Thread_t {
  uint32_t ThreadId = 0;
  uint32_t SuspendCount = 0;
  uint32_t PriorityClass = 0;
  uint32_t Priority = 0;
  uint64_t Teb = 0;
  std::variant<UnknownContext_t, Context32_t, Context64_t> Context;
  Thread_t(const dmp::ThreadEntry_t &T, UnknownContext_t &UnknownContext)
      : Thread_t(T) {
    Context = UnknownContext;
  }

  Thread_t(const dmp::ThreadEntry_t &T, Context32_t &Context32) : Thread_t(T) {
    Context = Context32;
  }

  Thread_t(const dmp::ThreadEntry_t &T, Context64_t &Context64) : Thread_t(T) {
    Context = Context64;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "Thread(";
    ss << "Id=0x" << std::hex << ThreadId << ", ";
    ss << "SuspendCount=0x" << std::hex << SuspendCount << ", ";
    ss << "Teb=0x" << std::hex << Teb;
    ss << ")";
    return ss.str();
  }

private:
  Thread_t(const dmp::ThreadEntry_t &T)
      : ThreadId(T.ThreadId), SuspendCount(T.SuspendCount),
        PriorityClass(T.PriorityClass), Priority(T.Priority), Teb(T.Teb) {}
};

class UserDumpParser {
private:
  //
  // The memory map; base address -> mem.
  //

  std::map<uint64_t, MemBlock_t> Mem_;

  //
  // The architecture of the dumped process.
  //

  std::optional<ProcessorArch_t> Arch_;

  //
  // The list of loaded modules; base address -> module.
  //

  std::map<uint64_t, Module_t> Modules_;

  //
  // The thread id of the foreground thread.
  //

  std::optional<uint32_t> ForegroundThreadId_;

  //
  // The list of threads; thread id -> thread.
  //

  std::unordered_map<uint32_t, Thread_t> Threads_;

  //
  // Reader.
  //

  std::shared_ptr<MemoryReader_t> Reader_;

public:
  //
  // Parse the file.
  //

  bool Parse(const char *PathFile) {

    //
    // Map a view of the file.
    //

    if (!fs::exists(PathFile)) {
      DbgPrintf("The dump file specified does not exist.\n");
      return false;
    }

    auto FileMapReader = std::make_shared<FileMap_t>();
    if (!FileMapReader->MapFile(PathFile)) {
      DbgPrintf("MapFile failed.\n");
      return false;
    }

    Reader_ = std::move(FileMapReader);
    return Parse();
  }

  bool Parse(const fs::path &PathFile) {
    return Parse(PathFile.string().c_str());
  }

  //
  // Parse from memory view.
  //

  bool Parse(std::shared_ptr<MemoryReader_t> Reader) {
    if (!Reader) {
      DbgPrintf("The memory view passed is null.\n");
      return false;
    }

    Reader_ = std::move(Reader);
    return Parse();
  }

  const std::map<uint64_t, MemBlock_t> &GetMem() const { return Mem_; }

  const MemBlock_t *GetMemBlock(const void *Address) const {
    return GetMemBlock(uint64_t(Address));
  }

  const MemBlock_t *GetMemBlock(const uint64_t Address) const {
    auto It = Mem_.upper_bound(Address);
    if (It == Mem_.begin()) {
      return nullptr;
    }

    It--;
    const auto &[MemBlockAddress, MemBlock] = *It;
    if (Address >= MemBlockAddress &&
        Address < (MemBlockAddress + MemBlock.RegionSize)) {
      return &MemBlock;
    }

    return nullptr;
  }

  const Module_t *GetModule(const void *Address) const {
    return GetModule(uint64_t(Address));
  }

  const Module_t *GetModule(const uint64_t Address) const {

    //
    // Look for a module that includes this address.
    //

    const auto &Res =
        std::find_if(Modules_.begin(), Modules_.end(), [&](const auto &It) {
          return Address >= It.first &&
                 Address < (It.first + It.second.SizeOfImage);
        });

    //
    // If we have a match, return it!
    //

    if (Res != Modules_.end()) {
      return &Res->second;
    }

    return nullptr;
  }

  const std::map<uint64_t, Module_t> &GetModules() const { return Modules_; }

  const std::unordered_map<uint32_t, Thread_t> &GetThreads() const {
    return Threads_;
  }

  std::optional<uint32_t> GetForegroundThreadId() const {
    return ForegroundThreadId_;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "UserDumpParser(";
    ss << "ModuleNb=" << Modules_.size();
    ss << ", ThreadNb=" << Threads_.size();
    ss << ")";
    return ss.str();
  }

  std::optional<std::vector<uint8_t>> ReadMemory(const uint64_t Address,
                                                 const size_t Size) const {
    const auto &Block = GetMemBlock(Address);
    if (!Block) {
      return std::nullopt;
    }

    std::vector<uint8_t> Out;
    if (Block->DataSize == 0) {
      return Out;
    }

    const auto OffsetFromStart = Address - Block->BaseAddress;
    const auto RemainingSize = Block->DataSize - OffsetFromStart;
    if (RemainingSize > uint64_t(std::numeric_limits<size_t>::max())) {
      DbgPrintf("RemainingSize truncation to usize would be lossy.\n");
      return std::nullopt;
    }

    const auto DumpSize = std::min(size_t(RemainingSize), Size);
    Out.resize(DumpSize);
    if (!Reader_->Read(Block->DataOffset + OffsetFromStart, Out)) {
      DbgPrintf("Failed to ReadMemory.\n");
      return std::nullopt;
    }

    return Out;
  }

private:
  bool Parse() {

    //
    // Read the header..
    //

    dmp::Header_t Hdr;
    if (!Reader_->ReadT(0, Hdr)) {
      DbgPrintf("The header are not in bounds.\n");
      return false;
    }

    //
    // ..verify that it looks sane..
    //

    if (!Hdr.LooksGood()) {
      DbgPrintf("The header looks wrong.\n");
      return false;
    }

    //
    // .. walk through its directories.
    //

    std::unordered_map<dmp::StreamType_t, dmp::Directory_t> Directories;
    for (uint32_t StreamIdx = 0; StreamIdx < Hdr.NumberOfStreams; StreamIdx++) {
      //
      // Read the current directory..
      //

      const auto CurrentStreamDirectoryOffset =
          Hdr.StreamDirectoryRva + (StreamIdx * sizeof(dmp::Directory_t));
      dmp::Directory_t CurrentStreamDirectory;
      if (!Reader_->ReadT(CurrentStreamDirectoryOffset,
                          CurrentStreamDirectory)) {
        DbgPrintf("The stream directory %" PRIu32 " is out of the bounds.\n",
                  StreamIdx);
        return false;
      }

      //
      // ..skip unused ones..
      //

      if (CurrentStreamDirectory.StreamType == dmp::StreamType_t::Unused) {
        continue;
      }

      //
      // ..and keep track of the various stream encountered. If we see a stream
      // twice, bail as it isn't expected.
      //

      const auto &[_, Inserted] = Directories.try_emplace(
          CurrentStreamDirectory.StreamType, CurrentStreamDirectory);

      if (!Inserted) {
        DbgPrintf("There are more than one stream of type %" PRIu32 "\n",
                  uint32_t(CurrentStreamDirectory.StreamType));
        return false;
      }
    }

    //
    // Now, let's parse the stream in a specific order. Technically not
    // required, but it makes some logic easier to write.
    //

    const dmp::StreamType_t Order[] = {
        dmp::StreamType_t::SystemInfo,     dmp::StreamType_t::Exception,
        dmp::StreamType_t::MemoryInfoList, dmp::StreamType_t::Memory64List,
        dmp::StreamType_t::ThreadList,     dmp::StreamType_t::ModuleList};

    for (const auto &Type : Order) {

      //
      // If we have seen this stream, skip to the next.
      //

      const auto &Directory = Directories.find(Type);
      if (Directory == Directories.end()) {
        continue;
      }

      //
      // Parse the stream & bail the stream isn't recognized..
      //

      const auto &Result = ParseStream(Directory->second);
      if (!Result.has_value()) {
        DbgPrintf("Seems like there is a missing case for %" PRIu32
                  " in ParseStream?\n",
                  uint32_t(Type));
        return false;
      }

      //
      // ..or if the parsing of the stream has failed.
      //

      if (!Result.value()) {
        DbgPrintf("Failed to parse stream %" PRIu32 ".\n", uint32_t(Type));
        return false;
      }
    }

    //
    // If no foreground thread has been identified, then we're done.
    //

    if (!ForegroundThreadId_) {
      return true;
    }

    //
    // If we have one, ensure it exists in the list of threads, otherwise bail.
    //

    const bool ForegroundThreadExists =
        Threads_.find(*ForegroundThreadId_) != Threads_.end();
    if (!ForegroundThreadExists) {
      DbgPrintf("The Exception stream referenced a thread id that does not "
                "exist in the thread list.\n");
      return false;
    }

    return true;
  }

  std::optional<bool> ParseStream(const dmp::Directory_t &StreamDirectory) {

    //
    // Parse a stream if we know how to.
    //

    switch (StreamDirectory.StreamType) {
    case dmp::StreamType_t::Unused: {
      return true;
    }

    case dmp::StreamType_t::SystemInfo: {
      return ParseSystemInfoStream(StreamDirectory);
    }

    case dmp::StreamType_t::MemoryInfoList: {
      return ParseMemoryInfoListStream(StreamDirectory);
    }

    case dmp::StreamType_t::Memory64List: {
      return ParseMemory64ListStream(StreamDirectory);
    }

    case dmp::StreamType_t::ModuleList: {
      return ParseModuleListStream(StreamDirectory);
    }

    case dmp::StreamType_t::ThreadList: {
      return ParseThreadListStream(StreamDirectory);
    }

    case dmp::StreamType_t::Exception: {
      return ParseExceptionStream(StreamDirectory);
    }
    }

    return std::nullopt;
  }

  bool ParseExceptionStream(const dmp::Directory_t &StreamDirectory) {

    //
    // Read the exception stream..
    //

    dmp::ExceptionStream_t Exception;
    if (!Reader_->ReadTFromDirectory(StreamDirectory, 0, Exception)) {
      DbgPrintf("Failed to read ExceptionStream_t.\n");
      return false;
    }

    //
    // ..and grab the foreground TID (we ignore the rest).
    //

    ForegroundThreadId_ = Exception.ThreadId;
    return true;
  }

  bool ParseSystemInfoStream(const dmp::Directory_t &StreamDirectory) {

    //
    // Read the system infos stream..
    //

    dmp::SystemInfoStream_t SystemInfos;
    if (!Reader_->ReadTFromDirectory(StreamDirectory, 0, SystemInfos)) {
      DbgPrintf("The SystemInfo stream seems malformed.\n");
      return false;
    }

    //
    // ..and grab the processor architecture (we ignore the rest).
    //

    Arch_ = SystemInfos.ProcessorArchitecture;
    return true;
  }

  template <typename C_t>
  bool EmplaceThreadContext(const dmp::LocationDescriptor32_t &ThreadContext,
                            const dmp::ThreadEntry_t &Thread) {
    //
    // Make sure the that the thread context location is at least back enough to
    // read a `C_t`; otherwise bail.
    //

    C_t Context;
    if (ThreadContext.DataSize < sizeof(Context)) {
      DbgPrintf("The size of the Context doesn't match up with the thread "
                "context's length.\n");
      return false;
    }

    //
    // Read it..
    //

    if (!Reader_->ReadT(ThreadContext.Rva, Context)) {
      DbgPrintf("Failed to read Context for Thread %" PRIu32 ".\n",
                Thread.ThreadId);
      return false;
    }

    //
    // ..and create a `Thread_t`.
    //

    Threads_.try_emplace(Thread.ThreadId, Thread, Context);
    return true;
  }

  bool ParseThreadListStream(const dmp::Directory_t &StreamDirectory) {

    //
    // Read the number of thread..
    //

    uint32_t NumberOfThreads = 0;
    if (!Reader_->ReadTFromDirectory(StreamDirectory, 0, NumberOfThreads)) {
      DbgPrintf("The size of the ThreadList stream is not right.\n");
      return false;
    }

    //
    // ..and walk through every one of them.
    //

    for (uint32_t ThreadIdx = 0; ThreadIdx < NumberOfThreads; ThreadIdx++) {

      //
      // Read the thread entry which follows the `uint32_t` that contains the
      // number of threads..
      //

      dmp::ThreadEntry_t CurrentThread;
      const auto ThreadEntryOffset =
          sizeof(NumberOfThreads) + (ThreadIdx * sizeof(CurrentThread));
      if (!Reader_->ReadTFromDirectory(StreamDirectory, ThreadEntryOffset,
                                       CurrentThread)) {
        DbgPrintf("Failed to read Thread[%" PRIu32 ".\n");
        return false;
      }

      //
      // ..and figure out what kind of context do we expect depending on the
      // architecture if we have found any.
      //

      const auto &ThreadContext = CurrentThread.ThreadContext;
      bool Success = false;
      if (Arch_.has_value()) {
        switch (Arch_.value()) {
        case ProcessorArch_t::X86: {
          Success =
              EmplaceThreadContext<Context32_t>(ThreadContext, CurrentThread);
          break;
        }

        case ProcessorArch_t::AMD64: {
          Success =
              EmplaceThreadContext<Context64_t>(ThreadContext, CurrentThread);
          break;
        }

        default: {
          Success = EmplaceThreadContext<UnknownContext_t>(ThreadContext,
                                                           CurrentThread);
          break;
        }
        }
      } else {
        Success = EmplaceThreadContext<UnknownContext_t>(ThreadContext,
                                                         CurrentThread);
      }

      if (!Success) {
        return false;
      }
    }

    return true;
  }

  bool ParseMemoryInfoListStream(const dmp::Directory_t &StreamDirectory) {

    //
    // Read the memory info list stream..
    //

    dmp::MemoryInfoListStream_t MemoryInfoList;
    if (!Reader_->ReadTFromDirectory(StreamDirectory, 0, MemoryInfoList)) {
      DbgPrintf("Failed to read MemoryInfoListStream_t.\n");
      return false;
    }

    //
    // ..check that the header looks right..
    //

    if (MemoryInfoList.SizeOfHeader < sizeof(MemoryInfoList)) {
      DbgPrintf("The size of the MemoryInfoList header is not right.\n");
      return false;
    }

    //
    // ..check that the size of the entries looks right..
    //

    if (MemoryInfoList.SizeOfEntry < sizeof(dmp::MemoryInfo_t)) {
      DbgPrintf("The size of the MemoryInfo entries are not right.\n");
      return false;
    }

    //
    // ..and finally check that the size of the stream is what we think it
    // should be.
    //

    const uint64_t MaxEntries = std::numeric_limits<uint64_t>::max() /
                                uint64_t(MemoryInfoList.SizeOfEntry);
    if (MemoryInfoList.NumberOfEntries > MaxEntries) {
      DbgPrintf("Too many entries.\n");
      return false;
    }

    const uint64_t EntryOffset =
        uint64_t(MemoryInfoList.SizeOfEntry) * MemoryInfoList.NumberOfEntries;
    const uint64_t CalculatedStreamSize =
        uint64_t(MemoryInfoList.SizeOfHeader) + EntryOffset;
    if (CalculatedStreamSize <= EntryOffset) {
      DbgPrintf("Overflow with size of header.\n");
      return false;
    }

    if (CalculatedStreamSize != uint64_t(StreamDirectory.Location.DataSize)) {
      DbgPrintf("The MemoryInfoList stream size is not right.\n");
      return false;
    }

    //
    // Walk through the entries..
    //

    for (uint64_t MemoryInfoIdx = 0;
         MemoryInfoIdx < MemoryInfoList.NumberOfEntries; MemoryInfoIdx++) {
      //
      // ..read the entry..
      //

      const uint64_t CurrentMemoryInfoOffset =
          uint64_t(MemoryInfoList.SizeOfHeader) +
          (uint64_t(MemoryInfoList.SizeOfEntry) * MemoryInfoIdx);
      dmp::MemoryInfo_t CurrentMemoryInfo;
      if (!Reader_->ReadTFromDirectory(StreamDirectory, CurrentMemoryInfoOffset,
                                       CurrentMemoryInfo)) {
        return false;
      }

      //
      // ..and insert it in the map. If we've already seen this entry, bail.
      //

      const uint64_t BaseAddress = CurrentMemoryInfo.BaseAddress;
      const auto &[_, Inserted] =
          Mem_.try_emplace(BaseAddress, CurrentMemoryInfo);

      if (!Inserted) {
        DbgPrintf("The region %" PRIx64 " is already in the memory map.\n",
                  BaseAddress);
        return false;
      }
    }

    return true;
  }

  bool ParseModuleListStream(const dmp::Directory_t &StreamDirectory) {

    //
    // Read the number of modules..
    //

    uint32_t NumberOfModules;
    if (!Reader_->ReadTFromDirectory(StreamDirectory, 0, NumberOfModules)) {
      DbgPrintf("Failed to read NumberOfModules.\n");
      return false;
    }

    //
    // ..and walk through the entries.
    //

    for (uint32_t ModuleIdx = 0; ModuleIdx < NumberOfModules; ModuleIdx++) {
      //
      // Read the entry..
      //

      dmp::ModuleEntry_t CurrentModule;
      const size_t CurrentModuleOffset =
          sizeof(NumberOfModules) + (sizeof(CurrentModule) * size_t(ModuleIdx));
      if (!Reader_->ReadTFromDirectory(StreamDirectory, CurrentModuleOffset,
                                       CurrentModule)) {
        DbgPrintf("Failed to read module entry.\n");
        return false;
      }

      //
      // ..read the length of the module name..
      //

      const uint32_t ModuleNameLengthOffset = CurrentModule.ModuleNameRva;
      uint32_t ModuleNameLength;
      if (!Reader_->ReadT(ModuleNameLengthOffset, ModuleNameLength)) {
        DbgPrintf("Failed to read NameLengthOffset.\n");
        return false;
      }

      //
      // ..verify that it is well formed..
      //

      const bool WellFormed = (ModuleNameLength % 2) == 0;
      if (!WellFormed) {
        DbgPrintf("The MINIDUMP_STRING for the module index %" PRIu32
                  " is not well formed.\n",
                  ModuleIdx);
        return false;
      }

      //
      // ..and finally read the module name.
      //

      const size_t ModuleNameOffset =
          size_t(ModuleNameLengthOffset) + sizeof(ModuleNameLength);
      std::string ModuleName(ModuleNameLength, 0);
      std::span<uint8_t> ModuleNameSpan((uint8_t *)&ModuleName.front(),
                                        (uint8_t *)&ModuleName.back());
      if (!Reader_->Read(ModuleNameOffset, ModuleNameSpan)) {
        DbgPrintf("Failed to read the module name.\n");
        return false;
      }

      //
      // The module name is UTF16, so assume it is ASCII encoded so skip every
      // second bytes.
      //

      for (size_t CharIdx = 0; CharIdx < ModuleNameLength; CharIdx += 2) {
        if (!isprint(ModuleName[CharIdx])) {
          DbgPrintf("The MINIDUMP_STRING for the module index %" PRIu32
                    " has a non printable ascii character.\n",
                    ModuleIdx);
          return false;
        }

        ModuleName[CharIdx / 2] = ModuleName[CharIdx];
      }

      //
      // Resize the module name buffer when we read all its ASCII characters.
      //

      ModuleName.resize(ModuleNameLength / 2);
      ModuleName.shrink_to_fit();

      //
      // Read the Cv record..
      //

      std::vector<uint8_t> CvRecord(CurrentModule.CvRecord.DataSize);
      if (!Reader_->ReadFromLocation32(CurrentModule.CvRecord, 0, CvRecord)) {
        DbgPrintf("Failed to read CvRecord.\n");
        return false;
      }

      //
      // ..read the Misc record..
      //

      std::vector<uint8_t> MiscRecord(CurrentModule.MiscRecord.DataSize);
      if (!Reader_->ReadFromLocation32(CurrentModule.MiscRecord, 0,
                                       MiscRecord)) {
        DbgPrintf("Failed to read MiscRecord.\n");
        return false;
      }

      //
      // ..and finally create a `Module_t`.
      //

      Modules_.try_emplace(CurrentModule.BaseOfImage, CurrentModule, ModuleName,
                           std::move(CvRecord), std::move(MiscRecord));
    }

    return true;
  }

  bool ParseMemory64ListStream(const dmp::Directory_t &StreamDirectory) {

    //
    // Read the memory 64 list header..
    //

    dmp::Memory64ListStreamHdr_t Memory64List;
    if (!Reader_->ReadTFromDirectory(StreamDirectory, 0, Memory64List)) {
      DbgPrintf("Failed to read Memory64ListStreamHdr_t.\n");
      return false;
    }

    //
    // Grab the offset of where the actual memory content is stored at.
    //

    const uint64_t NumberOfMemoryRanges = Memory64List.NumberOfMemoryRanges;
    uint64_t CurrentDataOffset = Memory64List.BaseRva;

    //
    // Walk through the entries..
    //

    for (uint32_t RangeIdx = 0; RangeIdx < NumberOfMemoryRanges; RangeIdx++) {

      //
      // ..read a descriptor..
      //

      dmp::MemoryDescriptor64_t CurrentDescriptor;
      const size_t CurrentDescriptorOffset =
          sizeof(Memory64List) + (sizeof(CurrentDescriptor) * size_t(RangeIdx));

      if (!Reader_->ReadTFromDirectory(StreamDirectory, CurrentDescriptorOffset,
                                       CurrentDescriptor)) {
        DbgPrintf("Failed to read MemoryDescriptor64_t.\n");
        return false;
      }

      //
      // ..and if no existing entry is found, something funky is going on.
      //

      const uint64_t StartOfMemoryRange = CurrentDescriptor.StartOfMemoryRange;
      const auto &It = Mem_.find(StartOfMemoryRange);
      if (It == Mem_.end()) {
        DbgPrintf("The memory region starting at %" PRIx64
                  " does not exist in the map.\n",
                  StartOfMemoryRange);
        return false;
      }

      //
      // Update the entry.
      //

      const size_t DataSize = size_t(CurrentDescriptor.DataSize);
      It->second.DataOffset = CurrentDataOffset;
      It->second.DataSize = DataSize;
      CurrentDataOffset += DataSize;
    }

    return true;
  }
};
} // namespace udmpparser
