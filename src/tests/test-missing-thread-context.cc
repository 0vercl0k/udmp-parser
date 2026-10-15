#include "udmp-parser.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <variant>
#include <vector>

namespace {

template <typename T>
void Write(std::vector<uint8_t> &Dump, const size_t Offset, const T &Value) {
  std::memcpy(Dump.data() + Offset, &Value, sizeof(Value));
}

std::vector<uint8_t> MakeDump(const uint32_t ContextSize,
                              const uint32_t ContextRva) {
  using namespace udmpparser;

  constexpr size_t HeaderOffset = 0;
  constexpr size_t DirectoryOffset = sizeof(dmp::Header_t);
  constexpr size_t DirectoryCount = 2;
  constexpr size_t SystemInfoOffset =
      DirectoryOffset + DirectoryCount * sizeof(dmp::Directory_t);
  constexpr size_t ThreadListOffset =
      SystemInfoOffset + sizeof(dmp::SystemInfoStream_t);
  constexpr size_t DumpSize =
      ThreadListOffset + sizeof(uint32_t) + sizeof(dmp::ThreadEntry_t) + 1;

  std::vector<uint8_t> Dump(DumpSize);

  dmp::Header_t Header = {};
  Header.Signature = dmp::Header_t::ExpectedSignature;
  Header.NumberOfStreams = static_cast<uint32_t>(DirectoryCount);
  Header.StreamDirectoryRva = static_cast<uint32_t>(DirectoryOffset);
  Write(Dump, HeaderOffset, Header);

  dmp::Directory_t SystemInfoDirectory = {};
  SystemInfoDirectory.StreamType = dmp::StreamType_t::SystemInfo;
  SystemInfoDirectory.Location.DataSize =
      static_cast<uint32_t>(sizeof(dmp::SystemInfoStream_t));
  SystemInfoDirectory.Location.Rva =
      static_cast<uint32_t>(SystemInfoOffset);
  Write(Dump, DirectoryOffset, SystemInfoDirectory);

  dmp::Directory_t ThreadListDirectory = {};
  ThreadListDirectory.StreamType = dmp::StreamType_t::ThreadList;
  ThreadListDirectory.Location.DataSize =
      static_cast<uint32_t>(sizeof(uint32_t) + sizeof(dmp::ThreadEntry_t));
  ThreadListDirectory.Location.Rva =
      static_cast<uint32_t>(ThreadListOffset);
  Write(Dump, DirectoryOffset + sizeof(dmp::Directory_t),
        ThreadListDirectory);

  dmp::SystemInfoStream_t SystemInfo = {};
  SystemInfo.ProcessorArchitecture = ProcessorArch_t::AMD64;
  Write(Dump, SystemInfoOffset, SystemInfo);

  const uint32_t ThreadCount = 1;
  Write(Dump, ThreadListOffset, ThreadCount);

  dmp::ThreadEntry_t Thread = {};
  Thread.ThreadId = 0x24e4;
  Thread.ThreadContext.DataSize = ContextSize;
  Thread.ThreadContext.Rva = ContextRva;
  Write(Dump, ThreadListOffset + sizeof(ThreadCount), Thread);

  return Dump;
}

int TestMissingContextIsAccepted() {
  using namespace udmpparser;

  const auto Dump = MakeDump(0, 0);
  auto Reader = std::make_shared<MemoryReader_t>(
      std::span<const uint8_t>(Dump.data(), Dump.size()));
  UserDumpParser Parser;
  if (!Parser.Parse(std::move(Reader))) {
    std::cerr << "A thread without a context rejected the dump.\n";
    return 1;
  }

  const auto &Threads = Parser.GetThreads();
  const auto Thread = Threads.find(0x24e4);
  if (Thread == Threads.end()) {
    std::cerr << "The context-less thread was not retained.\n";
    return 1;
  }

  if (!std::holds_alternative<UnknownContext_t>(Thread->second.Context)) {
    std::cerr << "The missing context was not represented as unknown.\n";
    return 1;
  }

  return 0;
}

int TestTruncatedContextIsRejected() {
  using namespace udmpparser;

  constexpr uint32_t ContextRva = 1;
  const auto Dump = MakeDump(1, ContextRva);
  auto Reader = std::make_shared<MemoryReader_t>(
      std::span<const uint8_t>(Dump.data(), Dump.size()));
  UserDumpParser Parser;
  if (Parser.Parse(std::move(Reader))) {
    std::cerr << "A truncated non-empty AMD64 context was accepted.\n";
    return 1;
  }

  return 0;
}

} // namespace

int main() {
  if (TestMissingContextIsAccepted() != 0) {
    return 1;
  }

  return TestTruncatedContextIsRejected();
}
