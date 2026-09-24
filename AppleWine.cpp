#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commdlg.h>
#include <oleauto.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <stdexcept>
#include <thread>
#include <vector>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "User32.lib")

namespace fs = std::filesystem;

namespace macho {
constexpr uint32_t MH_MAGIC_64 = 0xFEEDFACF;
constexpr int32_t CPU_TYPE_ARM64 = 0x0100000C;
constexpr uint32_t MH_EXECUTE = 0x2;

constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_LOAD_DYLIB = 0x0C;
constexpr uint32_t LC_LOAD_WEAK_DYLIB = 0x80000018;
constexpr uint32_t LC_REEXPORT_DYLIB = 0x8000001F;
constexpr uint32_t LC_LOAD_UPWARD_DYLIB = 0x80000023;
constexpr uint32_t LC_LAZY_LOAD_DYLIB = 0x20;
constexpr uint32_t LC_RPATH = 0x8000001C;
constexpr uint32_t LC_MAIN = 0x80000028;
constexpr uint32_t LC_BUILD_VERSION = 0x32;
constexpr uint32_t LC_DYLD_EXPORTS_TRIE = 0x80000033;
constexpr uint32_t LC_DYLD_CHAINED_FIXUPS = 0x80000034;
constexpr uint32_t LC_CODE_SIGNATURE = 0x1D;

constexpr uint16_t DYLD_CHAINED_PTR_ARM64E = 1;
constexpr uint16_t DYLD_CHAINED_PTR_64 = 2;
constexpr uint16_t DYLD_CHAINED_PTR_64_OFFSET = 6;
constexpr uint16_t DYLD_CHAINED_PTR_ARM64E_USERLAND = 9;
constexpr uint16_t DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12;
constexpr uint32_t DYLD_CHAINED_PTR_START_NONE = 0xFFFF;
constexpr uint32_t DYLD_CHAINED_PTR_START_MULTI = 0x8000;
constexpr uint32_t DYLD_CHAINED_IMPORT = 1;
constexpr uint32_t DYLD_CHAINED_IMPORT_ADDEND = 2;
constexpr uint32_t DYLD_CHAINED_IMPORT_ADDEND64 = 3;

#pragma pack(push, 1)
struct mach_header_64 {
    uint32_t magic;
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t maxprot;
    int32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct entry_point_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};

struct rpath_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t path_offset;
};

struct build_version_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};
#pragma pack(pop)

struct Segment {
    std::string name;
    uint64_t vmaddr = 0;
    uint64_t vmsize = 0;
    uint64_t fileoff = 0;
    uint64_t filesize = 0;
    int32_t initprot = 0;
};

struct ParsedImage {
    mach_header_64 header{};
    std::vector<Segment> segments;
    std::vector<std::string> dylibs;
    std::vector<std::string> rpaths;
    std::optional<uint64_t> entryoff;
    std::optional<uint64_t> entryVm;
    std::optional<uint32_t> platform;
    std::optional<uint32_t> minos;
    std::optional<uint32_t> sdk;
    bool hasChainedFixups = false;
    bool hasExportsTrie = false;
    bool hasCodeSignature = false;
    std::optional<linkedit_data_command> chainedFixups;
};
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return L"<invalid utf8>";
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

static std::wstring Hex(uint64_t v) {
    std::wstringstream ss;
    ss << L"0x" << std::uppercase << std::hex << v;
    return ss.str();
}

static std::vector<uint8_t> ReadAll(const fs::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("cannot open file");
    const auto end = f.tellg();
    if (end < 0) throw std::runtime_error("cannot get file size");
    const size_t size = static_cast<size_t>(end);
    std::vector<uint8_t> data(size);
    f.seekg(0, std::ios::beg);
    if (size && !f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size)))
        throw std::runtime_error("cannot read file");
    return data;
}

static bool LooksLikeMachO64(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    uint32_t magic = 0;
    return !!(f.read(reinterpret_cast<char*>(&magic), sizeof(magic)) && magic == macho::MH_MAGIC_64);
}

static std::string FixedName(const char* p, size_t n) {
    size_t len = 0;
    while (len < n && p[len] != '\0') ++len;
    return std::string(p, p + len);
}

static std::string LoadCommandString(const std::vector<uint8_t>& data,
                                     size_t cmdFileOffset,
                                     uint32_t cmdsize,
                                     uint32_t stringOffset) {
    if (stringOffset >= cmdsize) return "<bad-offset>";
    const size_t begin = cmdFileOffset + stringOffset;
    const size_t end = cmdFileOffset + cmdsize;
    if (begin >= data.size() || end > data.size() || begin >= end) return "<bad-range>";
    size_t z = begin;
    while (z < end && data[z] != 0) ++z;
    return std::string(reinterpret_cast<const char*>(data.data() + begin), z - begin);
}

static macho::ParsedImage ParseMachO(const std::vector<uint8_t>& data) {
    using namespace macho;
    if (data.size() < sizeof(mach_header_64)) throw std::runtime_error("Mach-O is too small");

    ParsedImage out;
    std::memcpy(&out.header, data.data(), sizeof(out.header));
    if (out.header.magic != MH_MAGIC_64) throw std::runtime_error("not a little-endian Mach-O 64 image");

    const uint64_t commandsEnd64 = static_cast<uint64_t>(sizeof(mach_header_64)) + out.header.sizeofcmds;
    if (commandsEnd64 > data.size()) throw std::runtime_error("load command table is truncated");
    if (out.header.ncmds > 100000) throw std::runtime_error("unreasonable Mach-O command count");

    size_t off = sizeof(mach_header_64);
    for (uint32_t i = 0; i < out.header.ncmds; ++i) {
        if (off + sizeof(load_command) > data.size()) throw std::runtime_error("truncated load command");
        load_command lc{};
        std::memcpy(&lc, data.data() + off, sizeof(lc));
        if (lc.cmdsize < sizeof(load_command) || static_cast<uint64_t>(off) + lc.cmdsize > data.size())
            throw std::runtime_error("invalid load command size");

        if (lc.cmd == LC_SEGMENT_64 && lc.cmdsize >= sizeof(segment_command_64)) {
            segment_command_64 seg{};
            std::memcpy(&seg, data.data() + off, sizeof(seg));
            if (seg.fileoff > data.size() || seg.filesize > data.size() - static_cast<size_t>(seg.fileoff))
                throw std::runtime_error("segment points outside file");
            out.segments.push_back({FixedName(seg.segname, sizeof(seg.segname)), seg.vmaddr, seg.vmsize,
                                    seg.fileoff, seg.filesize, seg.initprot});
        } else if ((lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_LOAD_WEAK_DYLIB ||
                    lc.cmd == LC_REEXPORT_DYLIB || lc.cmd == LC_LOAD_UPWARD_DYLIB ||
                    lc.cmd == LC_LAZY_LOAD_DYLIB) && lc.cmdsize >= sizeof(dylib_command)) {
            dylib_command dc{};
            std::memcpy(&dc, data.data() + off, sizeof(dc));
            out.dylibs.push_back(LoadCommandString(data, off, lc.cmdsize, dc.name_offset));
        } else if (lc.cmd == LC_RPATH && lc.cmdsize >= sizeof(rpath_command)) {
            rpath_command rc{};
            std::memcpy(&rc, data.data() + off, sizeof(rc));
            out.rpaths.push_back(LoadCommandString(data, off, lc.cmdsize, rc.path_offset));
        } else if (lc.cmd == LC_MAIN && lc.cmdsize >= sizeof(entry_point_command)) {
            entry_point_command ec{};
            std::memcpy(&ec, data.data() + off, sizeof(ec));
            out.entryoff = ec.entryoff;
        } else if (lc.cmd == LC_BUILD_VERSION && lc.cmdsize >= sizeof(build_version_command)) {
            build_version_command bc{};
            std::memcpy(&bc, data.data() + off, sizeof(bc));
            out.platform = bc.platform;
            out.minos = bc.minos;
            out.sdk = bc.sdk;
        } else if (lc.cmd == LC_DYLD_CHAINED_FIXUPS && lc.cmdsize >= sizeof(linkedit_data_command)) {
            out.hasChainedFixups = true;
            linkedit_data_command fc{};
            std::memcpy(&fc, data.data() + off, sizeof(fc));
            if (static_cast<uint64_t>(fc.dataoff) + fc.datasize > data.size())
                throw std::runtime_error("chained fixups payload exceeds Mach-O file");
            out.chainedFixups = fc;
        } else if (lc.cmd == LC_DYLD_EXPORTS_TRIE) {
            out.hasExportsTrie = true;
        } else if (lc.cmd == LC_CODE_SIGNATURE) {
            out.hasCodeSignature = true;
        }

        off += lc.cmdsize;
    }

    if (out.entryoff) {
        auto it = std::find_if(out.segments.begin(), out.segments.end(), [](const Segment& s) { return s.name == "__TEXT"; });
        if (it != out.segments.end()) out.entryVm = it->vmaddr + *out.entryoff;
    }
    return out;
}

static std::wstring VersionString(uint32_t v) {
    std::wstringstream ss;
    ss << ((v >> 16) & 0xFFFF) << L'.' << ((v >> 8) & 0xFF) << L'.' << (v & 0xFF);
    return ss.str();
}

static std::wstring PlatformName(uint32_t p) {
    switch (p) {
    case 1: return L"macOS";
    case 2: return L"iOS";
    case 3: return L"tvOS";
    case 4: return L"watchOS";
    case 5: return L"bridgeOS";
    case 6: return L"Mac Catalyst";
    case 7: return L"iOS Simulator";
    case 8: return L"tvOS Simulator";
    case 9: return L"watchOS Simulator";
    case 10: return L"DriverKit";
    case 11: return L"visionOS";
    case 12: return L"visionOS Simulator";
    default: return L"platform " + std::to_wstring(p);
    }
}

static DWORD WinProtectFromVmProt(int32_t prot) {
    const bool r = (prot & 1) != 0;
    const bool w = (prot & 2) != 0;
    const bool x = (prot & 4) != 0;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x) return PAGE_EXECUTE;
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

struct MappedImage {
    uint8_t* base = nullptr;
    size_t size = 0;
    uint64_t minVm = 0;
    ~MappedImage() { if (base) VirtualFree(base, 0, MEM_RELEASE); }
    MappedImage() = default;
    MappedImage(const MappedImage&) = delete;
    MappedImage& operator=(const MappedImage&) = delete;
    MappedImage(MappedImage&& o) noexcept : base(o.base), size(o.size), minVm(o.minVm) { o.base = nullptr; o.size = 0; }
    MappedImage& operator=(MappedImage&& o) noexcept {
        if (this != &o) {
            if (base) VirtualFree(base, 0, MEM_RELEASE);
            base = o.base; size = o.size; minVm = o.minVm;
            o.base = nullptr; o.size = 0;
        }
        return *this;
    }
};

static MappedImage MapMachOSegments(const std::vector<uint8_t>& file, const macho::ParsedImage& img) {
    uint64_t lo = std::numeric_limits<uint64_t>::max();
    uint64_t hi = 0;
    for (const auto& s : img.segments) {
        if (s.name == "__PAGEZERO" || s.vmsize == 0) continue;
        lo = std::min(lo, s.vmaddr);
        if (s.vmaddr > std::numeric_limits<uint64_t>::max() - s.vmsize)
            throw std::runtime_error("segment VM range overflow");
        hi = std::max(hi, s.vmaddr + s.vmsize);
    }
    if (lo == std::numeric_limits<uint64_t>::max() || hi <= lo)
        throw std::runtime_error("no mappable Mach-O segments");

    const uint64_t span64 = hi - lo;
    if (span64 > 1024ull * 1024ull * 1024ull)
        throw std::runtime_error("image mapping is larger than 1 GiB");
    const size_t span = static_cast<size_t>(span64);

    MappedImage mapped;
    mapped.base = static_cast<uint8_t*>(VirtualAlloc(nullptr, span, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!mapped.base) throw std::runtime_error("VirtualAlloc failed");
    mapped.size = span;
    mapped.minVm = lo;

    for (const auto& s : img.segments) {
        if (s.name == "__PAGEZERO" || s.vmsize == 0) continue;
        const uint64_t dstOff64 = s.vmaddr - lo;
        if (dstOff64 > span || s.vmsize > span - static_cast<size_t>(dstOff64))
            throw std::runtime_error("segment exceeds mapped image");
        if (s.filesize) {
            if (s.fileoff > file.size() || s.filesize > file.size() - static_cast<size_t>(s.fileoff))
                throw std::runtime_error("segment file range exceeds Mach-O");
            std::memcpy(mapped.base + static_cast<size_t>(dstOff64),
                        file.data() + static_cast<size_t>(s.fileoff),
                        static_cast<size_t>(s.filesize));
        }
    }

    return mapped;
}

static void ProtectMappedMachOSegments(const macho::ParsedImage& img, MappedImage& mapped) {
    for (const auto& s : img.segments) {
        if (s.name == "__PAGEZERO" || s.vmsize == 0) continue;
        DWORD oldProtect = 0;
        const size_t dstOff = static_cast<size_t>(s.vmaddr - mapped.minVm);
        if (!VirtualProtect(mapped.base + dstOff, static_cast<SIZE_T>(s.vmsize),
                            WinProtectFromVmProt(s.initprot), &oldProtect)) {
            throw std::runtime_error("VirtualProtect failed while finalizing Mach-O segments");
        }
    }
    FlushInstructionCache(GetCurrentProcess(), mapped.base, mapped.size);
}



// ------------------------------
// Stage 2: small AArch64 interpreter
// ------------------------------

static int64_t SignExtend64(uint64_t value, unsigned bits) {
    if (bits == 0 || bits >= 64) return static_cast<int64_t>(value);
    const uint64_t m = 1ull << (bits - 1);
    return static_cast<int64_t>((value ^ m) - m);
}

// -----------------------------------------------------------------------------
// Stage 2.5: dyld chained fixups
// -----------------------------------------------------------------------------

struct GuestImport {
    std::string name;
    std::string dylib;
    int64_t addend = 0;
    bool weak = false;
    uint64_t guestAddress = 0;
};

struct GuestLinker {
    static constexpr uint64_t kImportBase = 0x0000006000000000ull;

    std::vector<GuestImport> imports;
    size_t rebases = 0;
    size_t binds = 0;
    size_t chainEntries = 0;
    std::vector<uint16_t> pointerFormats;
    bool applied = false;

    const GuestImport* Lookup(uint64_t address) const {
        if (address < kImportBase) return nullptr;
        const uint64_t delta = address - kImportBase;
        if (delta % 0x20 != 0) return nullptr;
        const size_t index = static_cast<size_t>(delta / 0x20);
        return index < imports.size() ? &imports[index] : nullptr;
    }
};

template <typename T>
static T ReadPod(const std::vector<uint8_t>& data, size_t offset, const char* what) {
    if (offset > data.size() || sizeof(T) > data.size() - offset)
        throw std::runtime_error(std::string("truncated ") + what);
    T value{};
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return value;
}

static std::string ReadCStringAt(const std::vector<uint8_t>& data, size_t offset, const char* what) {
    if (offset >= data.size()) throw std::runtime_error(std::string("bad ") + what + " offset");
    size_t end = offset;
    while (end < data.size() && data[end] != 0) ++end;
    if (end == data.size()) throw std::runtime_error(std::string("unterminated ") + what);
    return std::string(reinterpret_cast<const char*>(data.data() + offset), end - offset);
}

static bool GuestRangeInImage(const macho::ParsedImage& img, const MappedImage& mapped,
                              uint64_t address, size_t size) {
    for (const auto& s : img.segments) {
        if (s.name == "__PAGEZERO" || s.vmsize == 0) continue;
        if (address >= s.vmaddr && address <= s.vmaddr + s.vmsize &&
            static_cast<uint64_t>(size) <= s.vmaddr + s.vmsize - address) {
            const uint64_t off = address - mapped.minVm;
            return off <= mapped.size && static_cast<uint64_t>(size) <= mapped.size - off;
        }
    }
    return false;
}

static uint64_t ReadMappedWord(const macho::ParsedImage& img, const MappedImage& mapped,
                               uint64_t address, size_t size) {
    if (size != 4 && size != 8 || !GuestRangeInImage(img, mapped, address, size))
        throw std::runtime_error("chained fixup points outside mapped image");
    uint64_t value = 0;
    std::memcpy(&value, mapped.base + static_cast<size_t>(address - mapped.minVm), size);
    return value;
}

static void WriteMappedWord(const macho::ParsedImage& img, MappedImage& mapped,
                            uint64_t address, uint64_t value, size_t size) {
    if (size != 4 && size != 8 || !GuestRangeInImage(img, mapped, address, size))
        throw std::runtime_error("chained fixup write is outside mapped image");
    std::memcpy(mapped.base + static_cast<size_t>(address - mapped.minVm), &value, size);
}

static std::string DylibForOrdinal(const macho::ParsedImage& img, int32_t ordinal) {
    if (ordinal > 0 && static_cast<size_t>(ordinal) <= img.dylibs.size())
        return img.dylibs[static_cast<size_t>(ordinal - 1)];
    if (ordinal == 0) return "self";
    if (ordinal == -1) return "flat-lookup";
    if (ordinal == -2) return "weak-lookup";
    if (ordinal == -3) return "self-reexport";
    return "ordinal " + std::to_string(ordinal);
}

static GuestLinker ApplyChainedFixups(const std::vector<uint8_t>& file,
                                      const macho::ParsedImage& img, MappedImage& mapped) {
    GuestLinker linker;
    if (!img.chainedFixups) return linker;

    const auto& command = *img.chainedFixups;
    const size_t payload = command.dataoff;
    const size_t payloadSize = command.datasize;
    const auto header = ReadPod<macho::mach_header_64>(file, 0, "Mach-O header");
    (void)header;
    if (payloadSize < 28) throw std::runtime_error("chained fixups payload is too small");

    const uint32_t version = ReadPod<uint32_t>(file, payload + 0, "chained fixups version");
    const uint32_t startsOffset = ReadPod<uint32_t>(file, payload + 4, "chained starts offset");
    const uint32_t importsOffset = ReadPod<uint32_t>(file, payload + 8, "chained imports offset");
    const uint32_t symbolsOffset = ReadPod<uint32_t>(file, payload + 12, "chained symbols offset");
    const uint32_t importsCount = ReadPod<uint32_t>(file, payload + 16, "chained imports count");
    const uint32_t importsFormat = ReadPod<uint32_t>(file, payload + 20, "chained imports format");
    const uint32_t symbolsFormat = ReadPod<uint32_t>(file, payload + 24, "chained symbols format");
    if (version != 0) throw std::runtime_error("unsupported chained fixups version");
    if (symbolsFormat != 0) throw std::runtime_error("compressed chained fixup symbols are unsupported");
    if (startsOffset >= payloadSize || importsOffset >= payloadSize || symbolsOffset >= payloadSize)
        throw std::runtime_error("chained fixup table offset exceeds payload");

    size_t importSize = 0;
    if (importsFormat == macho::DYLD_CHAINED_IMPORT) importSize = 4;
    else if (importsFormat == macho::DYLD_CHAINED_IMPORT_ADDEND) importSize = 8;
    else if (importsFormat == macho::DYLD_CHAINED_IMPORT_ADDEND64) importSize = 16;
    else throw std::runtime_error("unsupported chained import format");
    if (importsCount > (payloadSize - importsOffset) / importSize)
        throw std::runtime_error("chained import table is truncated");

    linker.imports.reserve(importsCount);
    for (uint32_t i = 0; i < importsCount; ++i) {
        const size_t off = payload + importsOffset + static_cast<size_t>(i) * importSize;
        int32_t libOrdinal = 0;
        uint32_t nameOffset = 0;
        int64_t addend = 0;
        bool weak = false;
        if (importsFormat == macho::DYLD_CHAINED_IMPORT || importsFormat == macho::DYLD_CHAINED_IMPORT_ADDEND) {
            const uint32_t raw = ReadPod<uint32_t>(file, off, "chained import");
            libOrdinal = static_cast<int8_t>(raw & 0xFFu);
            weak = ((raw >> 8) & 1u) != 0;
            nameOffset = raw >> 9;
            if (importsFormat == macho::DYLD_CHAINED_IMPORT_ADDEND)
                addend = ReadPod<int32_t>(file, off + 4, "chained import addend");
        } else {
            const uint64_t raw = ReadPod<uint64_t>(file, off, "64-bit chained import");
            libOrdinal = static_cast<int16_t>(raw & 0xFFFFu);
            weak = ((raw >> 16) & 1u) != 0;
            nameOffset = static_cast<uint32_t>(raw >> 32);
            addend = static_cast<int64_t>(ReadPod<uint64_t>(file, off + 8, "64-bit chained import addend"));
        }
        const size_t nameAt = payload + symbolsOffset + nameOffset;
        if (nameAt < payload || nameAt >= payload + payloadSize)
            throw std::runtime_error("chained import name exceeds payload");
        GuestImport item;
        item.name = ReadCStringAt(file, nameAt, "chained import name");
        item.dylib = DylibForOrdinal(img, libOrdinal);
        item.addend = addend;
        item.weak = weak;
        item.guestAddress = GuestLinker::kImportBase + static_cast<uint64_t>(i) * 0x20;
        linker.imports.push_back(std::move(item));
    }

    const uint32_t segCount = ReadPod<uint32_t>(file, payload + startsOffset, "chained segment count");
    if (segCount > 4096) throw std::runtime_error("unreasonable chained segment count");
    const size_t offsetsAt = payload + startsOffset + 4;
    if (segCount > (payloadSize - startsOffset - 4) / 4)
        throw std::runtime_error("chained segment offset table is truncated");

    for (uint32_t segIndex = 0; segIndex < segCount; ++segIndex) {
        const uint32_t segmentInfoOffset = ReadPod<uint32_t>(file, offsetsAt + segIndex * 4, "chained segment offset");
        if (segmentInfoOffset == 0) continue;
        if (segmentInfoOffset >= payloadSize - startsOffset || segIndex >= img.segments.size())
            throw std::runtime_error("chained segment info is invalid");
        // seg_info_offset[] entries are relative to the starts-in-image
        // structure, not to the beginning of the complete fixup payload.
        const size_t si = payload + startsOffset + segmentInfoOffset;
        const uint32_t structSize = ReadPod<uint32_t>(file, si + 0, "chained segment size");
        const uint16_t pageSize = ReadPod<uint16_t>(file, si + 4, "chained page size");
        const uint16_t pointerFormat = ReadPod<uint16_t>(file, si + 6, "chained pointer format");
        const uint64_t segmentOffset = ReadPod<uint64_t>(file, si + 8, "chained segment vm offset");
        // dyld_chained_starts_in_segment layout:
        //   +16 max_valid_pointer (uint32_t)
        //   +20 page_count       (uint16_t)
        //   +22 page_start[]     (uint16_t[])
        const uint16_t pageCount = ReadPod<uint16_t>(file, si + 20, "chained page count");
        if (pageSize == 0 || pageCount == 0) continue;
        if (structSize < 22ull + static_cast<uint64_t>(pageCount) * 2 ||
            structSize > payloadSize - startsOffset - segmentInfoOffset)
            throw std::runtime_error("chained segment page table is truncated");
        const bool is64 = pointerFormat == macho::DYLD_CHAINED_PTR_64 ||
                          pointerFormat == macho::DYLD_CHAINED_PTR_64_OFFSET;
        const bool isArm64e = pointerFormat == macho::DYLD_CHAINED_PTR_ARM64E ||
                              pointerFormat == macho::DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                              pointerFormat == macho::DYLD_CHAINED_PTR_ARM64E_USERLAND24;
        if (!is64 && !isArm64e)
            throw std::runtime_error("unsupported chained pointer format " + std::to_string(pointerFormat));
        linker.pointerFormats.push_back(pointerFormat);
        const size_t stride = isArm64e ? 8 : 4;
        const size_t wordSize = 8;
        const auto& segment = img.segments[segIndex];
        // segment_offset is relative to the image's VM base, not relative to
        // the selected segment's own vmaddr. For a normal image it equals
        // segment.vmaddr - mapped.minVm.
        if (segment.vmaddr < mapped.minVm || segmentOffset != segment.vmaddr - mapped.minVm)
            throw std::runtime_error("chained segment offset does not match Mach-O segment");

        for (uint16_t page = 0; page < pageCount; ++page) {
            const uint16_t pageStart = ReadPod<uint16_t>(file, si + 22 + page * 2, "chained page start");
            if (pageStart == macho::DYLD_CHAINED_PTR_START_NONE) continue;
            if (pageStart & macho::DYLD_CHAINED_PTR_START_MULTI)
                throw std::runtime_error("multi-start chained pages are not supported yet");
            uint64_t address = mapped.minVm + segmentOffset + static_cast<uint64_t>(page) * pageSize + pageStart;
            size_t chainSteps = 0;
            for (;;) {
                if (++chainSteps > 10000) throw std::runtime_error("chained pointer loop detected");
                const uint64_t raw = ReadMappedWord(img, mapped, address, wordSize);
                const bool bind = is64 ? ((raw >> 63) & 1) != 0 : ((raw >> 62) & 1) != 0;
                uint64_t next = is64 ? ((raw >> 51) & 0xFFFu) : ((raw >> 51) & 0x7FFu);
                if (bind) {
                    const uint32_t ordinal = static_cast<uint32_t>(raw & (is64 ? 0xFFFFFFu :
                        pointerFormat == macho::DYLD_CHAINED_PTR_ARM64E_USERLAND24 ? 0xFFFFFFu : 0xFFFFu));
                    if (ordinal >= linker.imports.size())
                        throw std::runtime_error("chained bind ordinal exceeds import table");
                    int64_t inlineAddend = 0;
                    if (is64) inlineAddend = static_cast<int64_t>((raw >> 24) & 0xFFu);
                    else inlineAddend = SignExtend64((raw >> 32) & 0x7FFFFu, 19);
                    const uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(linker.imports[ordinal].guestAddress) +
                                                                    linker.imports[ordinal].addend + inlineAddend);
                    WriteMappedWord(img, mapped, address, target, wordSize);
                    ++linker.binds;
                } else {
                    uint64_t target = 0;
                    if (is64) {
                        target = raw & ((1ull << 36) - 1);
                        target |= ((raw >> 36) & 0xFFu) << 56;
                        if (pointerFormat == macho::DYLD_CHAINED_PTR_64_OFFSET)
                            target += mapped.minVm;
                    } else if (pointerFormat == macho::DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                               pointerFormat == macho::DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                        const bool authenticated = ((raw >> 63) & 1) != 0;
                        if (authenticated) {
                            target = (raw & 0xFFFFFFFFull) + mapped.minVm;
                        } else {
                            target = raw & ((1ull << 43) - 1);
                            target |= ((raw >> 43) & 0xFFu) << 56;
                            target += mapped.minVm;
                        }
                    } else {
                        target = raw & ((1ull << 43) - 1);
                        target |= ((raw >> 43) & 0xFFu) << 56;
                    }
                    WriteMappedWord(img, mapped, address, target, wordSize);
                    ++linker.rebases;
                }
                ++linker.chainEntries;
                if (next == 0) break;
                address += next * stride;
                const uint64_t pageEnd = mapped.minVm + segmentOffset +
                                          static_cast<uint64_t>(page + 1) * pageSize;
                if (address + wordSize > pageEnd)
                    throw std::runtime_error("chained pointer crosses page boundary");
            }
        }
    }
    linker.applied = true;
    return linker;
}

static uint64_t RotateRight(uint64_t value, unsigned amount, unsigned width) {
    amount %= width;
    if (!amount) return width == 32 ? static_cast<uint32_t>(value) : value;
    if (width == 32) {
        const uint32_t v = static_cast<uint32_t>(value);
        return static_cast<uint32_t>((v >> amount) | (v << (32 - amount)));
    }
    return (value >> amount) | (value << (64 - amount));
}

struct Arm64Cpu {
    std::array<uint64_t, 31> x{};
    std::array<std::array<uint8_t, 16>, 32> v{};
    uint64_t sp = 0;
    uint64_t pc = 0;
    bool N = false;
    bool Z = false;
    bool C = false;
    bool V = false;

    uint64_t ReadReg(unsigned r, bool reg31IsSp, unsigned width = 64) const {
        uint64_t v = 0;
        if (r == 31) v = reg31IsSp ? sp : 0;
        else v = x[r];
        return width == 32 ? static_cast<uint32_t>(v) : v;
    }

    void WriteReg(unsigned r, uint64_t v, bool reg31IsSp, unsigned width = 64) {
        if (width == 32) v = static_cast<uint32_t>(v);
        if (r == 31) {
            if (reg31IsSp) sp = v;
            return; // XZR/WZR discard writes.
        }
        x[r] = v;
    }
};

class Arm64Memory {
public:
    static constexpr uint64_t kStackBase = 0x0000007000000000ull;
    static constexpr size_t kStackSize = 4 * 1024 * 1024;
    static constexpr uint64_t kHeapBase = 0x0000007100000000ull;
    static constexpr size_t kHeapSize = 16 * 1024 * 1024;
    static constexpr uint64_t kReturnSentinel = 0x0000007FFFFFFFF0ull;

    Arm64Memory(const macho::ParsedImage& img, MappedImage& mapped)
        : img_(img), mapped_(mapped), stack_(kStackSize, 0), heap_(kHeapSize, 0) {}

    uint64_t StackTop() const { return kStackBase + stack_.size(); }

    bool IsExecutable(uint64_t addr) const {
        for (const auto& s : img_.segments) {
            if (s.name == "__PAGEZERO" || !(s.initprot & 4) || s.vmsize == 0) continue;
            if (addr >= s.vmaddr && addr < s.vmaddr + s.vmsize) return true;
        }
        return false;
    }

    bool Read(uint64_t addr, void* out, size_t n, std::string& why) const {
        if (!n) return true;
        if (RangeInside(kStackBase, stack_.size(), addr, n)) {
            std::memcpy(out, stack_.data() + static_cast<size_t>(addr - kStackBase), n);
            return true;
        }
        if (RangeInside(kHeapBase, heap_.size(), addr, n)) {
            std::memcpy(out, heap_.data() + static_cast<size_t>(addr - kHeapBase), n);
            return true;
        }
        const macho::Segment* seg = FindSegment(addr, n);
        if (!seg) {
            why = "read from unmapped guest address " + NarrowHex(addr);
            return false;
        }
        if (!(seg->initprot & 1) && !(seg->initprot & 4)) {
            why = "read from non-readable segment " + seg->name + " at " + NarrowHex(addr);
            return false;
        }
        const uint64_t off = addr - mapped_.minVm;
        if (off > mapped_.size || n > mapped_.size - static_cast<size_t>(off)) {
            why = "read exceeds mapped host image";
            return false;
        }
        std::memcpy(out, mapped_.base + static_cast<size_t>(off), n);
        return true;
    }

    bool Write(uint64_t addr, const void* in, size_t n, std::string& why) {
        if (!n) return true;
        if (RangeInside(kStackBase, stack_.size(), addr, n)) {
            std::memcpy(stack_.data() + static_cast<size_t>(addr - kStackBase), in, n);
            return true;
        }
        if (RangeInside(kHeapBase, heap_.size(), addr, n)) {
            std::memcpy(heap_.data() + static_cast<size_t>(addr - kHeapBase), in, n);
            return true;
        }
        const macho::Segment* seg = FindSegment(addr, n);
        if (!seg) {
            why = "write to unmapped guest address " + NarrowHex(addr);
            return false;
        }
        if (!(seg->initprot & 2)) {
            why = "write to non-writable segment " + seg->name + " at " + NarrowHex(addr);
            return false;
        }
        const uint64_t off = addr - mapped_.minVm;
        if (off > mapped_.size || n > mapped_.size - static_cast<size_t>(off)) {
            why = "write exceeds mapped host image";
            return false;
        }
        std::memcpy(mapped_.base + static_cast<size_t>(off), in, n);
        return true;
    }

    template <typename T>
    bool ReadValue(uint64_t addr, T& v, std::string& why) const {
        return Read(addr, &v, sizeof(v), why);
    }

    template <typename T>
    bool WriteValue(uint64_t addr, T v, std::string& why) {
        return Write(addr, &v, sizeof(v), why);
    }

    uint64_t Alloc(uint64_t requested, std::string& why) {
        const uint64_t size = std::max<uint64_t>(requested, 1);
        const uint64_t aligned = (size + 15) & ~15ull;
        if (heapCursor_ > heap_.size() || aligned > heap_.size() - heapCursor_) {
            why = "synthetic guest heap exhausted";
            return 0;
        }
        const uint64_t result = kHeapBase + heapCursor_;
        heapCursor_ += aligned;
        return result;
    }

    bool Copy(uint64_t dst, uint64_t src, size_t n, std::string& why) {
        std::vector<uint8_t> temp(n);
        if (!Read(src, temp.data(), n, why)) return false;
        return Write(dst, temp.data(), n, why);
    }

private:
    static bool RangeInside(uint64_t base, uint64_t size, uint64_t addr, size_t n) {
        if (addr < base) return false;
        const uint64_t rel = addr - base;
        return rel <= size && static_cast<uint64_t>(n) <= size - rel;
    }

    const macho::Segment* FindSegment(uint64_t addr, size_t n) const {
        for (const auto& s : img_.segments) {
            if (s.name == "__PAGEZERO" || s.vmsize == 0) continue;
            if (RangeInside(s.vmaddr, s.vmsize, addr, n)) return &s;
        }
        return nullptr;
    }

    static std::string NarrowHex(uint64_t v) {
        std::ostringstream ss;
        ss << "0x" << std::uppercase << std::hex << v;
        return ss.str();
    }

    const macho::ParsedImage& img_;
    MappedImage& mapped_;
    std::vector<uint8_t> stack_;
    std::vector<uint8_t> heap_;
    uint64_t heapCursor_ = 0;
};

static void SetNZ(Arm64Cpu& c, uint64_t value, unsigned width) {
    if (width == 32) {
        const uint32_t v = static_cast<uint32_t>(value);
        c.N = (v >> 31) != 0;
        c.Z = (v == 0);
    } else {
        c.N = (value >> 63) != 0;
        c.Z = (value == 0);
    }
}

static uint64_t AddWithFlags(Arm64Cpu& c, uint64_t a, uint64_t b, unsigned width) {
    if (width == 32) {
        const uint32_t aa = static_cast<uint32_t>(a), bb = static_cast<uint32_t>(b);
        const uint64_t wide = static_cast<uint64_t>(aa) + bb;
        const uint32_t r = static_cast<uint32_t>(wide);
        SetNZ(c, r, 32);
        c.C = (wide >> 32) != 0;
        c.V = ((~(aa ^ bb) & (aa ^ r)) >> 31) != 0;
        return r;
    }
    const uint64_t r = a + b;
    SetNZ(c, r, 64);
    c.C = r < a;
    c.V = ((~(a ^ b) & (a ^ r)) >> 63) != 0;
    return r;
}

static uint64_t SubWithFlags(Arm64Cpu& c, uint64_t a, uint64_t b, unsigned width) {
    if (width == 32) {
        const uint32_t aa = static_cast<uint32_t>(a), bb = static_cast<uint32_t>(b);
        const uint32_t r = aa - bb;
        SetNZ(c, r, 32);
        c.C = aa >= bb;
        c.V = (((aa ^ bb) & (aa ^ r)) >> 31) != 0;
        return r;
    }
    const uint64_t r = a - b;
    SetNZ(c, r, 64);
    c.C = a >= b;
    c.V = (((a ^ b) & (a ^ r)) >> 63) != 0;
    return r;
}

static bool ConditionHolds(const Arm64Cpu& c, unsigned cond) {
    switch (cond & 15) {
    case 0x0: return c.Z;
    case 0x1: return !c.Z;
    case 0x2: return c.C;
    case 0x3: return !c.C;
    case 0x4: return c.N;
    case 0x5: return !c.N;
    case 0x6: return c.V;
    case 0x7: return !c.V;
    case 0x8: return c.C && !c.Z;
    case 0x9: return !c.C || c.Z;
    case 0xA: return c.N == c.V;
    case 0xB: return c.N != c.V;
    case 0xC: return !c.Z && (c.N == c.V);
    case 0xD: return c.Z || (c.N != c.V);
    case 0xE: return true;
    default: return false;
    }
}

static const wchar_t* CondName(unsigned cond) {
    static const wchar_t* names[16] = {
        L"eq", L"ne", L"hs", L"lo", L"mi", L"pl", L"vs", L"vc",
        L"hi", L"ls", L"ge", L"lt", L"gt", L"le", L"al", L"nv"
    };
    return names[cond & 15];
}

static std::wstring RegName(unsigned r, unsigned width, bool reg31IsSp) {
    if (r == 31) return reg31IsSp ? (width == 32 ? L"wsp" : L"sp") : (width == 32 ? L"wzr" : L"xzr");
    return std::wstring(width == 32 ? L"w" : L"x") + std::to_wstring(r);
}

static uint64_t ShiftOperand(uint64_t v, unsigned shift, unsigned amount, unsigned width) {
    if (width == 32) v = static_cast<uint32_t>(v);
    amount %= width;
    switch (shift & 3) {
    case 0: return width == 32 ? static_cast<uint32_t>(v << amount) : (v << amount); // LSL
    case 1: return width == 32 ? static_cast<uint32_t>(v) >> amount : (v >> amount); // LSR
    case 2:
        if (width == 32) return static_cast<uint32_t>(static_cast<int32_t>(v) >> amount);
        return static_cast<uint64_t>(static_cast<int64_t>(v) >> amount); // ASR
    default: return RotateRight(v, amount, width);
    }
}

struct Arm64RunResult {
    Arm64Cpu cpu{};
    size_t steps = 0;
    uint64_t stopPc = 0;
    std::wstring reason;
    std::vector<std::wstring> trace;
};

enum class StepDisposition { Continue, Stop };

static StepDisposition StopAt(Arm64Cpu& c, std::wstring& reason, const std::wstring& text) {
    (void)c;
    reason = text;
    return StepDisposition::Stop;
}

static bool ImportNameHas(const std::string& name, const char* needle) {
    return name.find(needle) != std::string::npos;
}

static StepDisposition ReturnFromGuestImport(Arm64Cpu& c, Arm64Memory& mem,
                                             const GuestImport& import,
                                             std::wstring& stopReason) {
    if (c.x[30] == Arm64Memory::kReturnSentinel)
        return StopAt(c, stopReason, L"guest import returned through the synthetic LC_MAIN caller: " +
                      Utf8ToWide(import.name));
    c.pc = c.x[30];
    if (!mem.IsExecutable(c.pc))
        return StopAt(c, stopReason, L"guest import return address is outside executable code: " + Hex(c.pc));
    return StepDisposition::Continue;
}

static StepDisposition HandleGuestImport(Arm64Cpu& c, Arm64Memory& mem,
                                         const GuestImport& import,
                                         std::wstring& decoded, std::wstring& stopReason) {
    decoded += L" [shim: " + Utf8ToWide(import.name) + L"]";
    std::string why;

    if (ImportNameHas(import.name, "UIApplicationMain") ||
        ImportNameHas(import.name, "UIApplication") ||
        ImportNameHas(import.name, "WKWebView") ||
        ImportNameHas(import.name, "MTLCreateSystemDefaultDevice")) {
        return StopAt(c, stopReason, L"reached an unimplemented iOS framework boundary: " +
                      Utf8ToWide(import.name) + L" from " + Utf8ToWide(import.dylib));
    }
    if (ImportNameHas(import.name, "abort") || ImportNameHas(import.name, "stack_chk_fail"))
        return StopAt(c, stopReason, L"guest called fatal runtime import: " + Utf8ToWide(import.name));
    if (ImportNameHas(import.name, "exit"))
        return StopAt(c, stopReason, L"guest called exit(" + std::to_wstring(c.x[0]) + L")");

    if (ImportNameHas(import.name, "malloc")) {
        c.x[0] = mem.Alloc(c.x[0], why);
        if (!c.x[0]) return StopAt(c, stopReason, Utf8ToWide(why));
    } else if (ImportNameHas(import.name, "calloc")) {
        const uint64_t count = c.x[0];
        const uint64_t size = c.x[1];
        if (count && size > std::numeric_limits<uint64_t>::max() / count)
            return StopAt(c, stopReason, L"guest calloc size overflow");
        c.x[0] = mem.Alloc(count * size, why);
        if (!c.x[0]) return StopAt(c, stopReason, Utf8ToWide(why));
    } else if (ImportNameHas(import.name, "free")) {
        c.x[0] = 0;
    } else if (ImportNameHas(import.name, "memcpy") || ImportNameHas(import.name, "memmove")) {
        if (c.x[2] > 64ull * 1024ull * 1024ull)
            return StopAt(c, stopReason, L"guest memory copy is unreasonably large");
        if (!mem.Copy(c.x[0], c.x[1], static_cast<size_t>(c.x[2]), why))
            return StopAt(c, stopReason, Utf8ToWide(why));
    } else if (ImportNameHas(import.name, "memset")) {
        if (c.x[2] > 64ull * 1024ull * 1024ull)
            return StopAt(c, stopReason, L"guest memset is unreasonably large");
        std::vector<uint8_t> bytes(static_cast<size_t>(c.x[2]), static_cast<uint8_t>(c.x[1]));
        if (!mem.Write(c.x[0], bytes.data(), bytes.size(), why))
            return StopAt(c, stopReason, Utf8ToWide(why));
    } else if (ImportNameHas(import.name, "strlen")) {
        uint64_t length = 0;
        for (; length < 16ull * 1024ull * 1024ull; ++length) {
            uint8_t ch = 0;
            if (!mem.Read(c.x[0] + length, &ch, 1, why)) return StopAt(c, stopReason, Utf8ToWide(why));
            if (!ch) break;
        }
        if (length == 16ull * 1024ull * 1024ull)
            return StopAt(c, stopReason, L"guest strlen exceeded safety limit");
        c.x[0] = length;
    } else if (ImportNameHas(import.name, "strcmp")) {
        int result = 0;
        for (size_t i = 0; i < 1024 * 1024; ++i) {
            uint8_t a = 0, b = 0;
            if (!mem.Read(c.x[0] + i, &a, 1, why) || !mem.Read(c.x[1] + i, &b, 1, why))
                return StopAt(c, stopReason, Utf8ToWide(why));
            if (a != b) { result = a < b ? -1 : 1; break; }
            if (!a) break;
        }
        c.x[0] = static_cast<uint64_t>(static_cast<int64_t>(result));
    } else if (ImportNameHas(import.name, "objc_opt_self")) {
        // objc_opt_self is an objc_msgSend fast-path that returns the
        // receiver unchanged. It is commonly emitted by modern Apple SDKs.
    } else if (ImportNameHas(import.name, "objc_opt_class") ||
               ImportNameHas(import.name, "objc_opt_isKindOfClass") ||
               ImportNameHas(import.name, "objc_opt_respondsToSelector")) {
        // The probe has no class table yet. Returning a neutral value keeps
        // execution inside the guest until the next meaningful boundary.
        c.x[0] = 0;
    } else if (ImportNameHas(import.name, "swift_allocObject")) {
        // Swift's first arguments are metadata, size and alignment mask.
        // The synthetic heap is zeroed and 16-byte aligned, which is enough
        // for the startup probe and preserves the returned guest pointer.
        c.x[0] = mem.Alloc(c.x[1], why);
        if (!c.x[0]) return StopAt(c, stopReason, Utf8ToWide(why));
    } else if (ImportNameHas(import.name, "swift_deallocObject")) {
        // No reclamation is needed during the bounded probe.
    } else if (ImportNameHas(import.name, "swift_retain") ||
               ImportNameHas(import.name, "swift_retain_n") ||
               ImportNameHas(import.name, "swift_bridgeObjectRetain") ||
               ImportNameHas(import.name, "swift_unknownObjectRetain")) {
        // ARC retain operations return the object unchanged.
    } else if (ImportNameHas(import.name, "swift_release") ||
               ImportNameHas(import.name, "swift_release_n") ||
               ImportNameHas(import.name, "swift_bridgeObjectRelease") ||
               ImportNameHas(import.name, "swift_unknownObjectRelease")) {
        // Reference counts are intentionally omitted in the probe runtime.
    } else if (ImportNameHas(import.name, "objc_retain") ||
               ImportNameHas(import.name, "objc_autorelease") ||
               ImportNameHas(import.name, "objc_storeStrong")) {
        // The probe has no Objective-C heap, but preserving the first object argument
        // is enough to let the interpreter reach the next compatibility boundary.
    } else if (ImportNameHas(import.name, "objc_release") ||
               ImportNameHas(import.name, "objc_destroyWeak")) {
        c.x[0] = 0;
    } else if (ImportNameHas(import.name, "objc_msgSend") ||
               ImportNameHas(import.name, "objc_msgLookup")) {
        c.x[0] = 0;
    } else if (ImportNameHas(import.name, "__cxa_atexit") ||
               ImportNameHas(import.name, "pthread_") ||
               ImportNameHas(import.name, "os_unfair_lock")) {
        c.x[0] = 0;
    } else if (ImportNameHas(import.name, "dyld_get_image") ||
               ImportNameHas(import.name, "_dyld_get_image")) {
        c.x[0] = 0;
    } else if (ImportNameHas(import.name, "NSLog") || ImportNameHas(import.name, "os_log")) {
        c.x[0] = 0;
    } else {
        return StopAt(c, stopReason, L"reached unimplemented imported symbol: " +
                      Utf8ToWide(import.name) + L" from " + Utf8ToWide(import.dylib));
    }
    return ReturnFromGuestImport(c, mem, import, stopReason);
}

static StepDisposition ExecuteArm64One(Arm64Cpu& c, Arm64Memory& mem,
                                       const GuestLinker& linker,
                                       std::wstring& decoded, std::wstring& stopReason) {
    const uint64_t pc = c.pc;
    uint32_t insn = 0;
    std::string memWhy;
    if (!mem.IsExecutable(pc))
        return StopAt(c, stopReason, L"PC is outside an executable Mach-O segment: " + Hex(pc));
    if (!mem.ReadValue(pc, insn, memWhy))
        return StopAt(c, stopReason, L"instruction fetch failed: " + Utf8ToWide(memWhy));

    const auto branchTarget = [&](uint64_t target, bool link, const wchar_t* opname) -> StepDisposition {
        if (link) c.x[30] = pc + 4;
        std::wstringstream ss;
        ss << opname << L" " << Hex(target);
        decoded = ss.str();
        if (target == Arm64Memory::kReturnSentinel)
            return StopAt(c, stopReason, L"guest returned through the synthetic LR sentinel");
        if (const GuestImport* import = linker.Lookup(target))
            return HandleGuestImport(c, mem, *import, decoded, stopReason);
        c.pc = target;
        if (!mem.IsExecutable(target)) {
            return StopAt(c, stopReason,
                L"branch target is outside mapped executable code: " + Hex(target) +
                L". This is commonly where an unresolved dyld chained-fixup/import becomes visible.");
        }
        return StepDisposition::Continue;
    };

    // HINT/NOP/PAC/BTI class. PAC has no security meaning inside this interpreter yet.
    if ((insn & 0xFFFFF01Fu) == 0xD503201Fu) {
        decoded = L"hint/pac/bti (treated as nop)";
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // Advanced SIMD modified-immediate instructions. The first Swift object
    // initialization path uses this family before it reaches framework code.
    // Keep the vector register file byte-addressable so Q/D/S views can be
    // added without changing the integer CPU state.
    if ((insn & 0x9F800400u) == 0x0F000400u) {
        const unsigned q = (insn >> 30) & 1;
        const unsigned op = (insn >> 29) & 1;
        const unsigned cmode = (insn >> 12) & 0xF;
        const unsigned o2 = (insn >> 11) & 1;
        const unsigned rd = insn & 31;
        const uint8_t imm8 = static_cast<uint8_t>(((insn >> 16) & 0xE0) | ((insn >> 5) & 0x1F));
        if (o2) return StopAt(c, stopReason, L"unsupported Advanced SIMD modified-immediate encoding");

        c.v[rd].fill(0);
        if (cmode == 0xE && op == 1) {
            // FMOV immediate. The exact floating value is not needed for the
            // current Swift allocation probe; retain a deterministic zero
            // vector until scalar/vector floating arithmetic is implemented.
            decoded = L"fmov v" + std::to_wstring(rd) + L"." + (q ? L"2d" : L"d") + L", #imm8";
        } else {
            uint8_t byte = imm8;
            if (cmode == 0x0 || cmode == 0x2 || cmode == 0x4 || cmode == 0x6 || cmode == 0x8 || cmode == 0xA) {
                const unsigned shift = (cmode >> 1) * 8;
                for (unsigned lane = 0; lane < (q ? 4u : 2u); ++lane)
                    std::memcpy(c.v[rd].data() + lane * 4, &byte, 1);
                decoded = L"movi v" + std::to_wstring(rd) + L", #imm8";
                (void)shift;
            } else {
                decoded = L"movi v" + std::to_wstring(rd) + L", #imm8";
                for (auto& b : c.v[rd]) b = byte;
            }
        }
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // B / BL immediate.
    if ((insn & 0xFC000000u) == 0x14000000u || (insn & 0xFC000000u) == 0x94000000u) {
        const bool link = (insn & 0x80000000u) != 0;
        const int64_t off = SignExtend64(insn & 0x03FFFFFFu, 26) * 4;
        return branchTarget(static_cast<uint64_t>(static_cast<int64_t>(pc) + off), link, link ? L"bl" : L"b");
    }

    // BR / BLR / RET.
    const uint32_t brClass = insn & 0xFFFFFC1Fu;
    if (brClass == 0xD61F0000u || brClass == 0xD63F0000u || brClass == 0xD65F0000u) {
        const unsigned rn = (insn >> 5) & 31;
        const uint64_t target = c.ReadReg(rn, false, 64);
        if (brClass == 0xD65F0000u) {
            decoded = L"ret " + RegName(rn, 64, false) + L" -> " + Hex(target);
            if (target == Arm64Memory::kReturnSentinel)
                return StopAt(c, stopReason, L"LC_MAIN returned successfully to the synthetic caller");
            c.pc = target;
            if (!mem.IsExecutable(target))
                return StopAt(c, stopReason, L"RET target is outside mapped executable code: " + Hex(target));
            return StepDisposition::Continue;
        }
        return branchTarget(target, brClass == 0xD63F0000u, brClass == 0xD63F0000u ? L"blr" : L"br");
    }

    // Conditional B.cond.
    if ((insn & 0xFF000010u) == 0x54000000u) {
        const unsigned cond = insn & 15;
        const int64_t off = SignExtend64((insn >> 5) & 0x7FFFFu, 19) * 4;
        const uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(pc) + off);
        const bool take = ConditionHolds(c, cond);
        decoded = L"b." + std::wstring(CondName(cond)) + L" " + Hex(target) + (take ? L" [taken]" : L" [not taken]");
        c.pc = take ? target : pc + 4;
        if (take && !mem.IsExecutable(target))
            return StopAt(c, stopReason, L"conditional branch target is outside executable code: " + Hex(target));
        return StepDisposition::Continue;
    }

    // CBZ / CBNZ.
    if ((insn & 0x7E000000u) == 0x34000000u) {
        const unsigned width = (insn >> 31) ? 64 : 32;
        const bool nonzero = ((insn >> 24) & 1) != 0;
        const unsigned rt = insn & 31;
        const int64_t off = SignExtend64((insn >> 5) & 0x7FFFFu, 19) * 4;
        const uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(pc) + off);
        const uint64_t v = c.ReadReg(rt, false, width);
        const bool take = nonzero ? (v != 0) : (v == 0);
        decoded = std::wstring(nonzero ? L"cbnz " : L"cbz ") + RegName(rt, width, false) + L", " + Hex(target) +
                  (take ? L" [taken]" : L" [not taken]");
        c.pc = take ? target : pc + 4;
        if (take && !mem.IsExecutable(target))
            return StopAt(c, stopReason, L"compare-and-branch target is outside executable code: " + Hex(target));
        return StepDisposition::Continue;
    }

    // TBZ / TBNZ.
    if ((insn & 0x7E000000u) == 0x36000000u) {
        const bool nonzero = ((insn >> 24) & 1) != 0;
        const unsigned bit = (((insn >> 31) & 1) << 5) | ((insn >> 19) & 31);
        const unsigned rt = insn & 31;
        const int64_t off = SignExtend64((insn >> 5) & 0x3FFFu, 14) * 4;
        const uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(pc) + off);
        const bool isSet = ((c.ReadReg(rt, false, 64) >> bit) & 1) != 0;
        const bool take = nonzero ? isSet : !isSet;
        decoded = std::wstring(nonzero ? L"tbnz " : L"tbz ") + RegName(rt, bit >= 32 ? 64 : 32, false) +
                  L", #" + std::to_wstring(bit) + L", " + Hex(target) + (take ? L" [taken]" : L" [not taken]");
        c.pc = take ? target : pc + 4;
        if (take && !mem.IsExecutable(target))
            return StopAt(c, stopReason, L"test-bit branch target is outside executable code: " + Hex(target));
        return StepDisposition::Continue;
    }

    // ADR / ADRP.
    if ((insn & 0x9F000000u) == 0x10000000u || (insn & 0x9F000000u) == 0x90000000u) {
        const bool page = (insn & 0x80000000u) != 0;
        const unsigned rd = insn & 31;
        const uint64_t imm21 = (((insn >> 5) & 0x7FFFFu) << 2) | ((insn >> 29) & 3);
        const int64_t simm = SignExtend64(imm21, 21);
        const uint64_t value = page
            ? static_cast<uint64_t>(static_cast<int64_t>(pc & ~0xFFFull) + simm * 4096)
            : static_cast<uint64_t>(static_cast<int64_t>(pc) + simm);
        c.WriteReg(rd, value, false, 64);
        decoded = std::wstring(page ? L"adrp " : L"adr ") + RegName(rd, 64, false) + L", " + Hex(value);
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // ADD/SUB immediate, including CMP/CMN aliases.
    if ((insn & 0x1F000000u) == 0x11000000u) {
        const unsigned width = (insn >> 31) ? 64 : 32;
        const bool sub = ((insn >> 30) & 1) != 0;
        const bool setFlags = ((insn >> 29) & 1) != 0;
        const unsigned sh = ((insn >> 22) & 1) ? 12 : 0;
        const uint64_t imm = static_cast<uint64_t>((insn >> 10) & 0xFFFu) << sh;
        const unsigned rn = (insn >> 5) & 31;
        const unsigned rd = insn & 31;
        const uint64_t a = c.ReadReg(rn, true, width);
        uint64_t r;
        if (setFlags) r = sub ? SubWithFlags(c, a, imm, width) : AddWithFlags(c, a, imm, width);
        else r = sub ? (a - imm) : (a + imm);
        if (width == 32) r = static_cast<uint32_t>(r);
        c.WriteReg(rd, r, !setFlags, width);
        if (setFlags && rd == 31) {
            decoded = std::wstring(sub ? L"cmp " : L"cmn ") + RegName(rn, width, true) + L", #" + Hex(imm);
        } else {
            decoded = std::wstring(sub ? L"sub" : L"add") + (setFlags ? L"s " : L" ") +
                      RegName(rd, width, !setFlags) + L", " + RegName(rn, width, true) + L", #" + Hex(imm);
        }
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // ADD/SUB shifted register.
    if ((insn & 0x1F200000u) == 0x0B000000u) {
        const unsigned width = (insn >> 31) ? 64 : 32;
        const bool sub = ((insn >> 30) & 1) != 0;
        const bool setFlags = ((insn >> 29) & 1) != 0;
        const unsigned shift = (insn >> 22) & 3;
        const unsigned rm = (insn >> 16) & 31;
        const unsigned amount = (insn >> 10) & 63;
        const unsigned rn = (insn >> 5) & 31;
        const unsigned rd = insn & 31;
        if (shift == 3 || (width == 32 && amount >= 32))
            return StopAt(c, stopReason, L"unsupported ADD/SUB shifted-register variant");
        const uint64_t a = c.ReadReg(rn, false, width);
        const uint64_t b = ShiftOperand(c.ReadReg(rm, false, width), shift, amount, width);
        uint64_t r;
        if (setFlags) r = sub ? SubWithFlags(c, a, b, width) : AddWithFlags(c, a, b, width);
        else r = sub ? (a - b) : (a + b);
        if (width == 32) r = static_cast<uint32_t>(r);
        c.WriteReg(rd, r, false, width);
        if (setFlags && rd == 31) {
            decoded = std::wstring(sub ? L"cmp " : L"cmn ") + RegName(rn, width, false) + L", " + RegName(rm, width, false);
        } else {
            decoded = std::wstring(sub ? L"sub" : L"add") + (setFlags ? L"s " : L" ") +
                      RegName(rd, width, false) + L", " + RegName(rn, width, false) + L", " + RegName(rm, width, false);
        }
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // Move-wide: MOVN / MOVZ / MOVK.
    if ((insn & 0x1F800000u) == 0x12800000u) {
        const unsigned width = (insn >> 31) ? 64 : 32;
        const unsigned opc = (insn >> 29) & 3;
        const unsigned hw = (insn >> 21) & 3;
        const unsigned shift = hw * 16;
        const uint64_t imm = (insn >> 5) & 0xFFFFu;
        const unsigned rd = insn & 31;
        if ((width == 32 && hw >= 2) || opc == 1)
            return StopAt(c, stopReason, L"invalid/reserved move-wide encoding");
        const uint64_t mask = width == 32 ? 0xFFFFFFFFull : ~0ull;
        uint64_t r = 0;
        const wchar_t* op = L"mov?";
        if (opc == 0) { r = ~(imm << shift) & mask; op = L"movn"; }
        else if (opc == 2) { r = (imm << shift) & mask; op = L"movz"; }
        else { r = (c.ReadReg(rd, false, width) & ~(0xFFFFull << shift)) | (imm << shift); r &= mask; op = L"movk"; }
        c.WriteReg(rd, r, false, width);
        decoded = std::wstring(op) + L" " + RegName(rd, width, false) + L", #" + Hex(imm) +
                  (shift ? L", lsl #" + std::to_wstring(shift) : L"");
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // Logical shifted register: AND/ORR/EOR/ANDS, including MOV alias.
    if ((insn & 0x1F000000u) == 0x0A000000u) {
        const unsigned width = (insn >> 31) ? 64 : 32;
        const unsigned opc = (insn >> 29) & 3;
        const unsigned shift = (insn >> 22) & 3;
        const bool invert = ((insn >> 21) & 1) != 0;
        const unsigned rm = (insn >> 16) & 31;
        const unsigned amount = (insn >> 10) & 63;
        const unsigned rn = (insn >> 5) & 31;
        const unsigned rd = insn & 31;
        if (width == 32 && amount >= 32)
            return StopAt(c, stopReason, L"invalid 32-bit logical shift amount");
        uint64_t a = c.ReadReg(rn, false, width);
        uint64_t b = ShiftOperand(c.ReadReg(rm, false, width), shift, amount, width);
        const uint64_t mask = width == 32 ? 0xFFFFFFFFull : ~0ull;
        if (invert) b = (~b) & mask;
        uint64_t r = 0;
        const wchar_t* op = L"and";
        if (opc == 0) { r = a & b; op = invert ? L"bic" : L"and"; }
        else if (opc == 1) { r = a | b; op = invert ? L"orn" : L"orr"; }
        else if (opc == 2) { r = a ^ b; op = invert ? L"eon" : L"eor"; }
        else { r = a & b; op = invert ? L"bics" : L"ands"; SetNZ(c, r, width); c.C = false; c.V = false; }
        r &= mask;
        c.WriteReg(rd, r, false, width);
        if (opc == 1 && !invert && rn == 31 && shift == 0 && amount == 0)
            decoded = L"mov " + RegName(rd, width, false) + L", " + RegName(rm, width, false);
        else
            decoded = std::wstring(op) + L" " + RegName(rd, width, false) + L", " + RegName(rn, width, false) + L", " + RegName(rm, width, false);
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // LDR literal (W/X/LDRSW).
    if ((insn & 0x3B000000u) == 0x18000000u) {
        const unsigned opc = (insn >> 30) & 3;
        const unsigned rt = insn & 31;
        const int64_t off = SignExtend64((insn >> 5) & 0x7FFFFu, 19) * 4;
        const uint64_t addr = static_cast<uint64_t>(static_cast<int64_t>(pc) + off);
        if (opc == 0) {
            uint32_t v = 0; if (!mem.ReadValue(addr, v, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            c.WriteReg(rt, v, false, 32); decoded = L"ldr " + RegName(rt, 32, false) + L", [pc] -> " + Hex(addr);
        } else if (opc == 1) {
            uint64_t v = 0; if (!mem.ReadValue(addr, v, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            c.WriteReg(rt, v, false, 64); decoded = L"ldr " + RegName(rt, 64, false) + L", [pc] -> " + Hex(addr);
        } else if (opc == 2) {
            int32_t v = 0; if (!mem.ReadValue(addr, v, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            c.WriteReg(rt, static_cast<uint64_t>(static_cast<int64_t>(v)), false, 64); decoded = L"ldrsw " + RegName(rt, 64, false) + L", [pc] -> " + Hex(addr);
        } else {
            return StopAt(c, stopReason, L"PRFM literal is not implemented");
        }
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // Load/store unsigned immediate.
    const uint32_t ls = insn & 0xFFC00000u;
    if (ls == 0xF9000000u || ls == 0xF9400000u || ls == 0xB9000000u || ls == 0xB9400000u ||
        ls == 0x39000000u || ls == 0x39400000u || ls == 0x79000000u || ls == 0x79400000u || ls == 0xB9800000u) {
        const unsigned rn = (insn >> 5) & 31;
        const unsigned rt = insn & 31;
        size_t size = 0;
        bool load = false, sign32 = false;
        if (ls == 0xF9000000u || ls == 0xF9400000u) { size = 8; load = ls == 0xF9400000u; }
        else if (ls == 0xB9000000u || ls == 0xB9400000u) { size = 4; load = ls == 0xB9400000u; }
        else if (ls == 0x39000000u || ls == 0x39400000u) { size = 1; load = ls == 0x39400000u; }
        else if (ls == 0x79000000u || ls == 0x79400000u) { size = 2; load = ls == 0x79400000u; }
        else { size = 4; load = true; sign32 = true; }
        const uint64_t imm = static_cast<uint64_t>((insn >> 10) & 0xFFFu) * size;
        const uint64_t addr = c.ReadReg(rn, true, 64) + imm;
        if (load) {
            uint64_t v = 0;
            if (!mem.Read(addr, &v, size, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            if (sign32) v = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(static_cast<uint32_t>(v))));
            c.WriteReg(rt, v, false, sign32 || size == 8 ? 64 : 32);
        } else {
            uint64_t v = c.ReadReg(rt, false, size == 8 ? 64 : 32);
            if (!mem.Write(addr, &v, size, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
        }
        decoded = std::wstring(load ? (sign32 ? L"ldrsw " : L"ldr ") : L"str ") +
                  RegName(rt, sign32 || size == 8 ? 64 : 32, false) + L", [" + RegName(rn, 64, true) + L", #" + Hex(imm) + L"]";
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // LDUR/STUR unscaled immediate for W/X.
    const uint32_t unscaled = insn & 0xFFE00C00u;
    if (unscaled == 0xF8000000u || unscaled == 0xF8400000u || unscaled == 0xB8000000u || unscaled == 0xB8400000u) {
        const bool is64 = (unscaled == 0xF8000000u || unscaled == 0xF8400000u);
        const bool load = (unscaled == 0xF8400000u || unscaled == 0xB8400000u);
        const unsigned rn = (insn >> 5) & 31;
        const unsigned rt = insn & 31;
        const int64_t imm = SignExtend64((insn >> 12) & 0x1FFu, 9);
        const uint64_t addr = static_cast<uint64_t>(static_cast<int64_t>(c.ReadReg(rn, true, 64)) + imm);
        if (load) {
            uint64_t v = 0; if (!mem.Read(addr, &v, is64 ? 8 : 4, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            c.WriteReg(rt, v, false, is64 ? 64 : 32);
        } else {
            uint64_t v = c.ReadReg(rt, false, is64 ? 64 : 32);
            if (!mem.Write(addr, &v, is64 ? 8 : 4, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
        }
        decoded = std::wstring(load ? L"ldur " : L"stur ") + RegName(rt, is64 ? 64 : 32, false) +
                  L", [" + RegName(rn, 64, true) + L", #" + std::to_wstring(imm) + L"]";
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    // Integer LDP/STP (32/64-bit), offset/pre-index/post-index.
    if ((insn & 0x3A000000u) == 0x28000000u && (insn & 0x04000000u) == 0) {
        const unsigned opc = (insn >> 30) & 3;
        if (opc != 0 && opc != 2)
            return StopAt(c, stopReason, L"unsupported integer load/store pair variant");
        const unsigned width = opc == 2 ? 64 : 32;
        const size_t itemSize = width == 64 ? 8 : 4;
        const bool load = ((insn >> 22) & 1) != 0;
        const unsigned mode = (insn >> 23) & 3;
        const int64_t off = SignExtend64((insn >> 15) & 0x7Fu, 7) * static_cast<int64_t>(itemSize);
        const unsigned rt2 = (insn >> 10) & 31;
        const unsigned rn = (insn >> 5) & 31;
        const unsigned rt = insn & 31;
        uint64_t base = c.ReadReg(rn, true, 64);
        uint64_t addr = base;
        bool writeback = false;
        if (mode == 1) { addr = base; writeback = true; }
        else if (mode == 2 || mode == 0) { addr = static_cast<uint64_t>(static_cast<int64_t>(base) + off); }
        else { base = static_cast<uint64_t>(static_cast<int64_t>(base) + off); addr = base; writeback = true; }

        if (load) {
            uint64_t a = 0, b = 0;
            if (!mem.Read(addr, &a, itemSize, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            if (!mem.Read(addr + itemSize, &b, itemSize, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            c.WriteReg(rt, a, false, width); c.WriteReg(rt2, b, false, width);
        } else {
            uint64_t a = c.ReadReg(rt, false, width), b = c.ReadReg(rt2, false, width);
            if (!mem.Write(addr, &a, itemSize, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
            if (!mem.Write(addr + itemSize, &b, itemSize, memWhy)) return StopAt(c, stopReason, Utf8ToWide(memWhy));
        }
        if (writeback) {
            const uint64_t newBase = (mode == 1) ? static_cast<uint64_t>(static_cast<int64_t>(c.ReadReg(rn, true, 64)) + off) : base;
            c.WriteReg(rn, newBase, true, 64);
        }
        decoded = std::wstring(load ? L"ldp " : L"stp ") + RegName(rt, width, false) + L", " + RegName(rt2, width, false) +
                  L", [" + RegName(rn, 64, true) + L"]" + (writeback ? L" (writeback)" : L"");
        c.pc = pc + 4;
        return StepDisposition::Continue;
    }

    std::wstringstream ss;
    ss << L"unsupported instruction " << Hex(insn) << L" at " << Hex(pc);
    decoded = ss.str();
    return StopAt(c, stopReason, decoded);
}

static uint64_t AlignDown16(uint64_t v) { return v & ~15ull; }

static Arm64RunResult RunArm64Probe(const fs::path& executable,
                                    const macho::ParsedImage& img, MappedImage& mapped,
                                    const GuestLinker& linker,
                                    size_t maxSteps = 2000, size_t maxTrace = 600) {
    Arm64RunResult out;
    if (!img.entryVm) {
        out.reason = L"LC_MAIN is missing; there is no entry VM address to execute.";
        return out;
    }
    if (img.header.cputype != macho::CPU_TYPE_ARM64) {
        out.reason = L"Stage 2 only supports ARM64 Mach-O images.";
        return out;
    }

    Arm64Memory mem(img, mapped);
    Arm64Cpu c{};
    c.pc = *img.entryVm;
    c.x[30] = Arm64Memory::kReturnSentinel;

    // Minimal dyld-like main(argc, argv, envp, apple) context.
    // The real dyld provides more data; this is sufficient for early instruction execution.
    uint64_t cursor = Arm64Memory::kStackBase + Arm64Memory::kStackSize - 0x1000;
    const std::string exeName = executable.filename().string();
    cursor -= static_cast<uint64_t>(exeName.size() + 1);
    const uint64_t nameAddr = cursor;
    std::string why;
    if (!mem.Write(nameAddr, exeName.c_str(), exeName.size() + 1, why)) {
        out.reason = L"could not initialize guest stack: " + Utf8ToWide(why);
        return out;
    }
    cursor = AlignDown16(cursor - 16);
    const uint64_t argvAddr = cursor;
    uint64_t argv[2] = {nameAddr, 0};
    if (!mem.Write(argvAddr, argv, sizeof(argv), why)) {
        out.reason = L"could not initialize argv: " + Utf8ToWide(why);
        return out;
    }
    cursor = AlignDown16(cursor - 8);
    const uint64_t envpAddr = cursor;
    uint64_t zero = 0;
    mem.WriteValue(envpAddr, zero, why);
    cursor = AlignDown16(cursor - 8);
    const uint64_t appleAddr = cursor;
    mem.WriteValue(appleAddr, zero, why);
    c.sp = AlignDown16(cursor - 0x100);
    c.x[0] = 1; c.x[1] = argvAddr; c.x[2] = envpAddr; c.x[3] = appleAddr;

    for (size_t i = 0; i < maxSteps; ++i) {
        const uint64_t stepPc = c.pc;
        uint32_t raw = 0;
        std::string readWhy;
        if (!mem.ReadValue(stepPc, raw, readWhy)) {
            out.reason = L"instruction fetch failed: " + Utf8ToWide(readWhy);
            out.stopPc = stepPc;
            break;
        }
        std::wstring decoded, reason;
        const auto disp = ExecuteArm64One(c, mem, linker, decoded, reason);
        if (out.trace.size() < maxTrace) {
            std::wstringstream line;
            line << std::setw(5) << i << L"  " << Hex(stepPc) << L"  "
                 << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << raw
                 << std::setfill(L' ') << L"  " << decoded;
            out.trace.push_back(line.str());
        }
        out.steps = i + 1;
        if (disp == StepDisposition::Stop) {
            out.reason = reason;
            out.stopPc = stepPc;
            break;
        }
    }
    if (out.reason.empty()) {
        out.reason = L"instruction budget reached without a fault (" + std::to_wstring(maxSteps) + L" steps).";
        out.stopPc = c.pc;
    }
    out.cpu = c;
    return out;
}

static std::wstring BuildStage2Report(const fs::path& ipa, const fs::path& executable,
                                      const macho::ParsedImage& img, const MappedImage& mapped,
                                      const GuestLinker& linker,
                                      const Arm64RunResult& run) {
    std::wstringstream o;
    o << L"AppleWine Stage 2 - IPA/Mach-O + ARM64 interpreter\r\n";
    o << L"============================================================\r\n\r\n";
    o << L"IPA: " << ipa.wstring() << L"\r\n";
    o << L"Main executable: " << executable.filename().wstring() << L"\r\n\r\n";

    o << L"Mach-O\r\n";
    o << L"  CPU:          " << (img.header.cputype == macho::CPU_TYPE_ARM64 ? L"ARM64" : L"unsupported") << L"\r\n";
    if (img.platform) o << L"  platform:     " << PlatformName(*img.platform) << L"\r\n";
    if (img.minos) o << L"  minimum OS:   " << VersionString(*img.minos) << L"\r\n";
    if (img.sdk) o << L"  SDK:          " << VersionString(*img.sdk) << L"\r\n";
    if (img.entryVm) o << L"  LC_MAIN VM:   " << Hex(*img.entryVm) << L"\r\n";
    o << L"  chained fixups: " << (img.hasChainedFixups ?
        (linker.applied ? L"yes (applied)" : L"yes (not applied)") : L"no") << L"\r\n";
    if (img.hasChainedFixups) {
        o << L"  fixup chains:  " << linker.chainEntries << L" pointer(s), "
          << linker.rebases << L" rebase(s), " << linker.binds << L" bind(s)\r\n";
        o << L"  imports:       " << linker.imports.size() << L" synthetic guest address(es)\r\n";
        for (size_t i = 0; i < std::min<size_t>(linker.imports.size(), 24); ++i) {
            const auto& imp = linker.imports[i];
            o << L"    [" << i << L"] " << Hex(imp.guestAddress) << L"  "
              << Utf8ToWide(imp.name) << L"  (" << Utf8ToWide(imp.dylib) << L")\r\n";
        }
        if (linker.imports.size() > 24)
            o << L"    ... " << (linker.imports.size() - 24) << L" more import(s) ...\r\n";
    }
    o << L"\r\n";

    o << L"Guest CPU initialization\r\n";
    o << L"  architecture: ARM64 interpreted on x64 Windows\r\n";
    o << L"  initial argc: 1\r\n";
    o << L"  synthetic argv/envp/apple: yes\r\n";
    o << L"  synthetic stack: 4 MiB\r\n\r\n";

    o << L"Execution result\r\n";
    o << L"  executed: " << run.steps << L" instruction(s)\r\n";
    o << L"  stop PC:  " << Hex(run.stopPc) << L"\r\n";
    o << L"  reason:   " << run.reason << L"\r\n\r\n";

    o << L"Registers at stop\r\n";
    for (unsigned i = 0; i < 31; ++i) {
        o << L"  X" << std::setw(2) << std::setfill(L'0') << i << std::setfill(L' ') << L" = " << Hex(run.cpu.x[i]);
        if ((i % 2) == 1) o << L"\r\n"; else o << L"    ";
    }
    if ((31 % 2) == 1) o << L"\r\n";
    o << L"  SP  = " << Hex(run.cpu.sp) << L"\r\n";
    o << L"  PC  = " << Hex(run.cpu.pc) << L"\r\n";
    o << L"  NZCV= " << (run.cpu.N ? L'1' : L'0') << (run.cpu.Z ? L'1' : L'0')
      << (run.cpu.C ? L'1' : L'0') << (run.cpu.V ? L'1' : L'0') << L"\r\n\r\n";

    o << L"ARM64 execution trace\r\n";
    o << L"  step   guest-PC           raw         decoded/executed\r\n";
    for (const auto& line : run.trace) o << L"  " << line << L"\r\n";
    if (run.steps > run.trace.size())
        o << L"  ... trace display capped at " << run.trace.size() << L" lines ...\r\n";

    o << L"\r\nStage-2 status\r\n";
    if (run.steps > 0)
        o << L"  PASS: ARM64 instructions from the real iOS LC_MAIN were interpreted on Windows.\r\n";
    else
        o << L"  STOP: no ARM64 instruction completed. See the reason above.\r\n";
    o << L"\r\nStage 2.5 applies LC_DYLD_CHAINED_FIXUPS and names imported symbols.\r\n"
         L"The next boundary is now an unsupported ARM64 opcode, a Darwin shim, or an iOS framework.\r\n";
    return o.str();
}

static HRESULT DispId(IDispatch* d, const wchar_t* name, DISPID* id) {
    LPOLESTR n = const_cast<LPOLESTR>(name);
    return d->GetIDsOfNames(IID_NULL, &n, 1, LOCALE_USER_DEFAULT, id);
}

static HRESULT Invoke0(IDispatch* d, WORD flags, const wchar_t* name, VARIANT* result) {
    DISPID id{};
    HRESULT hr = DispId(d, name, &id);
    if (FAILED(hr)) return hr;
    DISPPARAMS dp{};
    return d->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, flags, &dp, result, nullptr, nullptr);
}

static HRESULT Invoke1(IDispatch* d, WORD flags, const wchar_t* name, VARIANT arg1, VARIANT* result) {
    DISPID id{};
    HRESULT hr = DispId(d, name, &id);
    if (FAILED(hr)) return hr;
    VARIANT args[1];
    VariantInit(&args[0]);
    VariantCopy(&args[0], &arg1);
    DISPPARAMS dp{args, nullptr, 1, 0};
    hr = d->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, flags, &dp, result, nullptr, nullptr);
    VariantClear(&args[0]);
    return hr;
}

static HRESULT Invoke2(IDispatch* d, WORD flags, const wchar_t* name, VARIANT arg1, VARIANT arg2, VARIANT* result) {
    DISPID id{};
    HRESULT hr = DispId(d, name, &id);
    if (FAILED(hr)) return hr;
    VARIANT args[2];
    VariantInit(&args[0]); VariantInit(&args[1]);
    // IDispatch arguments are passed right-to-left.
    VariantCopy(&args[0], &arg2);
    VariantCopy(&args[1], &arg1);
    DISPPARAMS dp{args, nullptr, 2, 0};
    hr = d->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, flags, &dp, result, nullptr, nullptr);
    VariantClear(&args[0]); VariantClear(&args[1]);
    return hr;
}

static IDispatch* ShellNameSpace(IDispatch* shell, const std::wstring& path) {
    VARIANT arg; VariantInit(&arg);
    arg.vt = VT_BSTR;
    arg.bstrVal = SysAllocString(path.c_str());
    VARIANT result; VariantInit(&result);
    HRESULT hr = Invoke1(shell, DISPATCH_METHOD, L"NameSpace", arg, &result);
    VariantClear(&arg);
    if (FAILED(hr)) return nullptr;
    IDispatch* out = nullptr;
    if (result.vt == VT_DISPATCH && result.pdispVal) {
        out = result.pdispVal;
        out->AddRef();
    }
    VariantClear(&result);
    return out;
}

static void ExtractZipWithWindowsShell(const fs::path& zip, const fs::path& outDir) {
    CLSID clsid{};
    if (FAILED(CLSIDFromProgID(L"Shell.Application", &clsid)))
        throw std::runtime_error("Shell.Application is unavailable");

    IDispatch* shell = nullptr;
    HRESULT hr = CoCreateInstance(clsid, nullptr, CLSCTX_ALL, IID_IDispatch, reinterpret_cast<void**>(&shell));
    if (FAILED(hr) || !shell) throw std::runtime_error("cannot create Shell.Application");

    IDispatch* src = ShellNameSpace(shell, zip.wstring());
    IDispatch* dst = ShellNameSpace(shell, outDir.wstring());
    if (!src || !dst) {
        if (src) src->Release();
        if (dst) dst->Release();
        shell->Release();
        throw std::runtime_error("Windows Shell could not open the ZIP namespace");
    }

    VARIANT items; VariantInit(&items);
    hr = Invoke0(src, DISPATCH_METHOD | DISPATCH_PROPERTYGET, L"Items", &items);
    if (FAILED(hr) || items.vt != VT_DISPATCH || !items.pdispVal) {
        VariantClear(&items); src->Release(); dst->Release(); shell->Release();
        throw std::runtime_error("cannot enumerate ZIP items");
    }

    VARIANT options; VariantInit(&options);
    options.vt = VT_I4;
    options.lVal = 0x0004 | 0x0010 | 0x0400; // silent, no confirmation, no error UI
    VARIANT ignored; VariantInit(&ignored);
    hr = Invoke2(dst, DISPATCH_METHOD, L"CopyHere", items, options, &ignored);
    VariantClear(&ignored);
    VariantClear(&options);
    VariantClear(&items);
    src->Release(); dst->Release(); shell->Release();
    if (FAILED(hr)) throw std::runtime_error("Windows Shell CopyHere failed");
}

static fs::path MakeTempWorkDir() {
    wchar_t temp[MAX_PATH + 1]{};
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (!n || n > MAX_PATH) throw std::runtime_error("GetTempPathW failed");
    GUID g{};
    if (FAILED(CoCreateGuid(&g))) throw std::runtime_error("CoCreateGuid failed");
    wchar_t guid[64]{};
    StringFromGUID2(g, guid, 64);
    std::wstring s(guid);
    s.erase(std::remove_if(s.begin(), s.end(), [](wchar_t c) { return c == L'{' || c == L'}' || c == L'-'; }), s.end());
    fs::path p = fs::path(temp) / (L"AppleWine_" + s);
    fs::create_directories(p);
    return p;
}

static std::optional<fs::path> FindMainMachO(const fs::path& root) {
    std::error_code ec;
    const fs::path payload = root / L"Payload";
    if (!fs::exists(payload, ec)) return std::nullopt;

    for (const auto& d : fs::directory_iterator(payload, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) break;
        if (!d.is_directory(ec) || d.path().extension() != L".app") continue;
        for (const auto& f : fs::directory_iterator(d.path(), fs::directory_options::skip_permission_denied, ec)) {
            if (ec) break;
            if (!f.is_regular_file(ec)) continue;
            try {
                if (LooksLikeMachO64(f.path())) return f.path();
            } catch (...) {}
        }
    }
    return std::nullopt;
}

static fs::path WaitForMainMachO(const fs::path& root) {
    uintmax_t lastSize = 0;
    int stable = 0;
    fs::path candidate;
    for (int i = 0; i < 240; ++i) {
        auto p = FindMainMachO(root);
        if (p) {
            std::error_code ec;
            const uintmax_t sz = fs::file_size(*p, ec);
            if (!ec && sz > 0) {
                if (*p == candidate && sz == lastSize) ++stable;
                else { candidate = *p; lastSize = sz; stable = 0; }
                if (stable >= 5) return candidate;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    throw std::runtime_error("IPA extraction did not produce a main Mach-O executable");
}

static std::wstring PickIpaFile(HWND owner) {
    wchar_t file[32768]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"iOS application (*.ipa)\0*.ipa\0All files (*.*)\0*.*\0\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = static_cast<DWORD>(std::size(file));
    ofn.lpstrTitle = L"Choose an unsigned/test IPA";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (!GetOpenFileNameW(&ofn)) return {};
    return file;
}

static std::wstring g_report;
static HWND g_edit = nullptr;

static LRESULT CALLBACK ReportWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_report.c_str(),
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_LEFT | ES_MULTILINE |
            ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            0, 0, 100, 100, hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (g_edit) SendMessageW(g_edit, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        return 0;
    }
    case WM_SIZE:
        if (g_edit) MoveWindow(g_edit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
        return 0;
    case WM_SETFOCUS:
        if (g_edit) SetFocus(g_edit);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static int ShowReport(HINSTANCE hInstance, const std::wstring& report) {
    g_report = report;
    const wchar_t* cls = L"AppleWineStage2Report";
    WNDCLASSW wc{};
    wc.lpfnWndProc = ReportWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = cls;
    RegisterClassW(&wc);

    HWND w = CreateWindowExW(0, cls, L"AppleWine Stage 2 - ARM64 Interpreter",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 700,
        nullptr, nullptr, hInstance, nullptr);
    if (!w) return 1;

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int) {
    HRESULT co = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(co);
    fs::path work;
    try {
        const std::wstring picked = PickIpaFile(nullptr);
        if (picked.empty()) {
            if (uninit) CoUninitialize();
            return 0;
        }
        const fs::path ipa(picked);
        work = MakeTempWorkDir();
        const fs::path zipCopy = work / L"bundle.zip";
        const fs::path extracted = work / L"extracted";
        fs::create_directories(extracted);

        if (!CopyFileW(ipa.c_str(), zipCopy.c_str(), FALSE))
            throw std::runtime_error("CopyFileW failed while creating temporary ZIP copy");

        ExtractZipWithWindowsShell(zipCopy, extracted);
        const fs::path exe = WaitForMainMachO(extracted);
        const auto bytes = ReadAll(exe);
        const auto parsed = ParseMachO(bytes);
        auto mapped = MapMachOSegments(bytes, parsed);
        const auto linker = ApplyChainedFixups(bytes, parsed, mapped);
        ProtectMappedMachOSegments(parsed, mapped);
        const auto run = RunArm64Probe(exe, parsed, mapped, linker);
        const std::wstring report = BuildStage2Report(ipa, exe, parsed, mapped, linker, run);

        // Keep the mapped image alive while the report window is open.
        const int rc = ShowReport(hInstance, report);
        mapped = MappedImage{};
        std::error_code ec;
        fs::remove_all(work, ec);
        if (uninit) CoUninitialize();
        return rc;
    } catch (const std::exception& e) {
        std::wstring msg = L"AppleWine Stage 2 failed:\n\n" + Utf8ToWide(e.what());
        MessageBoxW(nullptr, msg.c_str(), L"AppleWine Stage 2", MB_ICONERROR | MB_OK);
        if (!work.empty()) { std::error_code ec; fs::remove_all(work, ec); }
        if (uninit) CoUninitialize();
        return 1;
    }
}
