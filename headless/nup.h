// SPDX-License-Identifier: GPL-3.0-or-later
// NUP (NX Package, nup-meow SPEC.md v1): a container of unencrypted Switch dumps. A .nup holds the
// ExeFS and RomFS trees of a base game, of its updates and of its add-ons, each file zstd-compressed
// or raw, with the title's name, publisher, display version and icons in a metadata block.
//
// What this header gives the app:
//   ReadInfo       the library's view of a .nup (title ID, name, icon, languages, how many updates and
//                  add-ons) from its superblock and metadata blocks alone: a few KiB of reading, however
//                  big the game is. The table of contents is not verified here.
//   IsReady        whether the game has been unpacked already (reads only the 128-byte superblock).
//   Materialize    unpacks the game once into the cache, in the layout of an extracted dump that the core
//                  already loads (patch 0001: base/exefs, base/romfs, updates/<decimal version>/...), after
//                  verifying the table of contents and every file's SHA-256. Files of an update that are
//                  the same as the layer below are not written again: the core reads them from there.
//   EnsureExtracted  Materialize without progress, for the game start itself.
//
// The reader follows SPEC.md section 6.1: the table of contents is hashed before any value from it is
// trusted, every offset and size is bounds-checked, unknown codecs/kinds/flags are refused, and a file
// name is only a label (a name that is empty, "." or "..", or holds a slash, is refused, so nothing can
// be written outside the cache).
//
// Not covered: add-on packages (DLC). The core takes DLC from NSP/XCI files in updates/ only; their
// number is reported by ReadInfo, their files are not unpacked.
#pragma once

#include <zstd.h>

#include <sys/stat.h>
#ifndef PS5_NATIVE
#include <sys/statvfs.h>
#endif
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "extracted_game.h"
#include "storage_paths.h"

namespace Eden::Nup {

// Malformed or nonconforming data, or a file that cannot be written: the message is shown to the player.
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
// The unpacking was ended by the player.
class Cancelled : public Error {
public:
    Cancelled() : Error("Cancelled") {}
};

inline constexpr std::uint32_t kNoDir = 0xFFFFFFFFu;
inline constexpr std::uint8_t kBase = 0, kUpdate = 1, kAddon = 2, kAddonUpdate = 3, kSystem = 4;
inline constexpr std::uint8_t kFlagStandaloneUpdate = 0x01;
inline constexpr std::uint16_t kTlvNpdm = 0x0001, kTlvNacp = 0x0002, kTlvIcon = 0x0003, kTlvDisplayVersion = 0x0004,
                               kTlvTitleName = 0x0005, kTlvPublisher = 0x0006, kTlvBuildId = 0x0007,
                               kTlvLocalizedTitles = 0x0009, kTlvLocalizedIcons = 0x000A;

inline bool IsNupPath(std::string_view path) {
    if (path.size() < 5) return false;
    std::string extension(path.substr(path.size() - 4));
    for (char& c : extension) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return extension == ".nup";
}

// ---------------------------------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), so that reading a package needs nothing but zstd.
class Sha256 {
public:
    Sha256() { Reset(); }
    void Reset() {
        state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        length_ = 0;
        used_ = 0;
    }
    void Update(const void* data, std::size_t size) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        length_ += size;
        if (used_) {
            const std::size_t take = std::min(size, block_.size() - used_);
            std::memcpy(block_.data() + used_, bytes, take);
            used_ += take;
            bytes += take;
            size -= take;
            if (used_ < block_.size()) return;
            Compress(block_.data());
            used_ = 0;
        }
        for (; size >= block_.size(); bytes += block_.size(), size -= block_.size()) Compress(bytes);
        if (size) {
            std::memcpy(block_.data(), bytes, size);
            used_ = size;
        }
    }
    std::array<std::uint8_t, 32> Final() {
        const std::uint64_t bits = length_ * 8;
        const std::uint8_t one = 0x80;
        Update(&one, 1);
        const std::uint8_t zero = 0;
        while (used_ != 56) Update(&zero, 1);
        std::uint8_t tail[8];
        for (int i = 0; i < 8; ++i) tail[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        Update(tail, sizeof(tail));
        std::array<std::uint8_t, 32> digest{};
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j) digest[4 * i + j] = static_cast<std::uint8_t>(state_[i] >> (24 - 8 * j));
        Reset();
        return digest;
    }
    static std::array<std::uint8_t, 32> Of(const void* data, std::size_t size) {
        Sha256 hash;
        hash.Update(data, size);
        return hash.Final();
    }

private:
    static std::uint32_t Rotate(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void Compress(const std::uint8_t* chunk) {
        static constexpr std::uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = static_cast<std::uint32_t>(chunk[4 * i]) << 24 | static_cast<std::uint32_t>(chunk[4 * i + 1]) << 16 |
                   static_cast<std::uint32_t>(chunk[4 * i + 2]) << 8 | chunk[4 * i + 3];
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = Rotate(w[i - 15], 7) ^ Rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = Rotate(w[i - 2], 17) ^ Rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3], e = state_[4], f = state_[5],
                      g = state_[6], h = state_[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t s1 = Rotate(e, 6) ^ Rotate(e, 11) ^ Rotate(e, 25);
            const std::uint32_t choose = (e & f) ^ (~e & g);
            const std::uint32_t t1 = h + s1 + choose + k[i] + w[i];
            const std::uint32_t s0 = Rotate(a, 2) ^ Rotate(a, 13) ^ Rotate(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = s0 + majority;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> block_{};
    std::size_t used_ = 0;
    std::uint64_t length_ = 0;
};

inline std::string Hex(const std::uint8_t* bytes, std::size_t count) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string text;
    for (std::size_t i = 0; i < count; ++i) {
        text += digits[bytes[i] >> 4];
        text += digits[bytes[i] & 15];
    }
    return text;
}

// ---------------------------------------------------------------------------------------------------
namespace detail {
inline std::uint16_t U16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] | p[1] << 8); }
inline std::uint32_t U32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | static_cast<std::uint32_t>(p[1]) << 8 |
           static_cast<std::uint32_t>(p[2]) << 16 | static_cast<std::uint32_t>(p[3]) << 24;
}
inline std::uint64_t U64(const std::uint8_t* p) {
    return static_cast<std::uint64_t>(U32(p)) | static_cast<std::uint64_t>(U32(p + 4)) << 32;
}
inline bool Zero(const std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i)
        if (p[i]) return false;
    return true;
}
// offset + size <= limit, without overflow.
inline bool Within(std::uint64_t offset, std::uint64_t size, std::uint64_t limit) {
    return offset <= limit && size <= limit - offset;
}

inline constexpr std::size_t kHeaderSize = 0x80, kTocHeaderSize = 0x30, kPackageSize = 0x40, kDirSize = 0x18,
                             kFileSize = 0x50, kAlign = 16;
inline constexpr std::uint64_t kMaxToc = 1ull << 30;  // a table of contents of a gigabyte is not a game's
inline constexpr std::uint64_t kMaxMeta = 64ull << 20;

struct Closer {
    void operator()(std::FILE* file) const {
        if (file) std::fclose(file);
    }
};
}  // namespace detail

struct Package {
    std::uint64_t title_id = 0;
    std::uint32_t root_dir = 0, exefs_dir = kNoDir, romfs_dir = kNoDir, version = 0;
    std::uint8_t kind = kBase, flags = 0;
    std::uint64_t meta_offset = 0;
    std::uint32_t meta_size = 0;
};

struct FileNode {
    std::uint32_t name_off = 0, name_len = 0;
    std::uint64_t size = 0, extent_offset = 0, extent_size = 0;
    std::array<std::uint8_t, 32> sha256{};
    std::uint8_t codec = 0;
};

// One file of a package: its path from the package root ("exefs/main", "romfs/a/b.bin") and its record.
struct Entry {
    std::string path;
    std::uint32_t file = 0;
};
struct Listing {
    std::vector<Entry> files;
    std::vector<std::string> dirs;  // every directory below the listed one, as paths (empty ones included)
};

using Meta = std::map<std::uint16_t, std::vector<std::uint8_t>>;

class Archive {
public:
    enum class Mode {
        full,  // the whole table of contents, hashed and checked
        info,  // the superblock and the package records only: enough for the library
    };

    explicit Archive(const std::string& path, Mode mode = Mode::full) : path_(path) {
        using namespace detail;
        file_.reset(std::fopen(path.c_str(), "rb"));
        if (!file_) throw Error("Cannot open " + path);
        if (std::fseek(file_.get(), 0, SEEK_END) != 0) throw Error("Cannot read " + path);
        const auto end = static_cast<std::int64_t>(ftello(file_.get()));
        if (end < 0) throw Error("Cannot read " + path);
        real_size_ = static_cast<std::uint64_t>(end);

        std::uint8_t head[kHeaderSize];
        ReadAt(0, head, sizeof(head), "the superblock");
        if (std::memcmp(head, "NUP", 3) != 0) throw Error("Not a NUP file");
        if (head[3] != 1) throw Error("Unsupported NUP version " + std::to_string(head[3]));
        header_size_ = U16(head + 4);
        toc_offset_ = U64(head + 0x08);
        toc_size_ = U64(head + 0x10);
        std::memcpy(toc_sha256_.data(), head + 0x18, 32);
        blob_offset_ = U64(head + 0x38);
        file_size_ = U64(head + 0x40);
        const std::uint32_t package_count = U32(head + 0x48);
        const std::uint32_t flags = U32(head + 0x4C);
        std::memcpy(uuid_.data(), head + 0x50, 16);
        if (header_size_ < kHeaderSize) throw Error("Bad NUP header size");
        if (!Zero(head + 0x60, 32)) throw Error("Bad NUP superblock");
        if (flags != 0) throw Error("The NUP uses features this version does not know");
        if (file_size_ != real_size_) throw Error("The NUP file is incomplete (copied only in part?)");
        if (toc_offset_ < header_size_ || !Within(toc_offset_, toc_size_, file_size_) ||
            toc_size_ < kTocHeaderSize || toc_size_ > kMaxToc)
            throw Error("Bad NUP table of contents position");
        if (blob_offset_ % kAlign != 0 || blob_offset_ > file_size_ || blob_offset_ < toc_offset_ + toc_size_)
            throw Error("Bad NUP data position");
        if (package_count == 0) throw Error("The NUP has no package");

        if (mode == Mode::info) {
            std::uint8_t toc_head[kTocHeaderSize];
            ReadAt(toc_offset_, toc_head, sizeof(toc_head), "the table of contents");
            ParseTocHead(toc_head, package_count);
            const std::uint64_t packages_size = static_cast<std::uint64_t>(package_count) * kPackageSize;
            if (!Within(kTocHeaderSize, packages_size, toc_size_)) throw Error("NUP table of contents is truncated");
            std::vector<std::uint8_t> records(static_cast<std::size_t>(packages_size));
            ReadAt(toc_offset_ + kTocHeaderSize, records.data(), records.size(), "the packages");
            ParsePackages(records.data(), package_count);
            return;
        }

        std::vector<std::uint8_t> toc(static_cast<std::size_t>(toc_size_));
        ReadAt(toc_offset_, toc.data(), toc.size(), "the table of contents");
        if (Sha256::Of(toc.data(), toc.size()) != toc_sha256_)
            throw Error("The NUP is damaged (its table of contents does not match its hash)");
        ParseTocHead(toc.data(), package_count);
        ParseToc(toc, package_count);
    }

    const std::vector<Package>& packages() const { return packages_; }
    const std::array<std::uint8_t, 16>& uuid() const { return uuid_; }
    const std::array<std::uint8_t, 32>& toc_sha256() const { return toc_sha256_; }
    std::uint64_t file_size() const { return file_size_; }
    std::uint64_t blob_offset() const { return blob_offset_; }
    std::uint64_t dir_count() const { return dir_count_; }
    std::uint64_t file_count() const { return file_count_; }

    // What a package's output is named in the cache and in the library: unique for the contents.
    std::string Key() const { return Hex(uuid_.data(), 16) + "-" + Hex(toc_sha256_.data(), 8); }

    // The metadata block of a package: TLV type -> payload (the first record of a type wins).
    Meta ReadMeta(const Package& package) const {
        Meta meta;
        if (package.meta_size == 0) return meta;
        if (package.meta_size > detail::kMaxMeta) throw Error("A NUP metadata block is too big");
        std::vector<std::uint8_t> block(package.meta_size);
        ReadAt(package.meta_offset, block.data(), block.size(), "a metadata block");
        std::size_t position = 0;
        while (position + 8 <= block.size()) {
            const std::uint16_t type = detail::U16(block.data() + position);
            const std::uint32_t size = detail::U32(block.data() + position + 4);
            if (size > block.size() - position - 8) throw Error("A NUP metadata record runs past its block");
            meta.emplace(type, std::vector<std::uint8_t>(block.begin() + static_cast<std::ptrdiff_t>(position) + 8,
                                                         block.begin() + static_cast<std::ptrdiff_t>(position) + 8 +
                                                             static_cast<std::ptrdiff_t>(size)));
            position += 8 + size;
        }
        return meta;
    }

    // Every file below a directory of the table of contents, with paths that start with `prefix`.
    Listing List(std::uint32_t dir, const std::string& prefix) const {
        if (dir_count_ == 0 && children_.empty() && dirs_.empty()) throw Error("The table of contents was not read");
        if (dir >= dirs_.size()) throw Error("A NUP directory is out of range");
        Listing listing;
        std::vector<std::uint8_t> seen(dirs_.size(), 0);
        struct Item {
            std::uint32_t dir;
            std::string path;
        };
        std::vector<Item> stack{{dir, prefix}};
        seen[dir] = 1;
        listing.dirs.push_back(prefix);
        while (!stack.empty()) {
            Item item = std::move(stack.back());
            stack.pop_back();
            const DirNode& node = dirs_[item.dir];
            for (std::uint32_t slot = node.first_child; slot < node.first_child + node.child_count; ++slot) {
                const std::uint32_t id = children_[slot];
                if (id < dirs_.size()) {
                    if (seen[id]) throw Error("A NUP directory is reached twice");
                    seen[id] = 1;
                    CheckName(Name(dirs_[id].name_off, dirs_[id].name_len));
                    std::string path = item.path + "/" + std::string(Name(dirs_[id].name_off, dirs_[id].name_len));
                    if (path.size() > 4096) throw Error("A NUP path is too long");
                    listing.dirs.push_back(path);
                    stack.push_back({id, std::move(path)});
                } else {
                    const std::uint32_t index = id - static_cast<std::uint32_t>(dirs_.size());
                    std::string path = item.path + "/" + std::string(Name(files_[index].name_off, files_[index].name_len));
                    if (path.size() > 4096) throw Error("A NUP path is too long");
                    listing.files.push_back({std::move(path), index});
                }
            }
        }
        return listing;
    }

    const FileNode& file(std::uint32_t index) const { return files_.at(index); }

    // Writes one file to `destination`, decompressing it as it is read (memory stays at a few MiB however
    // big the file is) and checking its SHA-256. A file that does not check out is removed.
    // `stop` is looked at between blocks; `written` counts the bytes put out.
    void Extract(std::uint32_t index, const std::string& destination, const std::atomic<bool>* stop,
                 std::atomic<std::uint64_t>* written = nullptr) const {
        const FileNode& node = file(index);
        std::unique_ptr<std::FILE, detail::Closer> out(std::fopen(destination.c_str(), "wb"));
        if (!out) throw Error("Cannot write " + destination);
        static constexpr std::size_t kBuffer = 1u << 20;
        std::vector<char> stdio_buffer(kBuffer);
        std::setvbuf(out.get(), stdio_buffer.data(), _IOFBF, stdio_buffer.size());
        Sha256 hash;
        std::uint64_t produced = 0;
        bool ok = true;
        try {
            const auto emit = [&](const void* data, std::size_t size) {
                if (!size) return;
                produced += size;
                if (produced > node.size) throw Error("A file in the NUP is longer than it says");
                hash.Update(data, size);
                if (std::fwrite(data, 1, size, out.get()) != size)
                    throw Error("Cannot write " + destination + " (is the disk full?)");
                if (written) *written += size;
            };
            if (node.size != 0) Stream(node, emit, stop);
            if (produced != node.size) throw Error("A file in the NUP is shorter than it says");
            if (hash.Final() != node.sha256) throw Error("The NUP is damaged (a file does not match its hash)");
        } catch (...) {
            ok = false;
            out.reset();
            std::remove(destination.c_str());
            throw;
        }
        if (ok && std::fclose(out.release()) != 0) {
            std::remove(destination.c_str());
            throw Error("Cannot write " + destination + " (is the disk full?)");
        }
    }

private:
    struct DirNode {
        std::uint32_t name_off = 0, name_len = 0, first_child = 0, child_count = 0;
    };

    void ReadAt(std::uint64_t offset, void* buffer, std::size_t size, const char* what) const {
        if (!detail::Within(offset, size, real_size_)) throw Error(std::string{"The NUP is truncated at "} + what);
        if (size == 0) return;
        if (fseeko(file_.get(), static_cast<off_t>(offset), SEEK_SET) != 0 ||
            std::fread(buffer, 1, size, file_.get()) != size)
            throw Error(std::string{"Cannot read "} + what + " of " + path_);
    }

    void ParseTocHead(const std::uint8_t* toc, std::uint32_t package_count) {
        using namespace detail;
        if (std::memcmp(toc, "TOC", 3) != 0 || toc[3] != 1) throw Error("Bad NUP table of contents");
        if (U32(toc + 4) != package_count) throw Error("The NUP's package counts disagree");
        dir_count_ = U64(toc + 8);
        file_count_ = U64(toc + 0x10);
        pool_off_ = U64(toc + 0x18);
        pool_size_ = U64(toc + 0x20);
    }

    void ParsePackages(const std::uint8_t* records, std::uint32_t package_count) {
        using namespace detail;
        packages_.clear();
        for (std::uint32_t i = 0; i < package_count; ++i) {
            const std::uint8_t* p = records + static_cast<std::size_t>(i) * kPackageSize;
            Package package;
            package.title_id = U64(p);
            package.root_dir = U32(p + 0x08);
            package.exefs_dir = U32(p + 0x0C);
            package.romfs_dir = U32(p + 0x10);
            package.version = U32(p + 0x14);
            package.kind = p[0x18];
            package.flags = p[0x19];
            package.meta_offset = U64(p + 0x20);
            package.meta_size = U32(p + 0x28);
            if (package.kind >= 5) throw Error("The NUP holds a kind of package this version does not know");
            if (package.flags & ~kFlagStandaloneUpdate) throw Error("The NUP uses package flags this version does not know");
            if (U16(p + 0x1A) != 0 || U32(p + 0x1C) != 0 || !Zero(p + 0x2C, 20)) throw Error("Bad NUP package record");
            if (package.root_dir >= dir_count_ ||
                (package.exefs_dir != kNoDir && package.exefs_dir >= dir_count_) ||
                (package.romfs_dir != kNoDir && package.romfs_dir >= dir_count_))
                throw Error("A NUP package points outside its directories");
            if (package.meta_size != 0 && !Within(package.meta_offset, package.meta_size, file_size_))
                throw Error("A NUP metadata block is out of bounds");
            packages_.push_back(package);
        }
        // SPEC 3.1.2: an update needs a base in the same container, or the standalone_update flag.
        const bool has_base = std::any_of(packages_.begin(), packages_.end(), [](const Package& p) { return p.kind == kBase; });
        std::size_t bases = 0;
        for (const Package& p : packages_) {
            bases += p.kind == kBase;
            if (p.kind == kUpdate && !has_base && !(p.flags & kFlagStandaloneUpdate))
                throw Error("The NUP holds an update without its game");
        }
        if (bases > 1) throw Error("The NUP holds more than one base game");
    }

    void ParseToc(const std::vector<std::uint8_t>& toc, std::uint32_t package_count) {
        using namespace detail;
        // Counts come from the file: bound them by the table's own size before multiplying.
        if (dir_count_ > toc_size_ / kDirSize || file_count_ > toc_size_ / kFileSize)
            throw Error("NUP table of contents is truncated");
        const std::uint64_t packages_end = kTocHeaderSize + static_cast<std::uint64_t>(package_count) * kPackageSize;
        const std::uint64_t dirs_end = packages_end + dir_count_ * kDirSize;
        const std::uint64_t files_end = dirs_end + file_count_ * kFileSize;
        if (files_end > toc.size()) throw Error("NUP table of contents is truncated");
        if (!Within(pool_off_, pool_size_, toc.size()) || pool_off_ < files_end) throw Error("NUP string pool is out of bounds");
        if ((pool_off_ - files_end) % 4 != 0) throw Error("NUP children array is misaligned");
        if (dir_count_ + file_count_ > 0xFFFFFFFFull) throw Error("NUP has too many entries");

        ParsePackages(toc.data() + kTocHeaderSize, package_count);

        dirs_.resize(static_cast<std::size_t>(dir_count_));
        const std::uint64_t slots = (pool_off_ - files_end) / 4;
        std::uint64_t used = 0;
        for (std::size_t i = 0; i < dirs_.size(); ++i) {
            const std::uint8_t* p = toc.data() + packages_end + i * kDirSize;
            DirNode& dir = dirs_[i];
            dir.name_off = U32(p);
            dir.name_len = U32(p + 4);
            dir.first_child = U32(p + 8);
            dir.child_count = U32(p + 12);
            if (!Within(dir.name_off, dir.name_len, pool_size_)) throw Error("A NUP name is out of the string pool");
            if (!Within(dir.first_child, dir.child_count, slots)) throw Error("A NUP directory's children are out of bounds");
            used += dir.child_count;
        }
        if (used != slots) throw Error("NUP children array does not match its directories");
        files_.resize(static_cast<std::size_t>(file_count_));
        for (std::size_t i = 0; i < files_.size(); ++i) {
            const std::uint8_t* p = toc.data() + dirs_end + i * kFileSize;
            FileNode& node = files_[i];
            node.name_off = U32(p);
            node.name_len = U32(p + 4);
            node.size = U64(p + 8);
            node.extent_offset = U64(p + 0x10);
            node.extent_size = U64(p + 0x18);
            std::memcpy(node.sha256.data(), p + 0x20, 32);
            node.codec = p[0x40];
            if (!Within(node.name_off, node.name_len, pool_size_)) throw Error("A NUP name is out of the string pool");
            if (node.codec > 1) throw Error("The NUP uses a compression this version does not know");
            if (p[0x41] != 0 || U16(p + 0x42) != 0 || !Zero(p + 0x44, 12)) throw Error("Bad NUP file record");
            if (node.size == 0) {
                if (node.extent_offset != 0 || node.extent_size != 0 || node.codec != 0) throw Error("Bad NUP empty file");
                continue;
            }
            if (node.extent_size == 0) throw Error("A NUP file has no data");
            if (node.codec == 0 && node.extent_size != node.size) throw Error("A NUP file's size does not match its data");
            if (node.extent_offset < blob_offset_ || !Within(node.extent_offset, node.extent_size, file_size_) ||
                node.extent_offset % kAlign != 0)
                throw Error("A NUP file's data is out of bounds");
        }
        children_.resize(static_cast<std::size_t>(slots));
        const std::uint8_t* c = toc.data() + files_end;
        for (std::size_t i = 0; i < children_.size(); ++i) {
            children_[i] = U32(c + 4 * i);
            if (children_[i] >= dir_count_ + file_count_) throw Error("A NUP directory lists something that does not exist");
        }
        pool_.assign(toc.begin() + static_cast<std::ptrdiff_t>(pool_off_),
                     toc.begin() + static_cast<std::ptrdiff_t>(pool_off_ + pool_size_));
        for (const FileNode& node : files_) CheckName(Name(node.name_off, node.name_len));
    }

    std::string_view Name(std::uint32_t offset, std::uint32_t length) const {
        return std::string_view{reinterpret_cast<const char*>(pool_.data()) + offset, length};
    }
    // A name is a label, never a path (SPEC 6.1): nothing that could leave the folder it is written in.
    static void CheckName(std::string_view name) {
        if (name.empty() || name == "." || name == ".." || name.find_first_of(std::string_view{"/\\\0", 3}) != std::string_view::npos)
            throw Error("A name in the NUP cannot be used as a file name");
    }

    template <class Sink>
    void Stream(const FileNode& node, Sink&& sink, const std::atomic<bool>* stop) const {
        if (fseeko(file_.get(), static_cast<off_t>(node.extent_offset), SEEK_SET) != 0)
            throw Error("Cannot read " + path_);
        std::uint64_t remaining = node.extent_size;
        std::vector<std::uint8_t> in(256u << 10);
        const auto read_more = [&](std::size_t& got) {
            if (stop && *stop) throw Cancelled();
            const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(in.size(), remaining));
            if (want == 0) {
                got = 0;
                return;
            }
            got = std::fread(in.data(), 1, want, file_.get());
            if (got != want) throw Error("Cannot read " + path_);
            remaining -= got;
        };
        if (node.codec == 0) {
            std::size_t got = 0;
            for (read_more(got); got; read_more(got)) sink(in.data(), got);
            return;
        }
        struct Decoder {
            ZSTD_DStream* stream = ZSTD_createDStream();
            ~Decoder() { ZSTD_freeDStream(stream); }
        } decoder;
        if (!decoder.stream) throw Error("Out of memory");
        if (ZSTD_isError(ZSTD_initDStream(decoder.stream))) throw Error("Cannot start the decompressor");
        std::vector<std::uint8_t> out(1u << 20);
        bool finished = false;
        std::size_t got = 0;
        for (read_more(got); got && !finished; read_more(got)) {
            ZSTD_inBuffer input{in.data(), got, 0};
            for (;;) {
                ZSTD_outBuffer output{out.data(), out.size(), 0};
                const std::size_t hint = ZSTD_decompressStream(decoder.stream, &output, &input);
                if (ZSTD_isError(hint)) throw Error("The NUP is damaged (a file does not decompress)");
                sink(out.data(), output.pos);
                if (hint == 0) {
                    // End of the frame: the extent holds exactly one, nothing may follow it.
                    finished = true;
                    if (input.pos != input.size || remaining != 0) throw Error("A file in the NUP has data after its end");
                    break;
                }
                // The decoder may still hold output when the input is used up: go on while the block came out full.
                if (input.pos == input.size && output.pos < output.size) break;
            }
            if (stop && *stop) throw Cancelled();
        }
        if (!finished) throw Error("A file in the NUP ends before its compressed data does");
    }

    std::string path_;
    std::unique_ptr<std::FILE, detail::Closer> file_;
    std::uint64_t real_size_ = 0, toc_offset_ = 0, toc_size_ = 0, blob_offset_ = 0, file_size_ = 0;
    std::uint64_t dir_count_ = 0, file_count_ = 0, pool_off_ = 0, pool_size_ = 0;
    std::uint16_t header_size_ = 0;
    std::array<std::uint8_t, 32> toc_sha256_{};
    std::array<std::uint8_t, 16> uuid_{};
    std::vector<Package> packages_;
    std::vector<DirNode> dirs_;
    std::vector<FileNode> files_;
    std::vector<std::uint32_t> children_;
    std::vector<std::uint8_t> pool_;
};

// ---------------------------------------------------------------------------------------------------
// The library's view of a .nup.
struct Info {
    std::uint64_t title_id = 0;
    std::string name;             // the default-language name (TLV 0x0005), else the first localized one
    std::string publisher;
    std::string display_version;
    std::vector<std::uint8_t> icon;  // JPEG or PNG bytes, empty without one
    std::uint32_t languages = 0;     // NACP supported-language flags (bit n: ApplicationLanguage n); 0 unknown
    std::vector<std::uint8_t> build_id;
    unsigned updates = 0;
    unsigned addons = 0;
    std::uint32_t newest_update = 0;  // the newest update package's version, 0 without one
    bool has_base = false;
};

namespace detail {
inline std::string Text(const std::vector<std::uint8_t>& bytes) { return std::string(bytes.begin(), bytes.end()); }

// The records of a localized TLV (SPEC 5.1): tag -> data, in file order.
inline std::vector<std::pair<std::string, std::vector<std::uint8_t>>> Localized(const std::vector<std::uint8_t>& payload) {
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> records;
    std::size_t position = 0;
    while (position < payload.size()) {
        const std::size_t tag_size = payload[position++];
        if (tag_size == 0 || payload.size() - position < tag_size + 4) break;
        std::string tag(payload.begin() + static_cast<std::ptrdiff_t>(position),
                        payload.begin() + static_cast<std::ptrdiff_t>(position + tag_size));
        position += tag_size;
        const std::uint32_t size = U32(payload.data() + position);
        position += 4;
        if (size > payload.size() - position) break;
        records.emplace_back(std::move(tag), std::vector<std::uint8_t>(
                                                 payload.begin() + static_cast<std::ptrdiff_t>(position),
                                                 payload.begin() + static_cast<std::ptrdiff_t>(position + size)));
        position += size;
    }
    return records;
}
}  // namespace detail

inline Info ReadInfo(const std::string& path) {
    Archive archive(path, Archive::Mode::info);
    Info info;
    const Package* holder = nullptr;  // where the application's metadata is: the base, else the first package
    for (const Package& package : archive.packages()) {
        if (package.kind == kBase) {
            info.has_base = true;
            holder = &package;
            info.title_id = package.title_id;
        } else if (package.kind == kUpdate) {
            ++info.updates;
            info.newest_update = std::max(info.newest_update, package.version);
        } else if (package.kind == kAddon || package.kind == kAddonUpdate) {
            ++info.addons;
        }
    }
    if (!holder) holder = &archive.packages().front();
    if (!info.has_base) {
        // A game without its base: the title of its first update (or add-on) stands for it.
        info.title_id = holder->title_id;
    }
    const Meta meta = archive.ReadMeta(*holder);
    const auto text = [&](std::uint16_t type) {
        const auto found = meta.find(type);
        return found == meta.end() ? std::string{} : detail::Text(found->second);
    };
    info.name = text(kTlvTitleName);
    info.publisher = text(kTlvPublisher);
    info.display_version = text(kTlvDisplayVersion);
    if (const auto icon = meta.find(kTlvIcon); icon != meta.end()) info.icon = icon->second;
    if (const auto id = meta.find(kTlvBuildId); id != meta.end()) info.build_id = id->second;
    // Without a default name or icon, the first localized one (English first).
    const auto first_localized = [&](std::uint16_t type, auto&& use) {
        const auto found = meta.find(type);
        if (found == meta.end()) return;
        auto records = detail::Localized(found->second);
        std::stable_sort(records.begin(), records.end(), [](const auto& a, const auto& b) {
            const auto english = [](const std::string& tag) { return tag == "en-us" || tag == "en-gb" || tag == "en"; };
            return english(a.first) && !english(b.first);
        });
        for (const auto& record : records)
            if (use(record.second)) return;
    };
    if (info.name.empty())
        first_localized(kTlvLocalizedTitles, [&](const std::vector<std::uint8_t>& data) {
            info.name = detail::Text(data);
            return !info.name.empty();
        });
    if (info.icon.empty())
        first_localized(kTlvLocalizedIcons, [&](const std::vector<std::uint8_t>& data) {
            info.icon = data;
            return !data.empty();
        });
    if (const auto nacp = meta.find(kTlvNacp); nacp != meta.end() && nacp->second.size() >= 0x3030)
        info.languages = detail::U32(nacp->second.data() + 0x302C);  // ApplicationControlProperty.supported_language_flag
    return info;
}

// ---------------------------------------------------------------------------------------------------
// The cache.
inline constexpr const char* kMarker = ".nup-complete";

struct Progress {
    std::atomic<unsigned>* folders = nullptr;   // directories made
    std::atomic<unsigned>* files = nullptr;     // files written (or skipped as unchanged)
    std::atomic<unsigned>* expected = nullptr;  // files in all, known once the plan is made
    const std::atomic<bool>* stop = nullptr;
};

namespace detail {
struct DirEntry {
    std::string name;
    bool dir = false;
};
inline std::vector<DirEntry> ListDir(const std::string& path) {
    std::vector<DirEntry> names;
    std::error_code error;
#ifdef PS5_NATIVE
    const auto entries = Eden::ReadNativeDirectory(path, error);
#else
    const auto entries = std::filesystem::directory_iterator(path, error);
#endif
    if (error) return names;
    for (const auto& entry : entries) {
        std::error_code status;
        names.push_back({entry.path().filename().string(), entry.is_directory(status)});
    }
    return names;
}
inline void RemoveTree(const std::string& path) {
    for (const DirEntry& entry : ListDir(path)) {
        const std::string child = path + "/" + entry.name;
        if (entry.dir) RemoveTree(child);
        else std::remove(child.c_str());
    }
    std::remove(path.c_str());  // an empty directory: remove() takes it as rmdir does
}
inline bool MakeDirs(const std::string& path) {
    std::error_code error;
    std::filesystem::create_directories(path, error);
    return !error || Eden::DirectoryExists(path);
}
inline std::mutex& FailureMutex() {
    static std::mutex mutex;
    return mutex;
}
inline std::map<std::string, std::string>& Failures() {
    static std::map<std::string, std::string> failures;
    return failures;
}
}  // namespace detail

// The cache name of a .nup from its superblock alone (cheap), or empty when it is not one.
inline std::string KeyOf(const std::string& nup) {
    try {
        return Archive(nup, Archive::Mode::info).Key();
    } catch (const std::exception&) {
        return {};
    }
}

// Whether the game is unpacked in the cache already.
inline bool IsReady(const std::string& nup, const std::string& cache_root) {
    const std::string key = KeyOf(nup);
    return !key.empty() && Eden::FileExists(cache_root + "/" + key + "/" + kMarker);
}

// What a failed unpacking said, kept so that the game start does not repeat the work to learn it.
inline void RecordFailure(const std::string& nup, const std::string& message) {
    const std::lock_guard lock(detail::FailureMutex());
    detail::Failures()[nup] = message;
}
inline std::string TakeFailure(const std::string& nup) {
    const std::lock_guard lock(detail::FailureMutex());
    auto& failures = detail::Failures();
    const auto found = failures.find(nup);
    if (found == failures.end()) return {};
    std::string message = std::move(found->second);
    failures.erase(found);
    return message;
}

// Older unpackings are dropped, the newest `keep` kept (`current` always): a game is a lot of space.
inline void PruneCache(const std::string& cache_root, const std::string& current, std::size_t keep = 2) {
    struct Candidate {
        std::string name;
        std::int64_t time;
    };
    std::vector<Candidate> done;
    for (const detail::DirEntry& entry : detail::ListDir(cache_root)) {
        if (!entry.dir) continue;
        const std::string folder = cache_root + "/" + entry.name;
        if (entry.name.size() > 8 && entry.name.compare(entry.name.size() - 8, 8, ".partial") == 0) {
            detail::RemoveTree(folder);  // an unpacking that was cut off
            continue;
        }
        struct stat info {};
        if (stat((folder + "/" + kMarker).c_str(), &info) != 0) continue;  // not ours: left alone
        done.push_back({entry.name, static_cast<std::int64_t>(info.st_mtime)});
    }
    std::sort(done.begin(), done.end(), [&](const Candidate& a, const Candidate& b) {
        if ((a.name == current) != (b.name == current)) return a.name == current;
        return a.time > b.time;
    });
    for (std::size_t i = keep; i < done.size(); ++i) detail::RemoveTree(cache_root + "/" + done[i].name);
}

// Unpacks the game into <cache_root>/<key>/ unless it is there, and returns its exefs/main (what the core
// is started with). Layers: the base package in base/, each update in updates/<decimal version>/, oldest
// first; a file of an update that equals the one of the layers below is not written again.
inline std::string Materialize(const std::string& nup, const std::string& cache_root, const Progress& progress = {}) {
    using namespace detail;
    // Already unpacked: only the superblock and the package records are read.
    const std::string key = Archive(nup, Archive::Mode::info).Key();
    const std::string finished = cache_root + "/" + key;
    const auto result = [&]() {
        const std::string main = Eden::ExtractedGameMain(finished);
        if (main.empty()) throw Error("The NUP holds no program (exefs/main)");
        return main;
    };
    if (Eden::FileExists(finished + "/" + kMarker)) {
        if (std::FILE* marker = std::fopen((finished + "/" + kMarker).c_str(), "wb")) {  // used now: kept longest
            std::fputs(key.c_str(), marker);
            std::fclose(marker);
        }
        return result();
    }
    Archive archive(nup, Archive::Mode::full);  // the table of contents is verified before anything is written

    // The layers, oldest first.
    struct Layer {
        const Package* package;
        std::string folder;  // "base" or "updates/<version>"
    };
    std::vector<Layer> layers;
    std::vector<const Package*> updates;
    for (const Package& package : archive.packages()) {
        if (package.kind == kBase) layers.push_back({&package, "base"});
        else if (package.kind == kUpdate) updates.push_back(&package);
    }
    std::stable_sort(updates.begin(), updates.end(), [](const Package* a, const Package* b) { return a->version < b->version; });
    std::set<std::uint32_t> versions;
    for (const Package* package : updates) {
        if (!versions.insert(package->version).second) throw Error("The NUP holds two updates of the same version");
        layers.push_back({package, "updates/" + std::to_string(package->version)});
    }
    if (layers.empty()) throw Error("The NUP holds no game or update to start");

    // The plan: what each layer writes. Only the exefs and romfs of a package count (read through its
    // record fields, SPEC 3.1.3).
    struct Job {
        std::string path;  // relative to the unpacking folder
        std::uint32_t file;
    };
    std::vector<Job> jobs;
    std::set<std::string> folders;
    [[maybe_unused]] std::uint64_t bytes = 0;  // only the host build checks the free space
    std::uint64_t skipped = 0;
    std::map<std::string, std::pair<std::array<std::uint8_t, 32>, std::uint64_t>> below;  // path -> content so far
    for (const Layer& layer : layers) {
        for (const auto& [name, dir] : {std::pair<const char*, std::uint32_t>{"exefs", layer.package->exefs_dir},
                                        std::pair<const char*, std::uint32_t>{"romfs", layer.package->romfs_dir}}) {
            if (dir == kNoDir) continue;
            const std::string tree = std::string{name};
            const Listing listing = archive.List(dir, tree);
            for (const Entry& entry : listing.files) {
                const FileNode& node = archive.file(entry.file);
                const auto known = below.find(entry.path);
                if (known != below.end() && known->second.first == node.sha256 && known->second.second == node.size) {
                    ++skipped;  // the layer below has this very file
                    continue;
                }
                below[entry.path] = {node.sha256, node.size};
                jobs.push_back({layer.folder + "/" + entry.path, entry.file});
                bytes += node.size;
            }
            // Directories only of what is written here, and the empty ones of a base.
            for (const std::string& folder : listing.dirs) folders.insert(layer.folder + "/" + folder);
        }
    }
    const bool has_program = std::any_of(jobs.begin(), jobs.end(), [](const Job& job) {
        return job.path.size() >= 10 && job.path.compare(job.path.size() - 10, 10, "exefs/main") == 0 &&
               (job.path.size() == 10 || job.path[job.path.size() - 11] == '/');
    });
    if (!has_program) throw Error("The NUP holds no program (exefs/main)");
    if (progress.expected) *progress.expected = static_cast<unsigned>(std::min<std::size_t>(jobs.size() + skipped, 0xFFFFFFFFu));
    if (progress.files) *progress.files = static_cast<unsigned>(std::min<std::uint64_t>(skipped, 0xFFFFFFFFu));
#ifndef PS5_NATIVE
    // The console's free space is not known to a title (see remote/remote.cpp); a full disk shows as a write error.
    if (MakeDirs(cache_root)) {
        struct statvfs space {};
        if (statvfs(cache_root.c_str(), &space) == 0 &&
            static_cast<std::uint64_t>(space.f_bavail) * space.f_frsize < bytes + (64ull << 20))
            throw Error("Not enough free space to unpack the game");
    }
#endif

    const std::string partial = finished + ".partial";
    RemoveTree(partial);
    if (!MakeDirs(partial)) throw Error("Cannot create " + partial);
    try {
        unsigned made = 0;
        for (const std::string& folder : folders) {
            if (progress.stop && *progress.stop) throw Cancelled();
            if (!MakeDirs(partial + "/" + folder)) throw Error("Cannot create " + partial + "/" + folder);
            if (progress.folders) *progress.folders = ++made;
        }
        for (const Job& job : jobs) {
            if (progress.stop && *progress.stop) throw Cancelled();
            archive.Extract(job.file, partial + "/" + job.path, progress.stop);
            if (progress.files) ++*progress.files;
        }
        std::FILE* marker = std::fopen((partial + "/" + kMarker).c_str(), "wb");
        if (!marker) throw Error("Cannot write in " + partial);
        std::fputs(key.c_str(), marker);
        if (std::fclose(marker) != 0) throw Error("Cannot write in " + partial);
        if (std::rename(partial.c_str(), finished.c_str()) != 0) throw Error("Cannot move the unpacked game into place");
    } catch (...) {
        RemoveTree(partial);
        throw;
    }
    PruneCache(cache_root, key);
    return result();
}

// The game start: the unpacking is done already when the launcher prepared it (this is then a
// check), else it is made here, without progress. A failure the launcher met is reported as it was.
inline std::string EnsureExtracted(const std::string& nup, const std::string& cache_root) {
    if (const std::string failure = TakeFailure(nup); !failure.empty()) throw Error(failure);
    return Materialize(nup, cache_root);
}

}  // namespace Eden::Nup
