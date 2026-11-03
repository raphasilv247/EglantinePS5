// SPDX-License-Identifier: GPL-3.0-or-later
// Host check for the NUP reader (nup.h).
//   eden-nup-check                       SHA-256 and the other self-contained checks
//   eden-nup-check <game.nup> <dump>     also: unpack the .nup (made by tools/nup from <dump>) and compare it with
//                                        the dump, layer by layer, then try damaged copies of it
// The dump has the layout `nup pack` reads: base/{exefs,romfs}, updates/<decimal version>/{exefs,romfs}.
#include "nup.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <cstdlib>
#include <fstream>
#include <functional>
#include <iterator>

namespace {
namespace fs = std::filesystem;

[[noreturn]] void fail(const std::string& what) {
    std::fprintf(stderr, "NUP check FAIL: %s\n", what.c_str());
    std::exit(1);
}
void require(bool condition, const std::string& what) {
    if (!condition) fail(what);
}

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}
void write_file(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << bytes;
}

std::string hex_of(const std::string& text) {
    const auto digest = Eden::Nup::Sha256::Of(text.data(), text.size());
    return Eden::Nup::Hex(digest.data(), digest.size());
}

void check_sha256() {
    require(hex_of("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 of nothing");
    require(hex_of("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 of abc");
    require(hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "SHA-256 of the two-block message");
    // A million 'a's, fed in uneven pieces: the buffering across blocks.
    Eden::Nup::Sha256 hash;
    std::string piece(997, 'a');
    std::size_t left = 1000000;
    while (left) {
        const std::size_t take = std::min(left, piece.size());
        hash.Update(piece.data(), take);
        left -= take;
    }
    const auto digest = hash.Final();
    require(Eden::Nup::Hex(digest.data(), 32) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            "SHA-256 of a million a");
}

void check_paths() {
    require(Eden::Nup::IsNupPath("a.nup") && Eden::Nup::IsNupPath("Game [0100].NUP") && !Eden::Nup::IsNupPath("a.nsp") &&
                !Eden::Nup::IsNupPath(".nup") && !Eden::Nup::IsNupPath("nup"),
            "the .nup extension");
}

void for_each_file(const fs::path& tree, const std::function<void(const std::string&, const fs::path&)>& visit) {
    if (!fs::is_directory(tree)) return;
    for (const auto& entry : fs::recursive_directory_iterator(tree))
        if (entry.is_regular_file()) visit(fs::relative(entry.path(), tree).generic_string(), entry.path());
}

// A copy of the .nup with one byte changed.
fs::path damaged(const fs::path& nup, const fs::path& folder, const char* name, std::uint64_t offset) {
    std::string bytes = read_file(nup);
    require(offset < bytes.size(), std::string{"damage offset for "} + name);
    bytes[offset] = static_cast<char>(bytes[offset] ^ 0x5A);
    const fs::path out = folder / name;
    write_file(out, bytes);
    return out;
}

bool unpack_fails(const fs::path& nup, const fs::path& cache, const std::string& expect) {
    try {
        (void)Eden::Nup::Materialize(nup.string(), cache.string());
    } catch (const Eden::Nup::Error& error) {
        std::printf("  refused as expected: %s\n", error.what());
        return std::string{error.what()}.find(expect) != std::string::npos;
    }
    return false;
}

void check_package(const fs::path& nup, const fs::path& dump) {
    const fs::path work = fs::temp_directory_path() / ("nup-check-" + std::to_string(::getpid()));
    fs::remove_all(work);
    fs::create_directories(work);
    const fs::path cache = work / "cache";

    // -- the library's view
    const Eden::Nup::Info info = Eden::Nup::ReadInfo(nup.string());
    std::printf("title %016llx \"%s\" by \"%s\" version %s, %u update(s), %u add-on(s), icon %zu bytes\n",
                static_cast<unsigned long long>(info.title_id), info.name.c_str(), info.publisher.c_str(),
                info.display_version.c_str(), info.updates, info.addons, info.icon.size());
    require(info.title_id != 0, "the title ID is read");

    // -- not ready, then unpacked, then ready
    require(!Eden::Nup::IsReady(nup.string(), cache.string()), "a game that was not unpacked is not ready");
    std::atomic<unsigned> folders{0}, files{0}, expected{0};
    const Eden::Nup::Progress progress{&folders, &files, &expected, nullptr};
    const std::string main = Eden::Nup::Materialize(nup.string(), cache.string(), progress);
    require(Eden::FileExists(main), "exefs/main exists: " + main);
    require(files.load() == expected.load() && expected.load() > 0, "progress ends complete");
    require(Eden::Nup::IsReady(nup.string(), cache.string()), "the game is ready after unpacking");
    const std::string again = Eden::Nup::EnsureExtracted(nup.string(), cache.string());
    require(again == main, "a second start finds the same program");
    std::printf("unpacked: %s (%u folders, %u files)\n", main.c_str(), folders.load(), files.load());

    // The unpacked folder (the key's) holds the layers.
    fs::path unpacked;
    for (const auto& entry : fs::directory_iterator(cache))
        if (entry.is_directory() && fs::exists(entry.path() / Eden::Nup::kMarker)) unpacked = entry.path();
    require(!unpacked.empty(), "an unpacked folder with its marker");
    require(fs::path(main).string().rfind(unpacked.string(), 0) == 0, "main is inside the unpacked folder");

    // -- the unpacked folder is the dump as its newest version has it: base files, replaced by each update's,
    //    in version order; nothing else, nothing twice
    std::vector<std::pair<std::uint64_t, std::string>> versions;  // (version, folder) of the updates in the dump
    if (fs::is_directory(dump / "updates"))
        for (const auto& entry : fs::directory_iterator(dump / "updates"))
            if (entry.is_directory()) versions.emplace_back(std::stoull(entry.path().filename().string()), entry.path().filename().string());
    std::sort(versions.begin(), versions.end());
    std::map<std::string, fs::path> expected_files;  // relative path -> file of the dump
    const auto overlay = [&](const fs::path& source) {
        for (const char* tree : {"exefs", "romfs"})
            for_each_file(source / tree, [&](const std::string& relative, const fs::path& file) {
                expected_files[std::string{tree} + "/" + relative] = file;
            });
    };
    if (fs::is_directory(dump / "base")) overlay(dump / "base");
    else overlay(dump);  // a bare content folder
    for (const auto& version : versions) overlay(dump / "updates" / version.second);

    std::size_t found = 0;
    for_each_file(unpacked, [&](const std::string& relative, const fs::path& file) {
        if (relative == Eden::Nup::kMarker) return;
        const auto want = expected_files.find(relative);
        require(want != expected_files.end(), "the unpacked folder has a file the dump does not: " + relative);
        require(read_file(file) == read_file(want->second), relative + " has the bytes of the dump's newest version");
        ++found;
    });
    require(found == expected_files.size(), "every file of the dump's newest version is unpacked");
    require(!fs::exists(unpacked / "base") && !fs::exists(unpacked / "updates"), "a flat folder, no layers");
    require(fs::path(main) == unpacked / "exefs" / "main", "the game starts from exefs/main at the root");
    std::printf("compared %zu files with the dump's newest version\n", found);
    require(found > 0, "something was compared");
    require(files.load() == found, "one write for each file");

    // -- damaged copies are refused, and leave nothing behind
    const fs::path bad_cache = work / "bad-cache";
    // A byte inside the data of the program the game starts from (the newest package's exefs/main), which is
    // always unpacked: its hash (or its zstd frame) must catch it. (Data of files an update replaced is never
    // read, so a change there is not noticed.)
    std::uint64_t victim = 0;
    {
        const Eden::Nup::Archive archive(nup.string());
        // Newest first: updates by version, then the base; the first package that has an exefs/main.
        std::vector<const Eden::Nup::Package*> order;
        for (const Eden::Nup::Package& package : archive.packages())
            if (package.kind == Eden::Nup::kBase || package.kind == Eden::Nup::kUpdate) order.push_back(&package);
        std::sort(order.begin(), order.end(), [](const auto* a, const auto* b) {
            if ((a->kind == Eden::Nup::kUpdate) != (b->kind == Eden::Nup::kUpdate)) return a->kind == Eden::Nup::kUpdate;
            return a->version > b->version;
        });
        for (const auto* package : order) {
            if (victim != 0 || package->exefs_dir == Eden::Nup::kNoDir) continue;
            for (const Eden::Nup::Entry& entry : archive.List(package->exefs_dir, "exefs").files)
                if (entry.path == "exefs/main") victim = archive.file(entry.file).extent_offset + 1;
        }
        require(victim != 0, "the extent of exefs/main");
    }
    require(unpack_fails(damaged(nup, work, "blob.nup", victim), bad_cache, "damaged"), "a damaged byte of file data");
    require(unpack_fails(damaged(nup, work, "toc.nup", 0x90), bad_cache, "table of contents"), "a damaged table of contents");
    require(unpack_fails(damaged(nup, work, "magic.nup", 1), bad_cache, "Not a NUP"), "a damaged magic");
    {
        std::string bytes = read_file(nup);
        bytes.resize(bytes.size() - 7);
        write_file(work / "short.nup", bytes);
        require(unpack_fails(work / "short.nup", bad_cache, "incomplete"), "a truncated file");
        write_file(work / "empty.nup", "");
        require(unpack_fails(work / "empty.nup", bad_cache, "truncated"), "an empty file");
        require(!Eden::Nup::IsReady((work / "short.nup").string(), bad_cache.string()), "a broken file is never ready");
    }
    if (fs::exists(bad_cache))
        for (const auto& entry : fs::directory_iterator(bad_cache))
            require(entry.path().extension() != ".partial" && fs::exists(entry.path() / Eden::Nup::kMarker),
                    "a failed unpacking leaves no partial folder");

    // -- a stop request ends the unpacking and removes what it began
    {
        std::atomic<bool> stop{true};
        const fs::path stopped = work / "stopped-cache";
        bool cancelled = false;
        try {
            (void)Eden::Nup::Materialize(nup.string(), stopped.string(), {nullptr, nullptr, nullptr, &stop});
        } catch (const Eden::Nup::Cancelled&) {
            cancelled = true;
        }
        require(cancelled, "a stop request cancels the unpacking");
        require(!fs::exists(stopped) || fs::is_empty(stopped), "a cancelled unpacking leaves nothing behind");
    }

    // -- older unpackings are pruned: with the newest two kept, a third replaces the oldest
    {
        const fs::path pruned = work / "pruned";
        for (const char* name : {"aaaa-f2", "bbbb-f2", "cccc-f2"}) {
            write_file(pruned / name / Eden::Nup::kMarker, name);
            write_file(pruned / name / "base/exefs/main", "x");
        }
        write_file(pruned / "foreign" / "keep.txt", "not ours");
        write_file(pruned / "dddd-4.partial" / "half", "x");
        write_file(pruned / "eeee-old" / Eden::Nup::kMarker, "x");  // an older layout
        struct timespec old_time[2] = {{1000, 0}, {1000, 0}};
        utimensat(AT_FDCWD, (pruned / "aaaa-f2" / Eden::Nup::kMarker).c_str(), old_time, 0);
        struct timespec mid_time[2] = {{2000, 0}, {2000, 0}};
        utimensat(AT_FDCWD, (pruned / "bbbb-f2" / Eden::Nup::kMarker).c_str(), mid_time, 0);
        Eden::Nup::PruneCache(pruned.string(), "cccc-f2");
        require(!fs::exists(pruned / "aaaa-f2"), "the oldest unpacking is dropped");
        require(fs::exists(pruned / "bbbb-f2") && fs::exists(pruned / "cccc-f2"), "the newest ones stay");
        require(fs::exists(pruned / "foreign" / "keep.txt"), "a folder that is not ours is left alone");
        require(!fs::exists(pruned / "dddd-4.partial"), "a cut-off unpacking is cleared");
        require(!fs::exists(pruned / "eeee-old"), "an unpacking of an older layout is dropped");
    }
    fs::remove_all(work);
}
}  // namespace

int main(int argc, char** argv) {
    check_sha256();
    check_paths();
    if (argc == 3) check_package(argv[1], argv[2]);
    else if (argc != 1) fail("usage: eden-nup-check [<game.nup> <dump folder>]");
    std::puts("NUP check PASS");
    return 0;
}
