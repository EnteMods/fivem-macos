#include <StdInc.h>
#include <VFSManager.h>
#include <RelativeDevice.h>
#include <LocalDevice.h>
#include <Manager.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <zlib.h>

static void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

struct TemporaryRoot
{
    std::filesystem::path path;
    TemporaryRoot()
    {
        const auto pattern = (std::filesystem::temp_directory_path() / "cfx-native-vfs-XXXXXX").string();
        std::vector<char> buffer(pattern.begin(), pattern.end());
        buffer.push_back(0);
        const auto created = mkdtemp(buffer.data());
        if (!created) throw std::runtime_error("mkdtemp failed");
        path = created;
    }
    ~TemporaryRoot()
    {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
};

int main(int argc, char** argv)
{
    try
    {
        TemporaryRoot root;
        fwRefContainer<vfs::LocalDevice> local = new vfs::LocalDevice();
        if (argc == 2 && (std::string(argv[1]) == "--invalid-handle-probe" || std::string(argv[1]) == "--file-id-probe"))
        {
            if (std::string(argv[1]) != "--file-id-probe")
                Require(local->GetLength(vfs::Device::InvalidHandle) == size_t(-1), "Invalid handle stat must return failure sentinel");
            vfs::GetFileIdExtension id{vfs::Device::InvalidHandle, {}};
            Require(!local->ExtensionCtl(VFS_GET_FILE_ID, &id, sizeof(id)), "Invalid handle file-ID lookup must fail");
            std::cout << "Invalid POSIX handles rejected.\n";
            return 0;
        }
        fwRefContainer<vfs::ManagerServer> manager = new vfs::ManagerServer();
        Instance<vfs::Manager>::Set(manager.GetRef());
        fwRefContainer<vfs::RelativeDevice> mounted = new vfs::RelativeDevice(local, root.path.string() + "/");
        manager->Mount(mounted, "fixture:/");
        const std::string path = "fixture:/payload.bin";
        const std::string bytes("FiveM native\0resource", 21);
        auto output = vfs::Create(path);
        Require(output.GetRef() != nullptr, "Mounted file creation failed");
        Require(output->Write(bytes.data(), bytes.size()) == bytes.size(), "Mounted write failed");
        Require(output->Flush(), "Mounted fsync failed");
        Require(output->GetLength() == bytes.size(), "Mounted file length failed");
        output->Close();
        Require(output->GetHandle() == vfs::Device::InvalidHandle && !output->Flush(), "Closed stream handle validity failed");
        auto input = vfs::OpenRead(path);
        Require(input.GetRef() != nullptr, "Mounted file open failed");
        Require(input->Seek(6, SEEK_SET) == 6, "Mounted seek failed");
        auto tail = input->ReadToEnd();
        Require(std::string(tail.begin(), tail.end()) == bytes.substr(6), "Mounted read/seek bytes differ");
        Require(input->ReadToEnd().empty(), "EOF read failed");
        Require(input->Seek(-8, SEEK_END) == bytes.size() - 8, "Negative end-relative seek failed");
        char finalBytes[8];
        Require(input->Read(finalBytes, sizeof(finalBytes)) == sizeof(finalBytes), "End-relative read failed");
        Require(std::string(finalBytes, sizeof(finalBytes)) == bytes.substr(bytes.size() - 8), "End-relative payload differs");
        input->Close();
        Require(mounted->GetModifiedTime(path) > 0, "Mounted mtime stat failed");
        Require(mounted->GetAttributes(path) != uint32_t(-1), "Mounted file stat failed");
        Require((mounted->GetAttributes("fixture:/") & FILE_ATTRIBUTE_DIRECTORY) != 0, "Mounted directory stat failed");
        Require(vfs::OpenRead("fixture:/missing.bin").GetRef() == nullptr, "Missing file returned a valid stream");
        uint64_t pointer = 99;
        auto bulk = mounted->OpenBulk(path, &pointer);
        Require(bulk != vfs::Device::InvalidHandle && pointer == 0, "Bulk handle open failed");
        char first[5];
        Require(mounted->ReadBulk(bulk, 0, first, sizeof(first)) == sizeof(first) && std::string(first, sizeof(first)) == "FiveM", "Bulk pread failed");
        Require(mounted->CloseBulk(bulk), "Bulk close failed");
        const auto oldPath = root.path / "payload.bin";
        const auto newPath = root.path / "renamed.bin";
        Require(vfs::RenameFile(path, "fixture:/renamed.bin"), "POSIX rename success was reported as failure");
        Require(!std::filesystem::exists(oldPath) && std::filesystem::exists(newPath), "POSIX rename did not move the fixture");
        Require(!vfs::RenameFile("fixture:/missing.bin", "fixture:/nothing.bin"), "POSIX rename failure was reported as success");
        Require(vfs::RemoveFile("fixture:/renamed.bin"), "Mounted unlink failed");
        manager->Unmount("fixture:/");
        Require(vfs::OpenRead(path).GetRef() == nullptr, "Unmounted fixture unexpectedly accessible");
        std::cout << "Native mounted VFS write/read/seek/stat/bulk/rename/unlink passed.\n";
        std::cout << "zlib headers=" << ZLIB_VERSION << " runtime=" << zlibVersion() << '\n';
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
