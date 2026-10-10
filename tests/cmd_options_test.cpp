#include "cmd_options.h"
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>

namespace {
using namespace CryptoGuard;
namespace fs = std::filesystem;

// Специально сделал RAII для тренировки
struct TemporaryFile final {
    const fs::path m_BasePath;
    const fs::path m_FilePath;
    std::fstream m_Stream;

    explicit TemporaryFile(std::string_view filename, std::string_view fileContent = "")
        : m_BasePath(
              fs::temp_directory_path() /
              ("CryptoGuardTest_" +
               std::to_string(std::hash<std::thread::id>{}(
                   std::this_thread::get_id())))),  // Тесты работают параллельно, соответственно папки нужны уникальные
          m_FilePath(m_BasePath / filename) {
        if (!fs::exists(m_BasePath)) {
            if (!fs::create_directories(m_BasePath))
                throw std::runtime_error("Cannot create temporary file");
        }

        if (fs::exists(m_FilePath))
            fs::remove(m_FilePath);

        m_Stream.open(m_FilePath, std::ios::out | std::ios::trunc);
        if (!m_Stream.is_open()) {
            throw std::runtime_error("Cannot open temporary file for writing");
        }
        if (!fileContent.empty()) {
            m_Stream << fileContent;
            m_Stream.flush();
        }
    }

    ~TemporaryFile() {
        if (m_Stream.is_open())
            m_Stream.close();

        if (fs::exists(m_FilePath))
            fs::remove(m_FilePath);

        try {
            fs::remove_all(m_BasePath);
        } catch (...) {
        }
    }

    const std::string GetFolderPath() const noexcept { return m_BasePath.string(); }
    const std::string GetStringPath() const noexcept { return m_FilePath.string(); }
};

std::pair<std::vector<std::string>, std::vector<char *>> MakeArgv(const std::vector<std::string> &args) {
    std::vector<std::string> storage;
    storage.reserve(args.size());

    for (const auto &s : args)
        storage.push_back(s);

    std::vector<char *> argv;
    argv.reserve(storage.size() + 1);  // Для null-терминатора
    for (auto &s : storage)
        argv.push_back(const_cast<char *>(s.c_str()));
    argv.push_back(nullptr);  // Сам null-терминатор

    return {std::move(storage), std::move(argv)};
}
}  // namespace

TEST(ProgramOptions, MissingInputFile) {
    auto [storage, argv] = MakeArgv({"./app", "-i"});

    CryptoGuard::ProgramOptions po;
    po.Parse(static_cast<int>(storage.size()), argv.data());

    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);

    EXPECT_TRUE(po.GetInputFile().empty());
    EXPECT_TRUE(po.GetOutputFile().empty());
    EXPECT_TRUE(po.GetPassword().empty());
}

TEST(ProgramOptions, MissingOutputFile) {
    TemporaryFile tmp("input.txt", "Hello OpenSSL crypto world!");
    std::string inputPath = tmp.GetStringPath();

    auto [storage, argv] = MakeArgv({"./app", "-i", inputPath, "--command", "encrypt"});

    CryptoGuard::ProgramOptions po;
    po.Parse(static_cast<int>(storage.size()), argv.data());

    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);

    EXPECT_FALSE(po.GetInputFile().empty());
    EXPECT_EQ(po.GetInputFile(), inputPath);

    EXPECT_TRUE(po.GetOutputFile().empty());
    EXPECT_TRUE(po.GetPassword().empty());
}

TEST(ProgramOptions, MissingCommand) {
    TemporaryFile tmp("input.txt", "Hello OpenSSL crypto world!");
    std::string inputPath = tmp.GetStringPath();

    auto [storage, argv] = MakeArgv({"./app", "-i", inputPath});

    CryptoGuard::ProgramOptions po;
    po.Parse(static_cast<int>(storage.size()), argv.data());

    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);

    EXPECT_TRUE(po.GetInputFile().empty());
    EXPECT_TRUE(po.GetOutputFile().empty());
    EXPECT_TRUE(po.GetPassword().empty());
}

TEST(ProgramOptions, NoInputOptionAtAll) {
    auto [storage, argv] = MakeArgv({"./app", "--command", "checksum"});

    CryptoGuard::ProgramOptions po;
    po.Parse(static_cast<int>(storage.size()), argv.data());

    EXPECT_TRUE(po.GetInputFile().empty());
    EXPECT_NE(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, SuccessCommandChecksum) {
    TemporaryFile tmp("input.txt", "Hello OpenSSL crypto world!");
    std::string inputPath = tmp.GetStringPath();

    auto [storage, argv] = MakeArgv({"./app", "-i", inputPath, "--command", "checksum"});

    CryptoGuard::ProgramOptions po;
    po.Parse(static_cast<int>(storage.size()), argv.data());

    EXPECT_EQ(po.GetInputFile(), inputPath);
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, MixedLongAndShortOptions) {
    TemporaryFile tmp("input.txt", "Hello OpenSSL crypto world!");

    std::string inputPath = tmp.GetStringPath();
    std::string outputPath = fs::path(tmp.GetFolderPath()) / "output.txt";
    std::string pwd = "superSecretPwd";

    fs::remove(outputPath);  // fs::remove принимает fs::path

    auto [storage, argv] =
        MakeArgv({"./app", "--command", "decrypt", "-i", inputPath, "--output", outputPath, "-p", pwd});

    CryptoGuard::ProgramOptions po;
    po.Parse(static_cast<int>(storage.size()), argv.data());

    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(po.GetInputFile(), inputPath);
    EXPECT_EQ(po.GetOutputFile(), outputPath);
    EXPECT_EQ(po.GetPassword(), pwd);
}