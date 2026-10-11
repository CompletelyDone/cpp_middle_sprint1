#include "cmd_options.h"
#include <boost/program_options/errors.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

namespace po = boost::program_options;
namespace fs = std::filesystem;

ProgramOptions::ProgramOptions() : desc_("Allowed options"), command_(COMMAND_TYPE::UNKNOWN) {
    desc_.add_options()("help,h", "show help message")("command,c", po::value<std::string>(),
                                                       "command to proceed: encrypt, decrypt, or checksum")(
        "input,i", po::value<std::string>(), "input file path")(
        "output,o", po::value<std::string>(), "output file path")("password,p", po::value<std::string>(),
                                                                  "password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {

    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);  // Как я понял тут парсинг

        if (vm.count("help")) {
            desc_.print(std::cout);
            return;
        }

        po::notify(vm);  // А тут проверка required из конструктора(при наличии)
    } catch (const po::error &err) {
        desc_.print(std::cout);
        throw std::runtime_error(std::string("Error: parsing has failed.") + err.what());
    }

    if (!vm.count("command")) {
        desc_.print(std::cout);
        throw std::runtime_error("Error: command option is required.");
    }

    if (!vm.count("input")) {
        desc_.print(std::cout);
        throw std::runtime_error("Error: input file is required.");
    }

    const auto &cmdStr = vm["command"].as<std::string>();
    auto it = commandMapping_.find(cmdStr);
    if (it != commandMapping_.end()) {
        command_ = it->second;
    } else {
        desc_.print(std::cout);
        throw std::runtime_error("Error: command option is unknown\n"
                                 "Allowed in { encrypt, decrypt, checksum }");
    }

    const auto &inputPath = vm["input"].as<std::string>();
    if (!fs::exists(inputPath) || !fs::is_regular_file(inputPath)) {
        desc_.print(std::cout);
        throw std::runtime_error(std::string("Error: input file does not exist or is not a regular file: ") +
                                 inputPath);
    }
    inputFile_ = inputPath;

    if (command_ != COMMAND_TYPE::CHECKSUM) {

        if (!vm.count("output") || vm["output"].as<std::string>().empty()) {
            desc_.print(std::cout);
            throw std::runtime_error("Error: output file is required.");
        }
        if (!vm.count("password") || vm["password"].as<std::string>().empty()) {
            desc_.print(std::cout);
            throw std::runtime_error("Error: password is required for encrypt/decrypt commands.");
        }

        const auto &outputPath = vm["output"].as<std::string>();

        auto parentDir = fs::path(outputPath).parent_path();
        if (!parentDir.empty() && !fs::exists(parentDir)) {
            desc_.print(std::cout);
            throw std::runtime_error(std::string("Error: directory for output file does not exist: ") +
                                     parentDir.string());
        }

        outputFile_ = outputPath;
        password_ = vm["password"].as<std::string>();
    }
}
}  // namespace CryptoGuard
