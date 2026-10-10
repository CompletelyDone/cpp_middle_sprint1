#include "cmd_options.h"
#include <boost/program_options/errors.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <filesystem>
#include <iostream>
#include <string>

namespace CryptoGuard {

namespace po = boost::program_options;
namespace fs = std::filesystem;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "show help message")("command,c", po::value<std::string>(),
                                                       "command to proceed: encrypt, decrypt, or checksum")(
        "input,i", po::value<std::string>()->required(), "input file path")(
        "output,o", po::value<std::string>(), "output file path")("password,p", po::value<std::string>(),
                                                                  "password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {

    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);
    } catch (const po::error &err) {
        std::cerr << "Error: " << err.what() << std::endl;
        std::cout << desc_ << std::endl;
        return;
    }

    if (vm.count("help")) {
        desc_.print(std::cout);
        return;
    }

    if (!vm.count("command")) {
        std::cerr << "Error: command option is required" << std::endl;
        desc_.print(std::cout);
        return;
    }

    const auto &cmdStr = vm["command"].as<std::string>();
    auto it = commandMapping_.find(cmdStr);
    if (it != commandMapping_.end()) {
        command_ = it->second;
    } else {
        std::cerr << "Error: command option is unknown" << std::endl
                  << "Allowed in { encrypt, decrypt, checksum }" << std::endl;
        desc_.print(std::cout);
        return;
    }

    const auto &inputPath = vm["input"].as<std::string>();
    if (!fs::exists(inputPath) || !fs::is_regular_file(inputPath)) {
        std::cerr << "Error: input file does not exist or is not a regular file: " << inputPath << std::endl;
        std::cout << desc_ << std::endl;
        return;
    }
    inputFile_ = inputPath;

    if (command_ != COMMAND_TYPE::CHECKSUM) {

        if (!vm.count("output") || vm["output"].as<std::string>().empty()) {
            std::cerr << "Error: output file is required." << std::endl;
            std::cout << desc_ << std::endl;
            return;
        }
        if (!vm.count("password") || vm["password"].as<std::string>().empty()) {
            std::cerr << "Error: password is required for encrypt/decrypt commands." << std::endl;
            std::cout << desc_ << std::endl;
            return;
        }

        const auto &outputPath = vm["output"].as<std::string>();

        auto parentDir = fs::path(outputPath).parent_path();
        if (!parentDir.empty() && !fs::exists(parentDir)) {
            std::cerr << "Error: directory for output file does not exist: " << parentDir << std::endl;
            std::cout << desc_ << std::endl;
            return;
        }

        outputFile_ = outputPath;
        password_ = vm["password"].as<std::string>();
    }
}
}  // namespace CryptoGuard
