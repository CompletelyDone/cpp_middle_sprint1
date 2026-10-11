#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <exception>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions po;
        po.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx ctx;

        switch (po.GetCommand()) {
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM: {
            std::fstream fs(po.GetInputFile(), std::ios::in);
            if (!fs.is_open())
                throw std::runtime_error("Cannot open input file.");
            std::string checksum = ctx.CalculateChecksum(fs);
            std::println("Checksum result: {}", checksum);
            break;
        };
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT: {
            std::fstream fs(po.GetInputFile(), std::ios::in);
            if (!fs.is_open())
                throw std::runtime_error("Cannot open input file.");
            std::fstream os(po.GetOutputFile(), std::ios::out | std::ios::trunc);
            if (!os.is_open())
                throw std::runtime_error("Cannot open output file.");
            ctx.EncryptFile(fs, os, po.GetPassword());
            std::println("Input file: {}\nOutput file: {}\nResult: Success", po.GetInputFile(), po.GetOutputFile());
            break;
        };
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT: {
            std::fstream fs(po.GetInputFile(), std::ios::in);
            if (!fs.is_open())
                throw std::runtime_error("Cannot open input file.");
            std::fstream os(po.GetOutputFile(), std::ios::out | std::ios::trunc);
            if (!os.is_open())
                throw std::runtime_error("Cannot open output file.");
            ctx.DecryptFile(fs, os, po.GetPassword());
            std::println("Input file: {}\nOutput file: {}\nResult: Success", po.GetInputFile(), po.GetOutputFile());
            break;
        };
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::UNKNOWN: {
            return 0;
        }
        default:
            break;
        }
    } catch (const std::exception &error) {
        std::println(std::cout, "Error: {}", error.what());
        return 1;
    }

    return 0;
}