#include "crypto_guard_ctx.h"
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace CryptoGuard {

namespace {
enum class CryptMode { Decrypt = 0, Encrypt = 1 };

std::string ErrorToString() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}
}  // namespace

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

struct CryptoGuardCtx::Impl {
    struct EVPCtxDeleter {
        void operator()(EVP_CIPHER_CTX *ctx) const {
            if (ctx)
                EVP_CIPHER_CTX_free(ctx);
        }
    };
    struct EVPMDCtxDeleter {
        void operator()(EVP_MD_CTX *ctx) const {
            if (ctx) {
                EVP_MD_CTX_free(ctx);
            }
        }
    };
    using CipherCtxUPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPCtxDeleter>;
    using MDCtxUPtr = std::unique_ptr<EVP_MD_CTX, EVPMDCtxDeleter>;
    // хотелось бы конечно через лямбду
    // using MDCtxUPtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    Impl() { OpenSSL_add_all_algorithms(); };
    ~Impl() { EVP_cleanup(); }

    void ProcessFile(std::iostream &inStream, std::iostream &outStream, std::string_view password, CryptMode mode) {
        if (!inStream || !outStream)
            throw std::runtime_error("Invalid stream");

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = static_cast<int>(mode);

        CipherCtxUPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw std::runtime_error(std::string("ctx not created. ") + ErrorToString());
        }

        if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) <=
            0) {
            throw std::runtime_error(std::string("ctx init failed. ") + ErrorToString());
        }

        const std::size_t sizeOfBuffer =
            4096;  // Поменял до стандартного размера страницы виртуальной памяти, который ОС обычно читает
        std::vector<unsigned char> inBuf(sizeOfBuffer);
        std::vector<unsigned char> outBuf(sizeOfBuffer + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), sizeOfBuffer);
            auto readBytes = inStream.gcount();

            if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
                throw std::runtime_error("input stream failed");
            }

            if (readBytes > 0) {
                if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(readBytes)) <=
                    0) {
                    throw std::runtime_error(std::string("cipher update failed. ") + ErrorToString());
                }

                outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
                if (!outStream)
                    throw std::runtime_error("output stream failed");
            }

            if (inStream.eof())
                break;
        }

        // Заканчиваем работу с cipher
        if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) <= 0) {
            throw std::runtime_error(std::string("cipher final failed. ") + ErrorToString());
        }

        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        if (!outStream)
            throw std::runtime_error("output stream failed");
    }
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ProcessFile(inStream, outStream, password, CryptMode::Encrypt);
    }
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ProcessFile(inStream, outStream, password, CryptMode::Decrypt);
    }
    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream)
            throw std::runtime_error("Invalid stream");

        MDCtxUPtr ctx(EVP_MD_CTX_new());
        if (!ctx)
            throw std::runtime_error("md ctx not created. " + ErrorToString());

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) <= 0)
            throw std::runtime_error(std::string("digest init failed. ") + ErrorToString());

        const std::size_t sizeOfBuffer = 4096;
        std::vector<unsigned char> inBuf(sizeOfBuffer);

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), sizeOfBuffer);
            auto readBytes = inStream.gcount();

            if (inStream.bad() || (inStream.fail() && !inStream.eof()))
                throw std::runtime_error{"Instream broken"};

            if (readBytes > 0) {
                if (EVP_DigestUpdate(ctx.get(), inBuf.data(), static_cast<std::size_t>(readBytes)) <= 0)
                    throw std::runtime_error(std::string("DigestUpdate failed") + ErrorToString());
            }

            if (inStream.eof())
                break;
        }

        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int s = 0;

        if (EVP_DigestFinal_ex(ctx.get(), md, &s) <= 0) {
            throw std::runtime_error(std::string("digest final failed. ") + ErrorToString());
        }

        std::stringstream ss;
        for (unsigned int i = 0; i < s; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
        }

        return ss.str();
    }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0)
            throw std::runtime_error{"Failed to create a key from password"};

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : m_pImpl(std::make_unique<CryptoGuardCtx::Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() {}

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    m_pImpl->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    m_pImpl->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return m_pImpl->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
