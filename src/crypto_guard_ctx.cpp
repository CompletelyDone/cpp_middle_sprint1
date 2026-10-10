#include "crypto_guard_ctx.h"
#include <array>
#include <cstddef>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::string ErrorToString() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}
}  // namespace

namespace CryptoGuard {

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
    using CipherCtxUPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPCtxDeleter>;

    Impl() { OpenSSL_add_all_algorithms(); };
    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream || !outStream)
            throw std::runtime_error("Invalid stream");

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        CipherCtxUPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw std::runtime_error(std::string("ctx not created. ") + ErrorToString());
        }

        if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) <=
            0) {
            throw std::runtime_error(std::string("ctx init failed. ") + ErrorToString());
        }

        const std::size_t sizeOfBuffer = 16;
        std::vector<unsigned char> inBuf(sizeOfBuffer);
        std::vector<unsigned char> outBuf(sizeOfBuffer + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), sizeOfBuffer);
            auto readBytes = inStream.gcount();

            if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
                throw std::runtime_error("stream looser");
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
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksum(std::iostream &inStream);

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
