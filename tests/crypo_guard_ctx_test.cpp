#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string_view>

// В git шаблоне очепятка crypo_guard_ctx_test.cpp
namespace gtest::crypo_guard_ctx {

constexpr std::string_view kText = "Hello OpenSSL crypto world!";
constexpr std::string_view kPassword = "SuperSecretPassword";
constexpr std::string_view kKnownSHA256Hash = "c2b95cb70f5d88a90082658033f32a6b1070a48466ee3775a1c1a1041171e397";
// Через sha256sum взял хэш от "Roman Konstantinovich"

using namespace CryptoGuard;

TEST(CryptoGuardCtxImpl, EncryptDifferentPasswordDifferentResults) {
    std::stringstream ss, outss, diffOutss;

    ss << kText << std::endl;

    CryptoGuardCtx ctx;

    ctx.EncryptFile(ss, outss, kPassword);
    ss.clear();
    ss.seekg(0);
    ctx.EncryptFile(ss, diffOutss, "diffPassword");

    EXPECT_FALSE(outss.str().empty());
    EXPECT_FALSE(diffOutss.str().empty());

    EXPECT_NE(outss.str(), diffOutss.str());

    EXPECT_EQ(outss.str().size() % 16, 0);
}

TEST(CryptoGuardCtxImpl, EncryptChangesData) {
    std::stringstream ss, outss;
    ss << kText;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(ss, outss, kPassword);

    EXPECT_NE(outss.str(), std::string(kText));
}

TEST(CryptoGuardCtxImpl, EncryptBadBitInputStream) {
    std::stringstream ss, outss;
    ss << kText;
    ss.setstate(std::ios::badbit);

    CryptoGuardCtx ctx;

    ASSERT_THROW(ctx.EncryptFile(ss, outss, kPassword), std::runtime_error);
}

TEST(CryptoGuardCtxImpl, DecryptRound) {
    std::stringstream ss, encrypted, decrypted;
    ss << kText;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(ss, encrypted, kPassword);

    EXPECT_FALSE(encrypted.str().empty());
    encrypted.seekg(0);

    ctx.DecryptFile(encrypted, decrypted, kPassword);

    EXPECT_EQ(decrypted.str(), kText);
}

TEST(CryptoGuardCtxImpl, DecryptWithWrongPassword) {
    std::stringstream ss, encrypted, decrypted;
    ss << kText;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(ss, encrypted, kPassword);

    EXPECT_FALSE(encrypted.str().empty());
    encrypted.seekg(0);

    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, "WrongPassword"), std::runtime_error);
}

TEST(CryptoGuardCtxImpl, DecryptLongText) {
    std::string longText(100000, 'R');
    std::stringstream ss, encrypted, decrypted;
    ss << longText;

    CryptoGuardCtx ctx;
    ctx.EncryptFile(ss, encrypted, kPassword);
    encrypted.seekg(0);

    ctx.DecryptFile(encrypted, decrypted, kPassword);

    EXPECT_EQ(decrypted.str(), longText);
}

TEST(CryptoGuardCtxImpl, CalculateChecksumTwoDiffStreamsSameResult) {
    std::stringstream ss, diffss;
    ss << kText;
    diffss << kText;

    CryptoGuardCtx ctx;

    EXPECT_EQ(ctx.CalculateChecksum(ss), ctx.CalculateChecksum(diffss));
}

TEST(CryptoGuardCtxImpl, CalculateChecksumThrowsOnBadInput) {
    std::stringstream ss;
    ss << kText;
    ss.setstate(std::ios::badbit);

    CryptoGuardCtx ctx;

    ASSERT_THROW(ctx.CalculateChecksum(ss), std::runtime_error);
}

TEST(CryptoGuardCtxImpl, CalculateChecksumKnownValue) {
    std::stringstream ss;
    ss << "Roman Konstantinovich";

    CryptoGuardCtx ctx;
    EXPECT_EQ(ctx.CalculateChecksum(ss), kKnownSHA256Hash);
}
}  // namespace gtest::crypo_guard_ctx
