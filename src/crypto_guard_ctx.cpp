#include "crypto_guard_ctx.h"
#include <memory>

namespace CryptoGuard {

struct CryptoGuardCtx::Impl {
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);
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
