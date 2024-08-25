#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

const std::string_view  GpCryptoKeyPair_Ed25519::sPrivateKeyPrefix  = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"_sv;
const std::string_view  GpCryptoKeyPair_Ed25519::sPublicKeyPrefix   = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"_sv;

GpCryptoKeyPair_Ed25519::GpCryptoKeyPair_Ed25519
(
    GpSecureStorage::CSP    aPrivateKey,
    GpBytesArray&&          aPublicKey
) noexcept:
GpCryptoKeyPair
{
    GpCryptoKeyType::ED_25519,
    std::move(aPrivateKey),
    std::move(aPublicKey)
}
{
}

GpCryptoKeyPair_Ed25519::~GpCryptoKeyPair_Ed25519 (void) noexcept
{
}

GpBytesArray    GpCryptoKeyPair_Ed25519::Sign (GpSpanByteR aData) const
{
    return SSign(aData, PrivateKey().V());
}

bool    GpCryptoKeyPair_Ed25519::VerifySign
(
    GpSpanByteR aData,
    GpSpanByteR aSign
) const
{
    return SVerifySign(aData, aSign, PublicKey());
}

GpBytesArray    GpCryptoKeyPair_Ed25519::SSign
(
    GpSpanByteR             aData,
    const GpSecureStorage&  aPrivateKey
)
{
    THROW_COND_GP
    (
        aData.Count() > 0,
        "Data is empty"_sv
    );

    GpSecureStorageViewR    privateKeyViewR = aPrivateKey.ViewR();
    GpSpanByteR             privateKey      = privateKeyViewR.R();

    THROW_COND_GP
    (
        privateKey.SizeInBytes() == crypto_sign_ed25519_BYTES,
        "Wrong private key size"_sv
    );

    GpBytesArray sign;
    sign.resize(size_t(crypto_sign_ed25519_BYTES));

    THROW_COND_GP
    (
        crypto_sign_ed25519_detached
        (
            reinterpret_cast<unsigned char*>(std::data(sign)),
            nullptr,
            aData.PtrAs<const unsigned char*>(),
            aData.Count(),
            privateKey.PtrAs<const unsigned char*>()
        ) == 0,
        "crypto_sign_ed25519_detached return error"_sv
    );

    return sign;
}

bool    GpCryptoKeyPair_Ed25519::SVerifySign
(
    GpSpanByteR aData,
    GpSpanByteR aSign,
    GpSpanByteR aPublicKey
)
{
    THROW_COND_GP
    (
        aSign.Count() >= size_t(crypto_sign_ed25519_BYTES),
        "aSign size too small"_sv
    );

    THROW_COND_GP
    (
        aPublicKey.Count() >= size_t(crypto_sign_ed25519_PUBLICKEYBYTES),
        "aPublicKey size too small"_sv
    );

    const auto res = crypto_sign_ed25519_verify_detached
    (
        aSign.PtrAs<const unsigned char*>(),
        aData.PtrAs<const unsigned char*>(),
        aData.Count(),
        aPublicKey.PtrAs<const unsigned char*>()
    );

    if (res == 0)
    {
        return true;
    } else
    {
        return false;
    }
}

GpSpanByteR GpCryptoKeyPair_Ed25519::PrivateKeyPrefix (void) const noexcept
{
    return sPrivateKeyPrefix;
}

GpSpanByteR GpCryptoKeyPair_Ed25519::PublicKeyPrefix (void) const noexcept
{
    return sPublicKeyPrefix;
}

}// namespace GPlatform
