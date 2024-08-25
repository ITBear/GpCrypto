#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Import.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpCryptoKeyFactory_Ed25519_Import::GpCryptoKeyFactory_Ed25519_Import (GpSecureStorage::CSP aSeed) noexcept:
iSeed(std::move(aSeed))
{
}

GpCryptoKeyFactory_Ed25519_Import::~GpCryptoKeyFactory_Ed25519_Import (void) noexcept
{
}

GpCryptoKeyPair::CSP    GpCryptoKeyFactory_Ed25519_Import::Generate (void)
{
    THROW_COND_GP
    (
        iSeed.V().Size() == size_t(crypto_sign_ed25519_SEEDBYTES),
        "Wrong seed size"_sv
    );

    GpSecureStorage::SP privateBytes = MakeSP<GpSecureStorage>();
    GpBytesArray        publicBytes;

    privateBytes.V().Resize(size_t(crypto_sign_ed25519_SECRETKEYBYTES));
    publicBytes.resize(size_t(crypto_sign_ed25519_PUBLICKEYBYTES));

    GpSpanByteRW publicBytesPtr = GpSpanByteRW(publicBytes);

    const auto res = crypto_sign_ed25519_seed_keypair
    (
        publicBytesPtr.PtrAs<unsigned char*>(),
        privateBytes.V().ViewRW().RW().PtrAs<unsigned char*>(),
        iSeed.V().ViewR().R().PtrAs<const unsigned char*>()
    );

    if (res != 0)
    {
        THROW_GP("crypto_sign_ed25519_keypair return error"_sv);
    }

    return MakeCSP<GpCryptoKeyPair_Ed25519>(privateBytes, std::move(publicBytes));
}

/*void  GpCryptoKeyFactory_Ed25519_Import::Serialize (GpByteWriter& aWriter) const
{
    aWriter.BytesWithLen("GpCryptoKeyFactory_Ed25519_Import"_sv);
}

void    GpCryptoKeyFactory_Ed25519_Import::Deserialize (GpByteReader& aReader)
{
    THROW_COND_GP
    (
        aReader.BytesWithLen() == "GpCryptoKeyFactory_Ed25519_Import"_sv,
        "Wrong data"_sv
    );
}*/

}// namespace GPlatform
