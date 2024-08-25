#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpCryptoKeyFactory_Ed25519_Rnd::GpCryptoKeyFactory_Ed25519_Rnd (void) noexcept
{
}

GpCryptoKeyFactory_Ed25519_Rnd::~GpCryptoKeyFactory_Ed25519_Rnd (void) noexcept
{
}

GpCryptoKeyPair::CSP    GpCryptoKeyFactory_Ed25519_Rnd::Generate (void)
{
    GpSecureStorage::SP privateBytes = MakeSP<GpSecureStorage>();
    GpBytesArray        publicBytes;

    {
        privateBytes.V().Resize(size_t(crypto_sign_ed25519_SECRETKEYBYTES));
        publicBytes.resize(size_t(crypto_sign_PUBLICKEYBYTES));

        GpSecureStorageViewRW   privateBytesView    = privateBytes.V().ViewRW();
        GpSpanByteRW            privateBytesPtr     = privateBytesView.RW();
        GpSpanByteRW            publicBytesPtr      = GpSpanByteRW(publicBytes);

        const auto res = crypto_sign_ed25519_keypair
        (
            publicBytesPtr.PtrAs<unsigned char*>(),
            privateBytesPtr.PtrAs<unsigned char*>()
        );

        if (res != 0)
        {
            THROW_GP("crypto_sign_ed25519_keypair return error"_sv);
        }
    }

    return MakeSP<GpCryptoKeyPair_Ed25519>(privateBytes, std::move(publicBytes));
}
/*
void    GpCryptoKeyFactory_Ed25519_Rnd::Serialize (GpByteWriter& aWriter) const
{
    aWriter.BytesWithLen("GpCryptoKeyFactory_Ed25519_Rnd"_sv);
}

void    GpCryptoKeyFactory_Ed25519_Rnd::Deserialize (GpByteReader& aReader)
{
    THROW_COND_GP
    (
        aReader.BytesWithLen() == "GpCryptoKeyFactory_Ed25519_Rnd"_sv,
        "Wrong data"_sv
    );
}
*/
}// namespace GPlatform
