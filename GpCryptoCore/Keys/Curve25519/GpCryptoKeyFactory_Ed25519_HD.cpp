#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyFactory_Ed25519_HD.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyPair_Ed25519.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Import.hpp>
#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDKeyGen.hpp>

GP_WARNING_PUSH()
GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

GpCryptoKeyFactory_Ed25519_HD::GpCryptoKeyFactory_Ed25519_HD (GpCryptoHDKeyStorage::CSP aParentHDKeyStorage) noexcept:
iParentHDKeyStorage{std::move(aParentHDKeyStorage)}
{
}

GpCryptoKeyFactory_Ed25519_HD::~GpCryptoKeyFactory_Ed25519_HD (void) noexcept
{
}

GpCryptoKeyPair::CSP    GpCryptoKeyFactory_Ed25519_HD::Generate (void)
{
    THROW_COND_GP
    (
        iParentHDKeyStorage.V().SchemeType() == GpCryptoHDSchemeType::SLIP10_ED25519,
        "HD scheme type must be SLIP10_ED25519"_sv
    );

    GpCryptoHDKeyStorage::SP keyStorageHD = GpCryptoHDKeyGen::SChildKeyPair(iParentHDKeyStorage.V(), iChildNumber);
    iChildNumber++;

    GpCryptoKeyFactory_Ed25519_Import factory(keyStorageHD.V().KeyData());

    return factory.Generate();
}

/*void  GpCryptoKeyFactory_Ed25519_HD::Serialize (GpByteWriter& aWriter) const
{
    //iParentHDKeyStorage
    {
        //SchemeType
        aWriter.BytesWithLen(GpCryptoHDSchemeType::SToString(iParentHDKeyStorage.SchemeType()));

        //ChainCode
        aWriter.BytesWithLen(iParentHDKeyStorage.ChainCode().ViewR().R());

        //KeyData
        aWriter.BytesWithLen(iParentHDKeyStorage.KeyData().ViewR().R());
    }

    //iChildNumber
    aWriter.CompactUInt32(iChildNumber.As<s_int_32>());
}

void    GpCryptoKeyFactory_Ed25519_HD::Deserialize (GpByteReader& aReader)
{
    //iParentHDKeyStorage
    {
        //SchemeType
        THROW_COND_GP
        (
            aReader.BytesWithLen() == GpCryptoHDSchemeType::SToString(iParentHDKeyStorage.SchemeType()),
            "Wrong SchemeType"_sv
        );

        //ChainCode
        iParentHDKeyStorage->ChainCode().ViewRW().RW().CopyFrom(aReader.BytesWithLen());

        //KeyData
        iParentHDKeyStorage->KeyData().ViewRW().RW().CopyFrom(aReader.BytesWithLen());
    }

    //iChildNumber
    iChildNumber = size_t::SMake(aReader.CompactSInt32());
}*/

}// namespace GPlatform
