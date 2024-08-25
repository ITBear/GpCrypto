#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDKeyGen.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoHDKeyGen_Ed25519.hpp>

namespace GPlatform {

GpCryptoHDKeyStorage::SP    GpCryptoHDKeyGen::SMasterKeyPairFromSeed
(
    GpSpanByteR         aSeed,
    const SchemeTypeTE  aSchemeType
)
{
    switch (aSchemeType)
    {
        case SchemeTypeTE::SLIP10_ED25519:
        {
            return GpCryptoHDKeyGen_Ed25519::SMasterKeyPairFromSeed(aSeed);
        } break;
        default:
        {
            THROW_GP("Unknown HD scheme type "_sv + SchemeTypeT::SToString(aSchemeType));
        }
    }
}

GpCryptoHDKeyStorage::SP    GpCryptoHDKeyGen::SChildKeyPair
(
    const GpCryptoHDKeyStorage& aParentHDKeyStorage,
    const size_t                aChildId
)
{
    switch (aParentHDKeyStorage.SchemeType())
    {
        case SchemeTypeTE::SLIP10_ED25519:
        {
            return GpCryptoHDKeyGen_Ed25519::SChildKeyPair(aParentHDKeyStorage, aChildId);
        } break;
        default:
        {
            THROW_GP("Unknown HD scheme type "_sv + SchemeTypeT::SToString(aParentHDKeyStorage.SchemeType()));
        }
    }
}

}// namespace GPlatform
