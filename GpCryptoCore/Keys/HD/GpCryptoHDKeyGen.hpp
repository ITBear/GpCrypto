#pragma once

#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDKeyStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHDKeyGen
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHDKeyGen)

    using SchemeTypeT   = GpCryptoHDSchemeType;
    using SchemeTypeTE  = SchemeTypeT::EnumT;

public:
    static GpCryptoHDKeyStorage::SP     SMasterKeyPairFromSeed  (GpSpanByteR    aSeed,
                                                                 SchemeTypeTE   aSchemeType);

    static GpCryptoHDKeyStorage::SP     SChildKeyPair           (const GpCryptoHDKeyStorage&    aParentHDKeyStorage,
                                                                 size_t                         aChildId);
};

}// namespace GPlatform
