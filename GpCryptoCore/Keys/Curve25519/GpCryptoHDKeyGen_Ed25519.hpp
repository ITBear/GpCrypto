#pragma once

#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDKeyStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoHDKeyGen_Ed25519
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoHDKeyGen_Ed25519)

public:
    static GpCryptoHDKeyStorage::SP     SMasterKeyPairFromSeed  (GpSpanByteR    aSeed);
    static GpCryptoHDKeyStorage::SP     SChildKeyPair           (const GpCryptoHDKeyStorage&    aParentHDKeyStorage,
                                                                 size_t                         aChildId);
};

}// namespace GPlatform
