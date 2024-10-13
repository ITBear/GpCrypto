#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Blake2b.hpp>

#if defined(RELEASE_BUILD_STATIC)
#   define SODIUM_STATIC
#endif

GP_WARNING_PUSH()
//GP_WARNING_DISABLE_GCC(duplicated-branches)

#include <libsodium/sodium.h>

GP_WARNING_POP()

namespace GPlatform {

void    GpCryptoHash_Blake2b::S_256
(
    GpSpanByteR                 aData,
    std::optional<GpSpanByteR>  aKey,
    GpSpanByteRW                aResOut
)
{
    THROW_COND_GP
    (
        aResOut.Count() >= std::tuple_size<Res256T>::value,
        "aRes size too small"_sv
    );

    unsigned char*          resDataPtr  = aResOut.PtrAs<unsigned char*>();
    constexpr size_t        resDataSize = std::tuple_size<Res256T>::value;
    const unsigned char*    dataPtr     = (aData.PtrAs<const unsigned char*>());
    const size_t            dataSize    = aData.Count();
    const unsigned char*    keyPtr      = nullptr;
    size_t                  keySize     = 0;

    if (aKey.has_value())
    {
        GpSpanByteR& k = aKey.value();
        keyPtr  = k.PtrAs<const unsigned char*>();
        keySize = k.Count();
    }

    crypto_generichash_blake2b(resDataPtr, resDataSize, dataPtr, dataSize, keyPtr, keySize);
}

GpCryptoHash_Blake2b::Res256T   GpCryptoHash_Blake2b::S_256
(
    GpSpanByteR                 aData,
    std::optional<GpSpanByteR>  aKey
)
{
    Res256T         res;
    GpSpanByteRW    r{res};

    S_256(aData, aKey, r);

    return res;
}

}// namespace GPlatform
