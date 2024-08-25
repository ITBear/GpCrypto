#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Ripemd160.hpp>
#include <GpCrypto/GpCryptoCore/ExtSources/ripemd160.hpp>

namespace GPlatform {

void    GpCryptoHash_Ripemd160::S_H
(
    GpSpanByteR     aData,
    GpSpanByteRW    aResOut
)
{
    Ripemd160(aData, aResOut);
}

GpCryptoHash_Ripemd160::Res160T GpCryptoHash_Ripemd160::S_H (GpSpanByteR aData)
{
    Res160T res;
    GpSpanByteRW r(res);
    S_H(aData, r);
    return res;
}

}// namespace GPlatform
