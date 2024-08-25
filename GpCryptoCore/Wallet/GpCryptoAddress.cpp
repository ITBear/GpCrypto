#include <GpCrypto/GpCryptoCore/Wallet/GpCryptoAddress.hpp>

namespace GPlatform {

GpCryptoAddress::GpCryptoAddress
(
    const GpUUID&           aUID,
    GpCryptoKeyPair::CSP    aKeyPair
) noexcept:
iUID    {aUID},
iKeyPair{std::move(aKeyPair)}
{
}

GpCryptoAddress::~GpCryptoAddress (void) noexcept
{
    iKeyPair.Clear();
}

GpBytesArray    GpCryptoAddress::SignData (GpSpanByteR aData) const
{
    return iKeyPair.V().Sign(aData);
}

bool    GpCryptoAddress::VerifySign
(
    GpSpanByteR aData,
    GpSpanByteR aSign
) const
{
    return iKeyPair.V().VerifySign(aData, aSign);
}

void    GpCryptoAddress::RecalcAddrStr (void)
{
    auto res = OnRecalcAddrStr();

    iAddr       = std::get<0>(res);
    iAddrStr    = std::get<1>(res);
}

}// namespace GPlatform
