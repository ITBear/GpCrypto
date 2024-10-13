#include <GpCrypto/GpCryptoWallet/GpCryptoWalletAddress.hpp>

namespace GPlatform {

GpCryptoWalletAddress::GpCryptoWalletAddress
(
    const GpUUID&               aUID,
    GpCryptoSignKeyPair::CSP    aKeyPair
) noexcept:
iUID    {aUID},
iKeyPair{std::move(aKeyPair)}
{
}

GpCryptoWalletAddress::~GpCryptoWalletAddress (void) noexcept
{
    iKeyPair.Clear();
}

GpBytesArray    GpCryptoWalletAddress::SignData (GpSpanByteR aData) const
{
    return iKeyPair.V().Sign(aData);
}

bool    GpCryptoWalletAddress::VerifySign
(
    GpSpanByteR aData,
    GpSpanByteR aSign
) const
{
    return iKeyPair.V().VerifySign(aData, aSign);
}

void    GpCryptoWalletAddress::RecalcAddrStr (void)
{
    auto res = OnRecalcAddrStr();

    iAddr       = std::get<0>(res);
    iAddrStr    = std::get<1>(res);
}

}// namespace GPlatform
