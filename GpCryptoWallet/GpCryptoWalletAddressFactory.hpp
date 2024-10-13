#pragma once

#include <GpCrypto/GpCryptoWallet/GpCryptoWalletAddress.hpp>
#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyFactory.hpp>

namespace GPlatform {

class GpCryptoWalletAddressFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoWalletAddressFactory)
    CLASS_DD(GpCryptoWalletAddressFactory)

protected:
                                        GpCryptoWalletAddressFactory    (void) noexcept {}

public:
    virtual                             ~GpCryptoWalletAddressFactory   (void) noexcept {}

    virtual GpCryptoWalletAddress::SP   Generate                        (GpCryptoSignKeyFactory& aKeyFactory) = 0;
};

}// namespace GPlatform
