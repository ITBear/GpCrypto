#pragma once

#include <GpCrypto/GpCryptoCore/Wallet/GpCryptoAddress.hpp>
#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyFactory.hpp>

namespace GPlatform {

class GpCryptoAddressFactory
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoAddressFactory)
    CLASS_DD(GpCryptoAddressFactory)

protected:
                                    GpCryptoAddressFactory  (void) noexcept {}

public:
    virtual                         ~GpCryptoAddressFactory (void) noexcept {}

    virtual GpCryptoAddress::SP     Generate                (GpCryptoKeyFactory& aKeyFactory) = 0;
};

}// namespace GPlatform
