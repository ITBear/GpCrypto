#pragma once

#include <GpCrypto/GpCryptoCore/Wallet/GpCryptoAddressFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoAddressGroup
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoAddressGroup)
    CLASS_DD(GpCryptoAddressGroup)

    using AddrListT = std::map<GpUUID, GpCryptoAddress::SP, std::less<>>;

public:
                                        GpCryptoAddressGroup    (const GpUUID&              aUID,
                                                                 GpCryptoKeyFactory::SP     aKeyFactory,
                                                                 GpCryptoAddressFactory::SP aAddrFactory) noexcept;
                                        ~GpCryptoAddressGroup   (void) noexcept;

    const GpUUID&                       UID                     (void) const noexcept {return iUID;}

    GpCryptoAddress::SP                 GenerateNext        (void);
    [[nodiscard]] bool                  Delete              (const GpUUID& aAddrUID);
    std::optional<GpCryptoAddress::SP>  Find                (const GpUUID& aAddrUID);
    GpCryptoAddress::C::Vec::SP         FindAllByName       (std::string_view aAddrName);
    const AddrListT&                    AddrsList           (void) const noexcept {return iAddrsList;}

private:
    const GpUUID                        iUID;
    GpCryptoKeyFactory::SP              iKeyFactory;
    GpCryptoAddressFactory::SP          iAddrFactory;
    AddrListT                           iAddrsList;
};

}// namespace GPlatform
