#pragma once

#include <GpCrypto/GpCryptoWallet/GpCryptoWalletAddressFactory.hpp>

namespace GPlatform {

class GP_CRYPTO_WALLET_API GpCryptoWalletAddressGroup
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoWalletAddressGroup)
    CLASS_DD(GpCryptoWalletAddressGroup)

    using AddrListT = std::map<GpUUID, GpCryptoWalletAddress::SP, std::less<>>;

public:
                                                GpCryptoWalletAddressGroup  (const GpUUID&                      aUID,
                                                                             GpCryptoSignKeyFactory::SP         aKeyFactory,
                                                                             GpCryptoWalletAddressFactory::SP   aAddrFactory) noexcept;
                                                ~GpCryptoWalletAddressGroup (void) noexcept;

    const GpUUID&                               UID                         (void) const noexcept {return iUID;}

    GpCryptoWalletAddress::SP                   GenerateNext                (void);
    [[nodiscard]] bool                          Delete                      (const GpUUID& aAddrUID);
    std::optional<GpCryptoWalletAddress::SP>    Find                        (const GpUUID& aAddrUID);
    GpCryptoWalletAddress::C::Vec::SP           FindAllByName               (std::string_view aAddrName);
    const AddrListT&                            AddrsList                   (void) const noexcept {return iAddrsList;}

private:
    const GpUUID                                iUID;
    GpCryptoSignKeyFactory::SP                  iKeyFactory;
    GpCryptoWalletAddressFactory::SP            iAddrFactory;
    AddrListT                                   iAddrsList;
};

}// namespace GPlatform
