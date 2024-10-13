#pragma once

#include <GpCrypto/GpCryptoWallet/GpCryptoWalletAddressGroup.hpp>

namespace GPlatform {

class GP_CRYPTO_WALLET_API GpCryptoWallet
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoWallet)
    CLASS_DD(GpCryptoWallet)

    using HDAddrGroupsT = GpCryptoWalletAddressGroup::C::MapUuid::SP;

public:
                                                    GpCryptoWallet      (GpCryptoWalletAddressFactory::SP aAddrFactory) noexcept;
    virtual                                         ~GpCryptoWallet     (void) noexcept;

    GpCryptoWalletAddress::SP                       GenerateNextRndAddr (void);
    GpCryptoWalletAddress::SP                       GenerateNextHDAddr  (const GpUUID& aGroupUID);

    std::optional<GpCryptoWalletAddress::SP>        FindAddr            (const GpUUID& aAddrUID);
    GpCryptoWalletAddress::C::Vec::SP               FindAddrAllByName   (std::string_view aAddrName);
    [[nodiscard]] bool                              DeleteAddr          (const GpUUID& aAddrUID);

    GpCryptoWalletAddressGroup::SP                  AddHDGroup          (GpSpanCharR    aMnemonic,
                                                                         GpSpanCharR    aPassword);
    std::optional<GpCryptoWalletAddressGroup::SP>   FindHDGroup         (const GpUUID& aGroupUID);
    [[nodiscard]] bool                              DeleteHDGroup       (const GpUUID& aGroupUID);

private:
    GpCryptoWalletAddressGroup&                     _RndAddrGroup       (void);

private:
    GpCryptoWalletAddressFactory::SP                iAddrFactory;
    GpCryptoWalletAddressGroup::SP                  iRndAddrGroup;
    HDAddrGroupsT                                   iHDAddrGroups;
};

}// namespace GPlatform
