#include <GpCrypto/GpCryptoWallet/GpCryptoWalletAddressGroup.hpp>
#include <GpCrypto/GpCryptoWallet/GpCryptoWalletUtils.hpp>

namespace GPlatform {

GpCryptoWalletAddressGroup::GpCryptoWalletAddressGroup
(
    const GpUUID&                       aUID,
    GpCryptoSignKeyFactory::SP          aKeyFactory,
    GpCryptoWalletAddressFactory::SP    aAddrFactory
) noexcept:
iUID        {aUID},
iKeyFactory {std::move(aKeyFactory)},
iAddrFactory{std::move(aAddrFactory)}
{
}

GpCryptoWalletAddressGroup::~GpCryptoWalletAddressGroup (void) noexcept
{
}

GpCryptoWalletAddress::SP   GpCryptoWalletAddressGroup::GenerateNext (void)
{
    GpCryptoWalletAddress::SP addr = GpCryptoWalletUtils::SNewAddrFromFactory(iAddrFactory.V(), iKeyFactory.V());

    THROW_COND_GP
    (
        iAddrsList.try_emplace(addr.V().UID(), addr).second,
        "Addr UID is not unique"_sv
    );

    return addr;
}

bool    GpCryptoWalletAddressGroup::Delete (const GpUUID& aAddrUID)
{
    auto iter = iAddrsList.find(aAddrUID);

    if (iter == iAddrsList.end())
    {
        return false;
    }

    iAddrsList.erase(iter);

    return true;
}

std::optional<GpCryptoWalletAddress::SP>    GpCryptoWalletAddressGroup::Find (const GpUUID& aAddrUID)
{
    auto iter = iAddrsList.find(aAddrUID);

    if (iter == iAddrsList.end())
    {
        return std::nullopt;
    }

    return iter->second;
}

GpCryptoWalletAddress::C::Vec::SP   GpCryptoWalletAddressGroup::FindAllByName (std::string_view aAddrName)
{
    GpCryptoWalletAddress::C::Vec::SP res;

    for (auto& addr: iAddrsList)
    {
        if (addr.second.V().Name() == aAddrName)
        {
            res.emplace_back(addr.second);
        }
    }

    return res;
}

}// namespace GPlatform
