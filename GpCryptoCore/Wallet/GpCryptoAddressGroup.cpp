#include <GpCrypto/GpCryptoCore/Wallet/GpCryptoAddressGroup.hpp>
#include <GpCrypto/GpCryptoCore/Wallet/GpCryptoWalletUtils.hpp>

namespace GPlatform {

GpCryptoAddressGroup::GpCryptoAddressGroup
(
    const GpUUID&               aUID,
    GpCryptoKeyFactory::SP      aKeyFactory,
    GpCryptoAddressFactory::SP  aAddrFactory
) noexcept:
iUID        {aUID},
iKeyFactory {std::move(aKeyFactory)},
iAddrFactory{std::move(aAddrFactory)}
{
}

GpCryptoAddressGroup::~GpCryptoAddressGroup (void) noexcept
{
}

GpCryptoAddress::SP GpCryptoAddressGroup::GenerateNext (void)
{
    GpCryptoAddress::SP addr = GpCryptoWalletUtils::SNewAddrFromFactory(iAddrFactory.V(), iKeyFactory.V());

    THROW_COND_GP
    (
        iAddrsList.try_emplace(addr.V().UID(), addr).second,
        "Addr UID is not unique"_sv
    );

    return addr;
}

bool    GpCryptoAddressGroup::Delete (const GpUUID& aAddrUID)
{
    auto iter = iAddrsList.find(aAddrUID);

    if (iter == iAddrsList.end())
    {
        return false;
    }

    iAddrsList.erase(iter);

    return true;
}

std::optional<GpCryptoAddress::SP>  GpCryptoAddressGroup::Find (const GpUUID& aAddrUID)
{
    auto iter = iAddrsList.find(aAddrUID);

    if (iter == iAddrsList.end())
    {
        return std::nullopt;
    }

    return iter->second;
}

GpCryptoAddress::C::Vec::SP GpCryptoAddressGroup::FindAllByName (std::string_view aAddrName)
{
    GpCryptoAddress::C::Vec::SP res;

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
