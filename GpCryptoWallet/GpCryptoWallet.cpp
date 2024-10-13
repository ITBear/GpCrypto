#include <GpCrypto/GpCryptoWallet/GpCryptoWallet.hpp>
#include <GpCrypto/GpCryptoWallet/GpCryptoWalletUtils.hpp>
#include <GpCrypto/GpCryptoCore/Keys/Curve25519/GpCryptoKeyFactory_Ed25519_Rnd.hpp>

namespace GPlatform {

GpCryptoWallet::GpCryptoWallet (GpCryptoWalletAddressFactory::SP aAddrFactory) noexcept:
iAddrFactory{std::move(aAddrFactory)}
{
}

GpCryptoWallet::~GpCryptoWallet (void) noexcept
{
}

GpCryptoWalletAddress::SP   GpCryptoWallet::GenerateNextRndAddr (void)
{
    return _RndAddrGroup().GenerateNext();
}

GpCryptoWalletAddress::SP   GpCryptoWallet::GenerateNextHDAddr (const GpUUID& aGroupUID)
{
    auto findGroupRes = FindHDGroup(aGroupUID);

    THROW_COND_GP
    (
        findGroupRes.has_value(),
        [&](){return "Group with UID '"_sv + aGroupUID.ToString() + "' not found"_sv;}
    );

    return findGroupRes.value().V().GenerateNext();
}

std::optional<GpCryptoWalletAddress::SP>    GpCryptoWallet::FindAddr (const GpUUID& aAddrUID)
{
    //Try to search in "rnd" group
    {
        auto res = _RndAddrGroup().Find(aAddrUID);

        if (res.has_value())
        {
            return res.value();
        }
    }

    //Try to search in "HD" groups
    for (auto& iter: iHDAddrGroups)
    {
        auto& groupHD = iter.second.V();

        auto res = groupHD.Find(aAddrUID);

        if (res.has_value())
        {
            return res.value();
        }
    }

    return std::nullopt;
}

GpCryptoWalletAddress::C::Vec::SP   GpCryptoWallet::FindAddrAllByName (std::string_view aAddrName)
{
    GpCryptoWalletAddress::C::Vec::SP res;

    //Try to search in "rnd" group
    {
        auto r = _RndAddrGroup().FindAllByName(aAddrName);
        res.insert
        (
            res.end(),
            std::make_move_iterator(r.begin()),
            std::make_move_iterator(r.end())
        );
    }

    //Try to search in "HD" groups
    for (auto& iter: iHDAddrGroups)
    {
        auto& groupHD = iter.second.V();

        auto r = groupHD.FindAllByName(aAddrName);

        res.insert
        (
            res.end(),
            std::make_move_iterator(r.begin()),
            std::make_move_iterator(r.end())
        );
    }

    return res;
}

bool    GpCryptoWallet::DeleteAddr (const GpUUID& aAddrUID)
{
    if (_RndAddrGroup().Delete(aAddrUID))
    {
        return true;
    }

    for (auto& iter: iHDAddrGroups)
    {
        auto& g = iter.second.V();

        if (g.Delete(aAddrUID))
        {
            return true;
        }
    }

    return false;
}

GpCryptoWalletAddressGroup::SP  GpCryptoWallet::AddHDGroup
(
    GpSpanCharR aMnemonic,
    GpSpanCharR aPassword
)
{
    GpCryptoSignKeyFactory::SP      hdKeyFactory    = GpCryptoWalletUtils::SNewHDKeyFactoryMnemonic(aMnemonic, aPassword);
    GpCryptoWalletAddressGroup::SP  addrGroup       = MakeSP<GpCryptoWalletAddressGroup>(GpUUID::SGenRandomV4(), hdKeyFactory, iAddrFactory);

    iHDAddrGroups.insert({addrGroup.V().UID(), addrGroup});

    return addrGroup;
}

std::optional<GpCryptoWalletAddressGroup::SP>   GpCryptoWallet::FindHDGroup (const GpUUID& aGroupUID)
{
    //Try to search in "HD" groups
    auto iter = iHDAddrGroups.find(aGroupUID);

    if (iter != iHDAddrGroups.end())
    {
        return iter->second;
    } else
    {
        return std::nullopt;
    }
}

bool    GpCryptoWallet::DeleteHDGroup (const GpUUID& aGroupUID)
{
    //Try to search in "HD" groups
    auto iter = iHDAddrGroups.find(aGroupUID);

    if (iter != iHDAddrGroups.end())
    {
        iHDAddrGroups.erase(iter);
        return true;
    } else
    {
        return false;
    }
}

GpCryptoWalletAddressGroup& GpCryptoWallet::_RndAddrGroup (void)
{
    if (iRndAddrGroup.IsNULL())
    {
        iRndAddrGroup = MakeSP<GpCryptoWalletAddressGroup>
        (
            GpUUID::CE_FromString("291000ae-897b-4566-8cfd-bfaf897989f5"_sv),
            MakeSP<GpCryptoKeyFactory_Ed25519_Rnd>(),
            iAddrFactory
        );
    }

    return iRndAddrGroup.V();
}

}// namespace GPlatform
