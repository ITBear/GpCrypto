#pragma once

#include <GpCrypto/GpCryptoWallet/GpCryptoWallet_global.hpp>
#include <GpCrypto/GpCryptoCore/Keys/GpCryptoSignKeyPair.hpp>
#include <GpCore2/GpUtils/Types/UIDs/GpUUID.hpp>

namespace GPlatform {

class GP_CRYPTO_WALLET_API GpCryptoWalletAddress
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoWalletAddress)
    CLASS_DD(GpCryptoWalletAddress)

public:
                                GpCryptoWalletAddress   (const GpUUID&              aUID,
                                                         GpCryptoSignKeyPair::CSP   aKeyPair) noexcept;

    virtual                     ~GpCryptoWalletAddress  (void) noexcept;

    const GpUUID&               UID                     (void) const noexcept {return iUID;}
    const GpCryptoSignKeyPair&  KeyPair                 (void) const noexcept {return iKeyPair.V();}
    std::string_view            Name                    (void) const noexcept {return iName;}
    void                        SetName                 (std::string_view aName)  {iName = aName;}
    GpSpanByteR                 Addr                    (void) const noexcept {return iAddr;}
    std::string_view            AddrStr                 (void) const noexcept {return iAddrStr;}

    GpBytesArray                SignData                (GpSpanByteR aData) const;
    bool                        VerifySign              (GpSpanByteR    aData,
                                                         GpSpanByteR    aSign) const;

    void                        RecalcAddrStr           (void);

protected:
    virtual std::tuple<GpBytesArray, std::string>
                                OnRecalcAddrStr         (void) const = 0;

private:
    const GpUUID                iUID;
    GpCryptoSignKeyPair::CSP    iKeyPair;
    std::string                 iName;
    GpBytesArray                iAddr;
    std::string                 iAddrStr;
};

}// namespace GPlatform
