#pragma once

#include <GpCrypto/GpCryptoCore/GpCryptoCore_global.hpp>
#include <GpCrypto/GpCryptoCore/Keys/GpCryptoKeyPair.hpp>
#include <GpCore2/GpUtils/Types/UIDs/GpUUID.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoAddress
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoAddress)
    CLASS_DD(GpCryptoAddress)

public:
                            GpCryptoAddress     (const GpUUID&          aUID,
                                                 GpCryptoKeyPair::CSP   aKeyPair) noexcept;

    virtual                 ~GpCryptoAddress    (void) noexcept;

    const GpUUID&           UID                 (void) const noexcept {return iUID;}
    const GpCryptoKeyPair&  KeyPair             (void) const noexcept {return iKeyPair.V();}
    std::string_view        Name                (void) const noexcept {return iName;}
    void                    SetName             (std::string_view aName)  {iName = aName;}
    GpSpanByteR             Addr                (void) const noexcept {return iAddr;}
    std::string_view        AddrStr             (void) const noexcept {return iAddrStr;}

    GpBytesArray            SignData            (GpSpanByteR aData) const;
    bool                    VerifySign          (GpSpanByteR    aData,
                                                 GpSpanByteR    aSign) const;

    void                    RecalcAddrStr       (void);

protected:
    virtual std::tuple<GpBytesArray, std::string>
                            OnRecalcAddrStr     (void) const = 0;

private:
    const GpUUID            iUID;
    GpCryptoKeyPair::CSP    iKeyPair;
    std::string             iName;
    GpBytesArray            iAddr;
    std::string             iAddrStr;
};

}// namespace GPlatform
