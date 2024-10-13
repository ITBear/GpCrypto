#pragma once

#include <GpCrypto/GpCryptoWallet/GpCryptoWalletAddressFactory.hpp>
#include <GpCrypto/GpCryptoCore/MnemonicCodes/GpCryptoMnemonicUtils.hpp>
#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDKeyStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_WALLET_API GpCryptoWalletUtils
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoWalletUtils)

public:
    static GpSecureStorage::CSP         SNewMnemonic                    (void);
    static bool                         SValidateMnemonic               (GpSpanCharR aMnemonic);
    static GpSecureStorage::CSP         SSeedFromMnemonic               (GpSpanCharR aMnemonic,
                                                                         GpSpanCharR aPassword);
    static GpCryptoHDKeyStorage::CSP    SGenerateBip44                  (GpSpanByteR aSeed);
    static GpCryptoSignKeyFactory::SP   SNewHDKeyFactory                (GpCryptoHDKeyStorage::CSP aBip44RootHD);
    static GpCryptoSignKeyFactory::SP   SNewHDKeyFactoryMnemonic        (GpSpanCharR aMnemonic, GpSpanCharR aPassword);
    static GpCryptoSignKeyFactory::SP   SNewRndKeyFactory               (void);
    static GpCryptoWalletAddress::SP    SNewAddrFromFactory             (GpCryptoWalletAddressFactory&  aAddrFactory,
                                                                         GpCryptoSignKeyFactory&        aKeyFactory);
    static GpCryptoWalletAddress::SP    SNewAddrFromPrivateKey          (GpCryptoWalletAddressFactory&  aAddrFactory,
                                                                         GpSecureStorage::CSP           aPrivateKey);
    static GpCryptoWalletAddress::SP    SNewAddrFromPrivateKeyStrHex    (GpCryptoWalletAddressFactory&  aAddrFactory,
                                                                         GpSecureStorage::CSP           aPrivateKeyStrHex);

private:
    static const GpCryptoMnemonicUtils::WordListT   sWordListEN;
};

}// namespace GPlatform
