#pragma once

#include <GpCrypto/GpCryptoCore/Wallet/GpCryptoAddressFactory.hpp>
#include <GpCrypto/GpCryptoCore/MnemonicCodes/GpMnemonicCodeGen.hpp>
#include <GpCrypto/GpCryptoCore/Keys/HD/GpCryptoHDKeyStorage.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoWalletUtils
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoWalletUtils)

public:
    static GpSecureStorage::CSP         SNewMnemonic                    (void);
    static bool                         SValidateMnemonic               (GpSpanCharR aMnemonic);
    static GpSecureStorage::CSP         SSeedFromMnemonic               (GpSpanCharR aMnemonic,
                                                                         GpSpanCharR aPassword);
    static GpCryptoHDKeyStorage::CSP    SGenerateBip44                  (GpSpanByteR aSeed);
    static GpCryptoKeyFactory::SP       SNewHDKeyFactory                (GpCryptoHDKeyStorage::CSP aBip44RootHD);
    static GpCryptoKeyFactory::SP       SNewHDKeyFactoryMnemonic        (GpSpanCharR aMnemonic, GpSpanCharR aPassword);
    static GpCryptoKeyFactory::SP       SNewRndKeyFactory               (void);
    static GpCryptoAddress::SP          SNewAddrFromFactory             (GpCryptoAddressFactory&    aAddrFactory,
                                                                         GpCryptoKeyFactory&        aKeyFactory);
    static GpCryptoAddress::SP          SNewAddrFromPrivateKey          (GpCryptoAddressFactory&    aAddrFactory,
                                                                         GpSecureStorage::CSP       aPrivateKey);
    static GpCryptoAddress::SP          SNewAddrFromPrivateKeyStrHex    (GpCryptoAddressFactory&    aAddrFactory,
                                                                         GpSecureStorage::CSP       aPrivateKeyStrHex);

private:
    static const GpMnemonicCodeGen::WordListT   sWordListEN;
};

}// namespace GPlatform
