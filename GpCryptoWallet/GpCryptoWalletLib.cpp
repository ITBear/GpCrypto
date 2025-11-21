#include <GpCrypto/GpCryptoWallet/GpCryptoWalletLib.hpp>
#include <GpCore2/GpUtils/Other/GpLinkedLibsInfo.hpp>

GP_STATIC_INITIALIZER_IMPL(GpCryptoWallet)
GP_LIB_REGISTRATOR(GpCryptoWalletLib)

void    GpCryptoWallet_StaticInitializer::OnInitialize (void)
{
    GpCryptoWalletLib::SRegisterSelf();
}
