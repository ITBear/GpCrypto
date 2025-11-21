#include <GpCrypto/GpCryptoCore/GpCryptoCoreLib.hpp>
#include <GpCore2/GpUtils/Other/GpLinkedLibsInfo.hpp>

GP_STATIC_INITIALIZER_IMPL(GpCryptoCore)
GP_LIB_REGISTRATOR(GpCryptoCoreLib)

void    GpCryptoCore_StaticInitializer::OnInitialize (void)
{
    GpCryptoCoreLib::SRegisterSelf();
}
