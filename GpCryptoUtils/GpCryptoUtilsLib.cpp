#include <GpCrypto/GpCryptoUtils/GpCryptoUtilsLib.hpp>
#include <GpCore2/GpUtils/Other/GpLinkedLibsInfo.hpp>

GP_STATIC_INITIALIZER_IMPL(GpCryptoUtils)
GP_LIB_REGISTRATOR(GpCryptoUtilsLib)

void    GpCryptoUtils_StaticInitializer::OnInitialize (void)
{
    GpCryptoUtilsLib::SRegisterSelf();
}
