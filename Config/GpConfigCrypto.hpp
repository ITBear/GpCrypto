#pragma once

#include <GpCore2/Config/GpEnvironmentDetector.hpp>

//******************* OS *****************
#if defined(GP_OS_WINDOWS)
#   include <GpCrypto/Config/GpConfigCrypto_os_windows.hpp>
#elif defined(GP_OS_LINUX)
#   include <GpCrypto/Config/GpConfigCrypto_os_android.hpp>
#elif defined(GP_OS_ANDROID)
#   include <GpCrypto/Config/GpConfigCrypto_os_android.hpp>
#elif defined(GP_OS_IOS)
#   include <GpCrypto/Config/GpConfigCrypto_os_ios.hpp>
#elif defined(GP_OS_IOS_SIMULATOR)
#   include <GpCrypto/Config/GpConfigCrypto_os_ios_simulator.hpp>
#elif defined(GP_OS_MACOSX)
#   include <GpCrypto/Config/GpConfigCrypto_os_macosx.hpp>
#elif defined(GP_OS_BARE_METAL)
#   include <GpCrypto/Config/GpConfigCrypto_os_baremetal.hpp>
#elif defined(GP_OS_BROWSER)
#   include <GpCrypto/Config/GpConfigCrypto_os_browser.hpp>
#else
#   error Current OS is not supported yet.
#endif
