# ----------- Config -----------
TEMPLATE        = lib
QMAKE_CXXFLAGS += -DGP_REFLECTION_STATIC_ADD_TO_MANAGER
QMAKE_CXXFLAGS += -DGP_MODULE_UUID=c49212af-d8cf-4210-8662-30d0b565738e
PACKET_NAME     = GpCryptoUtils
DEFINES        += GP_CRYPTO_UTILS_LIBRARY
_VER_MAJ        = 2
_VER_MIN        = 1
_VER_PAT        = 6
DIR_LEVEL       = ./../..

include($$DIR_LEVEL/../QtGlobalPro.pri)

release_build_static{
	CONFIG += staticlib
}

# ----------- Libraries -----------
os_windows{
}

os_linux{
	LIBS += -lGpCryptoCore$$TARGET_POSTFIX
}

# ----------- Sources and headers -----------
SOURCES += \
	GpCryptoFileUtils.cpp \
	GpCryptoUtilsLib.cpp \
	SASL/Scram/GpCryptoSASLScram.cpp


HEADERS += \
	GpCryptoFileUtils.hpp \
	GpCryptoUtilsLib.hpp \
	GpCryptoUtils_global.hpp \
	SASL/Scram/GpCryptoSASLScram.hpp
