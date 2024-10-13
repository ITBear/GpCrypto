TEMPLATE = subdirs

os_linux {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils \
		./GpCryptoWallet
} else:os_android {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils \
		./GpCryptoWallet
} else:os_ios {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils \
		./GpCryptoWallet
} else:os_windows {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils \
		./GpCryptoWallet
} else:os_macx {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils \
		./GpCryptoWallet
} else:os_browser {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils \		
		./GpCryptoUtilsWasm \
		./GpCryptoWallet
} else {
    error("Unknown OS")
}

CONFIG += ordered
