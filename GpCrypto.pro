TEMPLATE = subdirs

os_linux {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils
} else:os_android {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils
} else:os_ios {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils
} else:os_windows {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils
} else:os_macx {
	SUBDIRS += \
		./GpCryptoCore \
		./GpCryptoUtils
} else:os_browser {
	SUBDIRS +=
} else {
	error("Unknown OS. Set CONFIG+=... one of values: os_linux, os_android, os_ios, os_windows, os_macx, os_browser, os_baremetal")
}

CONFIG += ordered
