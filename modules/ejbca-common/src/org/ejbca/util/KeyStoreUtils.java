package org.ejbca.util;

import org.ejbca.core.model.SecConst;

public final class KeyStoreUtils {

	private KeyStoreUtils() {
	}

	public static String determineKeyStoreType(int keystoreType) {
		switch (keystoreType) {
		case SecConst.TOKEN_SOFT_JKS:
			return "JKS";
		case SecConst.TOKEN_SOFT_PEM:
			return "PEM";
		case SecConst.TOKEN_SOFT_P12:
		case SecConst.TOKEN_SOFT_BROWSERGEN:
			return "PKCS12";
		case SecConst.TOKEN_SOFT_BCFKS:
			return "BCFKS";
		default:
			return "UNKNOWN";
		}
	}
}
