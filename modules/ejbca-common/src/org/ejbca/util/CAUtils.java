/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util;

import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;

/**
 * Generic CA Utils aimed to be used all around the codebase.
 */
public final class CAUtils {
	private CAUtils() {
	}

	/**
	 * Check if OCSP response produced or not depending on CA settings.
	 *
	 * @param ca certificate authority.
	 * @return whether an OCSP responses produced or not - true/false.
	 */
	public static boolean isDoPreProduceOcspResponses(CA ca) {
		if (ca instanceof X509CA) {
			return ((X509CA) ca).isDoPreProduceOcspResponses();
		}
		return false;
	}
}
