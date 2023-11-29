/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
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

	/**
	 * Check if OCSP response have to be produced for individual certificates or not.
	 *
	 * @param ca certificate authority.
	 * @return whether an OCSP responses produced or not - true/false.
	 */
	public static boolean isDoPreProduceOcspResponsesUponIssuanceAndRevocation(CA ca) {
		if (ca instanceof X509CA) {
			return ((X509CA) ca).isDoPreProduceOcspResponseUponIssuanceAndRevocation();
		}
		return false;
	}

}
