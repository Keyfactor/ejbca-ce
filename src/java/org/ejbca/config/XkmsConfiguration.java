/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.config;

import org.apache.log4j.Logger;

/**
 * Configuration from xkms.properties
 *
 * @version $Id$
 */
public class XkmsConfiguration {

	private static final Logger log = Logger.getLogger(XkmsConfiguration.class);

	/**
	 * Return true if the XKMS service is enabled.
	 */
	public static boolean getEnabled() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.enabled", "false"));
	}
	
	/**
	 * Should signed XKMS request be required
	 */
	public static boolean getRequestRequireSignature() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.request.requiresignature", "false"));
	}
	
	/**
	 * ';'-separated list of CA names that are accepted for XKMS signed requests
	 */
	public static String[] getRequestAcceptedCas() {
		return ConfigurationHolder.getExpandedString("xkms.request.acceptedcas", "AdminCA1").split(";");
	}
	
	/**
	 * Signed response on request.
	 */
	public static boolean getResponseAcceptsignRequest() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.response.acceptsignrequest", "true"));
	}

	/**
	 * Always sign responses
	 */
	public static boolean getResponseAlwaysSign() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.response.alwayssign", "false"));
	}
	
	/**
	 * CA that should be used with the signed responses.
	 */
	public static String getResponseCaUsedForSigning() {
		return ConfigurationHolder.getExpandedString("xkms.response.causedforsigning", "AdminCA1");
	}
	
	/**
	 * The key usage in a X509 certificate is mapped to XKMS KeyUsage Signature
	 */
	public static boolean getKeyUsageSignatureIsNonRep() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.keyusage.signatureisnonrep", "true"));
	}

	/**
	 * Proof Of Possession element is required for KRSS calls.
	 */
	public static boolean getKrssPopRequired() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.krss.poprequired", "true"));
	}

	/**
	 * Setting indicating the size of server generated keys used in the register method.
	 */
	public static int getKrssServerGenKeyLength() {
		int value = 1024;
		try {
			value = Integer.parseInt(ConfigurationHolder.getString("xkms.krss.servergenkeylength", ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\"xkms.krss.servergenkeylength\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}
	
	/**
	 * End entity should be able to revoke his certificate using the revoke call and a revocation code identifier
	 */
	public static boolean getKrssAllowRevocation() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.krss.allowrevokation", "true"));
	}

	/**
	 * Defines if it should be possible to automatically issue a new certificate if the current one
	 * is valid and have a POP that verifies.
	 */
	public static boolean getKrssAllowAutomaticReissue() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("xkms.krss.allowautomaticreissue", "false"));
	}
}
