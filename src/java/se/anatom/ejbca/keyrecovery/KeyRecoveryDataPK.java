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

package se.anatom.ejbca.keyrecovery;

/**
 * Primary key for key recovery data
 *
 * @version $Id: KeyRecoveryDataPK.java,v 1.6 2004-06-08 18:02:29 sbailliez Exp $
 */
public final class KeyRecoveryDataPK implements java.io.Serializable {
	public String certSN;
    public String issuerDN;

	/**
	 * Creates a new KeyRecoveryDataPK object.
	 *
	 * @param certSN certificate serial number
	 * @param issuerDN dn of issuer of certificate
     * @deprecated Use KeyRecovery(String, String) instead
	 */
	public KeyRecoveryDataPK(java.math.BigInteger certSN, java.lang.String issuerDN) {
        this(certSN.toString(16), issuerDN);
	}

    /**
     * Create a new key
     * @param certSN the certificate sn in serial number in hexadecimal
     * @param issuerDN issuer dn of the certificate
     */
	public KeyRecoveryDataPK(String certSN, java.lang.String issuerDN) {
        this.certSN = certSN;
        this.issuerDN = issuerDN;
	}

	/**
	 * Creates a new KeyRecoveryDataPK object.
	 */
	public KeyRecoveryDataPK() {
	}
    public String getCertSN() {
        return certSN;
    }
    public String getIssuerDN() {
        return issuerDN;
    }

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(java.lang.Object other) {
        if (other instanceof KeyRecoveryDataPK) {
           return ( (certSN.equals(((KeyRecoveryDataPK)other).certSN)) &&
               (issuerDN.equals(((KeyRecoveryDataPK)other).issuerDN)) );
        }
        return false;
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return (this.certSN+this.issuerDN).hashCode();
	}

}
