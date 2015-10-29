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

package org.ejbca.core.model.keyrecovery;


import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;

import org.cesecore.keys.util.KeyPairWrapper;
import org.cesecore.util.StringTools;


/**
 * This is a value class containing the data relating to key saved for recovery for a user, sent
 * between server and clients.
 *
 * @version $Id$
 */
public class KeyRecoveryInformation implements Serializable {

    private static final long serialVersionUID = -7473386427889757839L;

    // Private fields
    private BigInteger certificatesn;
    private String issuerdn;
    private String username;
    private boolean markedasrecoverable;
    private KeyPairWrapper keypair;
    private Certificate certificate;
    
    
    // Public Constructors
    public KeyRecoveryInformation(BigInteger certificatesn, String issuerdn, String username,
                           boolean markedasrecoverable, KeyPair keypair, Certificate certificate) {
        this.certificatesn = certificatesn;
        this.issuerdn = issuerdn;
        this.username = StringTools.stripUsername(username);
        this.markedasrecoverable = markedasrecoverable;
        this.keypair = new KeyPairWrapper(keypair);
        this.certificate = certificate;
    }

    /**
     * Creates a new KeyRecoveryData object.
     */
    public KeyRecoveryInformation() {
    }

    // Public Methods
    public BigInteger getCertificateSN() {
        return this.certificatesn;
    }

    public void setCertificateSN(BigInteger certificatesn) {
        this.certificatesn = certificatesn;
    }

    public String getIssuerDN() {
        return this.issuerdn;
    }

    public void setIssuerDN(String issuerdn) {
        this.issuerdn = issuerdn;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = StringTools.stripUsername(username);
    }

    public boolean getMarkedAsRecoverable() {
        return this.markedasrecoverable;
    }

    public void setMarkedAsRecoverable(boolean markedasrecoverable) {
        this.markedasrecoverable = markedasrecoverable;
    }

    public KeyPair getKeyPair() {
        return keypair.getKeyPair();
    }

    public void setKeyPair(KeyPair keypair) {
        this.keypair = new KeyPairWrapper(keypair);
    }

	/**
	 * @return Returns the certificate.
	 */
	public Certificate getCertificate() {
		return certificate;
	}
	/**
	 * @param certificate The certificate to set.
	 */
	public void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}
   

}
