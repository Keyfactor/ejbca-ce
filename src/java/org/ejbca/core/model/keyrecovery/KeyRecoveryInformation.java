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

import org.cesecore.util.StringTools;


/**
 * This is a value class containing the data relating to key saved for recovery for a user, sent
 * between server and clients.
 *
 * @version $Id$
 */
public class KeyRecoveryInformation implements Serializable {

    private static final long serialVersionUID = -7473386427889757839L;
    // Public Constructors
    public KeyRecoveryInformation(BigInteger certificatesn, String issuerdn, String username,
                           boolean markedasrecoverable, KeyPair keypair, Certificate certificate) {
        this.certificatesn = certificatesn;
        this.issuerdn = issuerdn;
        this.username = StringTools.stripUsername(username);
        this.markedasrecoverable = markedasrecoverable;
        this.keypair = keypair;
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

    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     */
    public void setCertificateSN(BigInteger certificatesn) {
        this.certificatesn = certificatesn;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getIssuerDN() {
        return this.issuerdn;
    }

    /**
     * DOCUMENT ME!
     *
     * @param issuerdn DOCUMENT ME!
     */
    public void setIssuerDN(String issuerdn) {
        this.issuerdn = issuerdn;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     */
    public void setUsername(String username) {
        this.username = StringTools.stripUsername(username);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getMarkedAsRecoverable() {
        return this.markedasrecoverable;
    }

    /**
     * DOCUMENT ME!
     *
     * @param markedasrecoverable DOCUMENT ME!
     */
    public void setMarkedAsRecoverable(boolean markedasrecoverable) {
        this.markedasrecoverable = markedasrecoverable;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public KeyPair getKeyPair() {
        return this.keypair;
    }

    /**
     * DOCUMENT ME!
     *
     * @param keypair DOCUMENT ME!
     */
    public void setKeyPair(KeyPair keypair) {
        this.keypair = keypair;
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
    
    // Private fields
    private BigInteger certificatesn;
    private String issuerdn;
    private String username;
    private boolean markedasrecoverable;
    private KeyPair keypair;
    private Certificate certificate;


}
