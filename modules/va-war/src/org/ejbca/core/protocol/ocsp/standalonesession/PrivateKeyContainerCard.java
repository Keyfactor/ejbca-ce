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

package org.ejbca.core.protocol.ocsp.standalonesession;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;


/**
 * Card implementation.
 * 
 * @author primelars
 * @version  $Id$
 */
class PrivateKeyContainerCard implements PrivateKeyContainer {
    /**
     * The signing certificate.
     */
    final private X509Certificate certificate;
    /**
     * The keys on the card.
     */
    final private CardKeys cardKeys;
    /**
     * Initiates the object.
     * @param cert the signing certificate
     * @param keys The keys on the card.
     */
    PrivateKeyContainerCard( X509Certificate cert, CardKeys keys) {
        this.certificate = cert;
        this.cardKeys = keys;
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#getKey()
     */
    public PrivateKey getKey() throws Exception {
        return this.cardKeys.getPrivateKey((RSAPublicKey)this.certificate.getPublicKey());
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#releaseKey()
     */
    public void releaseKey() {
        // not used by cards since no rekeying
    }
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#isOK()
	 */
	public boolean isOK() {
		return this.cardKeys.isOK((RSAPublicKey)this.certificate.getPublicKey());
	}
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#clear()
     */
    public void clear() {
        // not used by cards.
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#set(java.security.KeyStore)
     */
    public void set(KeyStore keyStore) throws Exception {
        // not used by cards.
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#getCertificate()
     */
    public X509Certificate getCertificate() {
        return this.certificate;
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#init(java.util.List, int)
     */
    public void init(List<X509Certificate> name, int caid) {
        // do nothing
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#destroy()
     */
    public void destroy() {
        // do nothing
    }
}