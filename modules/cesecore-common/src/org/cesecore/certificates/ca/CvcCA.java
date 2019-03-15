/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keys.token.CryptoToken;

/**
 * 
 * @version $Id$
 *
 */
public interface CvcCA extends CA {

    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    void init(CVCCAInfo cainfo);

    /** Constructor used when retrieving existing CVCCA from database. */
    void init(HashMap<Object, Object> data, int caId, String subjectDN, String name, int status, Date updateTime, Date expireTime);

    String getCvcType();

    byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain);

    byte[] createPKCS7Rollover(CryptoToken cryptoToken);

    X509CRLHolder generateCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber);

    X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber);

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    float getLatestVersion();

    /** Implementation of UpgradableDataHashMap function upgrade. 
     */
    void upgrade();

    /**
     * Method to upgrade new (or existing external caservices)
     * This method needs to be called outside the regular upgrade
     * since the CA isn't instantiated in the regular upgrade.
     */
    boolean upgradeExtendedCAServices();

    byte[] decryptData(CryptoToken cryptoToken, byte[] data, int cAKeyPurpose);

    byte[] encryptData(CryptoToken cryptoToken, byte[] data, int keyPurpose);

}