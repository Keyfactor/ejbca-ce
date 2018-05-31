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

package org.ejbca.ui.web.rest.api.io.response;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.cesecore.util.Base64;

/**
 * A class representing general information about a keystore. Is used for REST services' responses.
 * 
 * @version $Id$
 */
public class KeystoreRestResponse {

    private byte[] keystoreData;
    private String keystoreType;

    
    public KeystoreRestResponse() {}

    public KeystoreRestResponse(KeyStore keystore, String password, String keystoreType) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        keystore.store(baos, password.toCharArray());
        this.keystoreData = Base64.encode(baos.toByteArray());
        this.keystoreType =  keystoreType;
    }
    
    /**
     * @return Returns the keystoreData, in Base64 encoded format.
     */
    public byte[] getKeystoreData() {
        return keystoreData;
    }

    /**
     * Set keystore data in Base64 format
     * @param keystoreData The keystoreData to set, in Base64 encoded format.
     */
    public void setKeystoreData(byte[] keystoreData) {
        this.keystoreData = keystoreData;
    }

    /**
     * @return Keystore type (JKS / PKCS12)
     */
    public String getKeystoreType() {
        return keystoreType;
    }

    /**
     * @param keystoreType JKS / PKCS12
     */
    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }
}