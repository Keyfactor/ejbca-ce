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
package org.cesecore.keys.util;

import java.io.Serializable;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Wrapper class for serializing KeyPair objects. 
 * 
 * @version $Id$
 *
 */
public class KeyPairWrapper implements Serializable {

    private static final long serialVersionUID = 1L;
    
    final byte[] encodedPublicKey;
    final byte[] encodedPrivateKey;
    final String algorithm;
    
    public KeyPairWrapper(final KeyPair keyPair) {
        this.encodedPublicKey = keyPair.getPublic().getEncoded();
        this.encodedPrivateKey = keyPair.getPrivate().getEncoded();
        this.algorithm = keyPair.getPublic().getAlgorithm();
    }
    
    /**
     * 
     * @return the decoded PublicKey object wrapped in this class.
     * 
     */
    private PublicKey getPublicKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not a known provider.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm "  + algorithm + " was not known at deserialisation", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("The incorrect key specification was implemented.", e);
        } 
    }
    
    /**
     * 
     * @return the decoded PublicKey object wrapped in this class.
     * 
     */
    private PrivateKey getPrivateKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not a known provider.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm "  + algorithm + " was not known at deserialisation", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("The incorrect key specification was implemented.", e);
        } 
    }
    
    
    public KeyPair getKeyPair() {
        return new KeyPair(getPublicKey(), getPrivateKey());
    }
   
}
