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

package org.cesecore.keys.token;

import java.util.HashMap;
import java.util.Map;

/**
 * Object used for passing key parameters and attributes for key generation.
 * @version $Id$
 *
 */
public class KeyGenParams {
    
    private String keySpecification;
    private Map<Long, Object> publicAttributesMap = new HashMap<>();
    private Map<Long, Object> privateAttributesMap = new HashMap<>();
    
    public KeyGenParams() {}

    /**
     * Should be in the form "RSAnnnn", "DSAnnnn" or a known EC curve name.
     * @param keySpecification
     */
    public KeyGenParams(final String keySpecification) {
        this.keySpecification = keySpecification;
    }
    
    /**
     * @return algorithm and key spec. E.g. 'RSA2048'.
     */
    public String getKeySpecification() {
        return keySpecification;
    }

    /**
     * @param keySpecification algorithm and key spec. E.g. 'RSA2048'.
     */
    public void setKeySpecification(String keySpecification) {
        this.keySpecification = keySpecification;
    }

    public Map<Long, Object> getPublicAttributesMap() {
        return publicAttributesMap;
    }

    public Map<Long, Object> getPrivateAttributesMap() {
        return privateAttributesMap;
    }
    
    /**
     * Override default PKCS#11 public key attributes used for key generation.
     * @param key attribute key. E.g. CKA.ENCRYPT
     * @param value attribute value. E.g. true / false
     */
    public void addPublicKeyAttribute(Long key, Object value) {
        publicAttributesMap.put(key, value);
    }
    
    /**
     * Override default PKCS#11 private key attributes used for key generation.
     * @param key attribute key. E.g. CKA.DECRYPT
     * @param value attribute value. E.g. true / false
     */
    public void addPrivateKeyAttribute(Long key, Object value) {
        privateAttributesMap.put(key, value);
    }
}
