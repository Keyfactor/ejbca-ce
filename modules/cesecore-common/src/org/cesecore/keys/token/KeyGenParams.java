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

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.pkcs11.jacknji11.CKA;

/**
 * Immutable object used for passing key parameters and attributes for key generation.
 * 
 * @version $Id$
 */
public class KeyGenParams implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private final String keySpecification;
    private final Map<Long, Object> publicAttributesMap;
    private final Map<Long, Object> privateAttributesMap;

    /**
     * Describes a set of PKCS #11 attribute templates.
     */
    public enum KeyPairTemplate {
        /**
         * Template for a keypair only allowed to be used for signing and verifying.
         */
        SIGN,
        /**
         * Template for a keypair only allowed to be used for decrypting and encrypting.
         */
        ENCRYPT
    }

    public static class KeyGenParamsBuilder {
        private String keySpecification;
        private Map<Long, Object> publicAttributesMap;
        private Map<Long, Object> privateAttributesMap;

        protected KeyGenParamsBuilder(final String keySpecification) {
            this.keySpecification = keySpecification;
            this.publicAttributesMap = new HashMap<>();
            this.privateAttributesMap = new HashMap<>();
        }

        protected KeyGenParamsBuilder(final KeyGenParams keyGenParams) {
            this.keySpecification = keyGenParams.getKeySpecification();
            this.publicAttributesMap = keyGenParams.getPublicAttributesMap();
            this.privateAttributesMap = keyGenParams.getPrivateAttributesMap();
        }

        /**
         * Specify the PKCS #11 attribute template to use.
         * 
         * @param keyPairTemplate the key pair template to use.
         * @return the builder.
         */
        public KeyGenParamsBuilder withKeyPairTemplate(final KeyPairTemplate keyPairTemplate) {
            if (keyPairTemplate == KeyPairTemplate.ENCRYPT) {
                privateAttributesMap.put(CKA.DECRYPT, true);
                privateAttributesMap.put(CKA.SIGN, false);
                publicAttributesMap.put(CKA.ENCRYPT, true);
                publicAttributesMap.put(CKA.VERIFY, false);
            } else if (keyPairTemplate == KeyPairTemplate.SIGN) {
                privateAttributesMap.put(CKA.DECRYPT, false);
                privateAttributesMap.put(CKA.SIGN, true);
                publicAttributesMap.put(CKA.ENCRYPT, false);
                publicAttributesMap.put(CKA.VERIFY, true);
            }
            return this;
        }

        /**
         * Set the type of key to use, e.g. 'RSA2048' or 'secp256r1'.
         * 
         * @param keySpecification the type of key to use.
         * @return the builder.
         */
        public KeyGenParamsBuilder setKeySpecification(final String keySpecification) {
            this.keySpecification = keySpecification;
            return this;
        }

        /**
         * Build an instance of the {@link KeyGenParams} class.
         * 
         * @return an instance of the {@link KeyGenParams} class.
         */
        public KeyGenParams build() {
            return new KeyGenParams(this);
        }
    }
    
    /**
     * Get a builder for constructing {@link KeyGenParams} instances.
     * 
     * @param keySpecification the type of key to use, e.g. 'RSA2048' or 'secp256r1'.
     * @return a builder for constructing {@link KeyGenParams} instances.
     */
    public static KeyGenParamsBuilder builder(final String keySpecification) {
        return new KeyGenParamsBuilder(keySpecification);
    }

    /**
     * Get a builder for constructing {@link KeyGenParams} instances, based on an existing
     * instance of {@link KeyGenParams}.
     * 
     * @param keyGenParams an existing instance of {@link KeyGenParams}.
     * @return a builder for constructing {@link KeyGenParams} instances.
     */
    public static KeyGenParamsBuilder builder(final KeyGenParams keyGenParams) {
        return new KeyGenParamsBuilder(keyGenParams);
    }

    private KeyGenParams(final KeyGenParamsBuilder builder) {
        this.keySpecification = builder.keySpecification;
        this.publicAttributesMap = builder.publicAttributesMap;
        this.privateAttributesMap = builder.privateAttributesMap;
    }
    
    /**
     * Get the type of key, e.g. 'RSA2048' or 'secp256r1'.
     * 
     * @return the key specification as a string.
     */
    public String getKeySpecification() {
        return keySpecification;
    }

    /**
     * Get a map with PKCS #11 attributes for the public key.
     * 
     * @return a map with PKCS #11 attributes.
     */
    public Map<Long, Object> getPublicAttributesMap() {
        return new HashMap<>(publicAttributesMap);
    }

    /**
     * Get a map with PKCS #11 attributes for the private key.
     * 
     * @return a map with PKCS #11 attributes.
     */
    public Map<Long, Object> getPrivateAttributesMap() {
        return new HashMap<>(privateAttributesMap);
    }
}
