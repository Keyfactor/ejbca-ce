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

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.pkcs11.jacknji11.CKA;

/**
 * Immutable object used for passing key parameters and attributes for key generation.
 */
public class KeyGenParams implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private final String keySpecification;
    private final Map<Long, Object> publicAttributesMap;
    private final Map<Long, Object> privateAttributesMap;

    /**
     * Describes a set of PKCS#11 attribute templates for the key pair generation with P11-NG
     */
    public enum KeyPairTemplate {
        /**
         * Template for a key pair only allowed to be used for signing and verifying.
         */
        SIGN,
        /**
         * Template for a key pair only allowed to be used for key wrapping and unwrapping.
         */
        ENCRYPT,
        /**
         * Template for a key pair allowed to be used for signing, verifying, unwrapping and wrapping.
         */
        SIGN_ENCRYPT
    }

    public static class KeyGenParamsBuilder {
        private String keySpecification;
        /** PKCS#11 attributes for the public key generation with P11-NG */
        private Map<Long, Object> publicAttributesMap;
        /** PKCS#11 attributes for the private key generation with P11-NG */
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
         * Specify the PKCS#11 attribute template to use, with P11-NG. There are different key templates depending on if
         * a generated key should be possible to use for signing or decryption, or both. Different HSMs can have limitations
         * regarding allowed mix of usage, for example Utimaco CP5, and Google GCP KMS, don't allow both sign and unwrap at the same time.
         * 
         * @param keyPairTemplate the {@link KeyPairTemplate} to use.
         * @return the builder.
         */
        public KeyGenParamsBuilder withKeyPairTemplate(final KeyPairTemplate keyPairTemplate) {
            // Utimaco CP5 allows only ENCRYPT/DECRYPT _or_ WRAP/UNWRAP. Since we use Decrypt in JackNJI11Provider we only need DECRYPT
            // See JackNJI11Provider.MyCipher.engineUnwrap for more information
            if (keyPairTemplate == KeyPairTemplate.ENCRYPT) {
                privateAttributesMap.put(CKA.DECRYPT, true);
                privateAttributesMap.put(CKA.UNWRAP, false);
                privateAttributesMap.put(CKA.SIGN, false);
                publicAttributesMap.put(CKA.ENCRYPT, true);
                publicAttributesMap.put(CKA.WRAP, false);
                publicAttributesMap.put(CKA.VERIFY, false);
            } else if (keyPairTemplate == KeyPairTemplate.SIGN) {
                privateAttributesMap.put(CKA.DECRYPT, false);
                privateAttributesMap.put(CKA.UNWRAP, false);
                privateAttributesMap.put(CKA.SIGN, true);
                publicAttributesMap.put(CKA.ENCRYPT, false);
                publicAttributesMap.put(CKA.WRAP, false);
                publicAttributesMap.put(CKA.VERIFY, true);
            } else if (keyPairTemplate == KeyPairTemplate.SIGN_ENCRYPT) {
                // SIGN_UNWRAP can not be used with a Utimaco CP5 HSM anyhow, but let's use the same limitations on DECRYPT/UNWRAP
                // there may be some future limitations on other HSMs, be minimalistic
                privateAttributesMap.put(CKA.DECRYPT, true);
                privateAttributesMap.put(CKA.UNWRAP, false);
                privateAttributesMap.put(CKA.SIGN, true);
                publicAttributesMap.put(CKA.ENCRYPT, true);
                publicAttributesMap.put(CKA.WRAP, false);
                publicAttributesMap.put(CKA.VERIFY, true);
            }
            return this;
        }

        public KeyGenParamsBuilder withPrivateTemplateAttribute(long attribute, boolean flag) {
            privateAttributesMap.put(attribute, flag);
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
     * Get key specification as a numeric string if RSA, or left untouched
     * 
     * @return the key specification string 
     */
    public static String getKeySpecificationNumericIfRsa(final String keySpec) {
        final String keySpecificationNumericIfRsa;
        if (StringUtils.startsWith(keySpec, AlgorithmConstants.KEYALGORITHM_RSA)) {
            keySpecificationNumericIfRsa = keySpec.substring(AlgorithmConstants.KEYALGORITHM_RSA.length());
        } else {
            keySpecificationNumericIfRsa = keySpec;
        }
        return keySpecificationNumericIfRsa;
    }
    
    /**
     * Get a map with PKCS#11 attributes for the public key generation with P11-NG.
     * 
     * @return a map with PKCS#11 attributes.
     */
    public Map<Long, Object> getPublicAttributesMap() {
        return new HashMap<>(publicAttributesMap);
    }

    /**
     * Get a map with PKCS#11 attributes for the private key generation with P11-NG
     * 
     * @return a map with PKCS#11 attributes.
     */
    public Map<Long, Object> getPrivateAttributesMap() {
        return new HashMap<>(privateAttributesMap);
    }
}
