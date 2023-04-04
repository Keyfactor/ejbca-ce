/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng.provider;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;

/**
 * A PrivateKey without a session.
 *
 */
public class NJI11ReleasebleSessionPrivateKey extends NJI11Object implements Key, PrivateKey {
    
    private static final long serialVersionUID = -1293160515130067674L;

    /** Instance methods to create different implementations depending on keyAlg.
     * 
     * @param object The PKCS#11 reference for the key
     * @param algorithm Key algorithm to be returned by Key.getAlgorithm, typically RSA or EC
     * @param slot The CryptokiDevice this key is used on, used by the provider in order to perform PKCS#11 calls
     * @param modulus the modulus of the public key, only used if keyAlg is RSA, set to null otherwise
     * @return PrivateKey that is either a KeyVaultPrivateKey or a KeyVaultPrivateRSAKey
     * @throws RuntimException if keyAlg is RSA but publicKey is not an RSAPublicKey 
     */
    public static PrivateKey getInstance(long object, String algorithm, CryptokiDevice.Slot slot, BigInteger modulus) {
        if ("RSA".equals(algorithm)) {
            // We only need special treatment for RSA private keys because OpenJDK make a bitLength check 
            // on the RSA private key in the TLS implementation
            // SignatureScheme.getSignerOfPreferableAlgorithm->KeyUtil.getKeySize
            return new NJI11ReleasebleSessionRSAPrivateKey(object, slot, modulus);
        }
        return new NJI11ReleasebleSessionPrivateKey(object, algorithm, slot);
    }

    
    private final String algorithm;
    
    public NJI11ReleasebleSessionPrivateKey(long object, String algorithm, CryptokiDevice.Slot slot) {
        super(object, slot);
        this.algorithm = algorithm;
    }
    
    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
    
    public static class NJI11ReleasebleSessionRSAPrivateKey extends NJI11ReleasebleSessionPrivateKey implements RSAKey {
        private static final long serialVersionUID = 1L;
        private BigInteger modulus;

        public NJI11ReleasebleSessionRSAPrivateKey(long object, CryptokiDevice.Slot slot, BigInteger modulus) {
            super(object, "RSA", slot);
            this.modulus = modulus;
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }
    }

}
