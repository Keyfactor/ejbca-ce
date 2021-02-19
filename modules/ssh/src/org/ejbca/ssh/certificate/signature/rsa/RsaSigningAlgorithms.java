/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.certificate.signature.rsa;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.ejbca.ssh.certificate.signature.SshSigningAlgorithm;

/**
 * Enum representation of all possible signing algorithms for SSH EC certificates
 */
public enum RsaSigningAlgorithms implements SshSigningAlgorithm {
    SHA1(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, "ssh-rsa"),
    SHA256(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, "rsa-sha2-256"),
    SHA512(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, "rsa-sha2-512");


    private final String identifier;
    private final String prefix;

    private static final Map<String, RsaSigningAlgorithms> identifierMap = new HashMap<>();

    static {
        for(RsaSigningAlgorithms rsaSigningAlgorithm : RsaSigningAlgorithms.values()) {
            identifierMap.put(rsaSigningAlgorithm.getIdentifier(), rsaSigningAlgorithm);
        }
    }

    RsaSigningAlgorithms(final String identifier, final String prefix) {
        this.identifier = identifier;
        this.prefix = prefix;
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Signature getSigner(final String provider) {
        try {
            return Signature.getInstance(identifier, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Fixed algorithms identifier " + identifier + " was not found in provider.");
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider was not found");
        }
    }

    @Override
    public String getPrefix() {
        return prefix;
    }

    public static RsaSigningAlgorithms getFromIdentifier(final String identifier) {
        return identifierMap.get(identifier);
    }

}
