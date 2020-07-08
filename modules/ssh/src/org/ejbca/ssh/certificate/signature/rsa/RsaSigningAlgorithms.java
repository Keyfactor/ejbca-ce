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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.ejbca.ssh.certificate.signature.SshSigningAlgorithm;

/**
 * Enum representation of all possible signing algorithms for SSH EC certificates
 *
 * @version $Id$
 */
public enum RsaSigningAlgorithms implements SshSigningAlgorithm {
    SHA1(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, "ssh-rsa"),
    SHA256(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, "rsa-sha2-256"),
    SHA512(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, "rsa-sha2-512");


    private final String identifier;
    private final String prefix;

    RsaSigningAlgorithms(final String identifier, final String prefix) {
        this.identifier = identifier;
        this.prefix = prefix;
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Signature getSigner() {
        try {
            return Signature.getInstance(identifier, BouncyCastleProvider.PROVIDER_NAME);
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

}
