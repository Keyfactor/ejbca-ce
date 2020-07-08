/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.certificate.signature.ec;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.ejbca.ssh.certificate.signature.SshSigningAlgorithm;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;

/**
 * Enum representation of all possible signing algorithms for SSH EC certificates
 *
 * @version $Id$
 */
public enum EcSigningAlgorithm implements SshSigningAlgorithm {
    SHA256(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, "ecdsa-sha2-nistp256", SshEcPublicKey.NISTP256),
    SHA384(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, "ecdsa-sha2-nistp384", SshEcPublicKey.NISTP384),
    SHA512(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, "ecdsa-sha2-nistp521", SshEcPublicKey.NISTP521);

    private final String identifier;
    private final String prefix;
    private final String requiredKey;

    private static final Map<String, EcSigningAlgorithm> identifierMap = new HashMap<>();

    static {
        for(EcSigningAlgorithm ecSigningAlgorithm : EcSigningAlgorithm.values()) {
            identifierMap.put(ecSigningAlgorithm.getIdentifier(), ecSigningAlgorithm);
        }
    }

    EcSigningAlgorithm(final String identifier, final String prefix, final String requiredKey) {
        this.identifier = identifier;
        this.prefix = prefix;
        this.requiredKey = requiredKey;
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

    public static EcSigningAlgorithm getFromIdentifier(final String identifier) {
        return identifierMap.get(identifier);
    }

    public boolean assertCorrectKeyType(final ECPublicKey ecPrivateKey) throws InvalidKeySpecException {
        return SshEcPublicKey.getSshCurveNameFromPublicKey(ecPrivateKey).equals(requiredKey);
    }

}
