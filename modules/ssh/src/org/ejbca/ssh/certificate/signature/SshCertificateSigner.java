/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.certificate.signature;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * SSH Certificate Signer.
 *
 * @version $Id$
 */
public interface SshCertificateSigner {

    /**
     * Sign the given payload and return a signature that can be inserted into an SSH certificate
     *
     * @param payload the payload to be signed, typically the contents of an SSH certificate except for the signature itself
     * @param signingPublicKey used to verify that the correct signing algorithm is being used
     * @param signingKey the CA's private key
     * @return a signature
     * @throws InvalidKeyException if the signing key was of an incorrect type
     * @throws SignatureException if the signer was unable to sign the key
     */
    byte[] signPayload(final byte[] payload, final PublicKey signingPublicKey, final PrivateKey signingKey)
            throws InvalidKeyException, SignatureException;
}
