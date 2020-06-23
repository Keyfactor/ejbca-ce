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
package org.ejbca.ssh.certificate.signature;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * @version $Id$
 *
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
