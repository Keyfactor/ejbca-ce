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
package org.ejbca.ssh.certificate.signature.rsa;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.ejbca.ssh.certificate.signature.SshCertificateSigner;

/**
 * @version $Id$
 *
 */
public class RsaCertificateSigner implements SshCertificateSigner {

    private final RsaSigningAlgorithms signingAlgorithm;

    public RsaCertificateSigner(final RsaSigningAlgorithms signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    @Override
    public byte[] signPayload(final byte[] payload, final PublicKey signingPublicKey, final PrivateKey signingKey)
            throws InvalidKeyException, SignatureException {
        try {
            Signature signer = signingAlgorithm.getSigner();
            signer.initSign(signingKey);
            signer.update(payload);
            byte[] signatureBytes = signer.sign();
            SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
            sshCertificateWriter.writeString(signingAlgorithm.getPrefix());
            sshCertificateWriter.writeByteArray(signatureBytes);
            sshCertificateWriter.flush();
            sshCertificateWriter.close();
            return sshCertificateWriter.toByteArray();
        } catch (IOException | SignatureException e) {
            throw new SignatureException("Given payload could not be signed.", e);
        }
    }

}
