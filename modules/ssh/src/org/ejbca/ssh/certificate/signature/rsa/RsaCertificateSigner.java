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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.ejbca.ssh.certificate.signature.SshCertificateSigner;

/**
 * RSA Certificate Signer.
 *
 * @version $Id$
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
