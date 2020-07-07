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
package org.ejbca.ssh.certificate.signature.ec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.ejbca.ssh.certificate.signature.SshCertificateSigner;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;

/**
 * EC Certificate Signer.
 *
 * @version $Id$
 */
public class EcCertificateSigner implements SshCertificateSigner {

    private final EcSigningAlgorithm signingAlgorithm;

    public EcCertificateSigner(final EcSigningAlgorithm sshSigningAlgorithm) {
        this.signingAlgorithm = sshSigningAlgorithm;
    }

    @Override
    public byte[] signPayload(final byte[] payload, final PublicKey signingPublicKey, final PrivateKey signingKey) throws InvalidKeyException, SignatureException {
        try {
            if (!signingAlgorithm.assertCorrectKeyType((ECPublicKey) signingPublicKey)) {
                throw new InvalidKeyException("Incorrect EC signing key ("
                        + SshEcPublicKey.getSshCurveNameFromPublicKey((ECPublicKey) signingPublicKey) + ") was provided for algorithm " + signingAlgorithm.getIdentifier());
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }

        try {
            Signature signer = signingAlgorithm.getSigner();
            signer.initSign(signingKey);
            signer.update(payload);
            byte[] signatureBytes = signer.sign();
            SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
            sshCertificateWriter.writeString(signingAlgorithm.getPrefix());
            SshCertificateWriter signatureWriter = new SshCertificateWriter();
            ByteArrayInputStream inStream = new ByteArrayInputStream(signatureBytes);
            ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
            ASN1Sequence asn1Sequence = (ASN1Sequence) asnInputStream.readObject();
            ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
            for (ASN1Encodable asn1Encodable : asn1Encodables) {
                ASN1Integer asn1Integer = (ASN1Integer) asn1Encodable.toASN1Primitive();
                BigInteger integer = asn1Integer.getValue();
                signatureWriter.writeBigInteger(integer);
            }
            asnInputStream.close();
            sshCertificateWriter.writeByteArray(signatureWriter.toByteArray());
            signatureWriter.close();
            sshCertificateWriter.flush();
            sshCertificateWriter.close();
            return sshCertificateWriter.toByteArray();
        } catch (IOException | SignatureException e) {
            throw new SignatureException("Given payload could not be signed.", e);
        }
    }

}
