package org.jscep.message;

import static org.bouncycastle.cms.CMSAlgorithm.DES_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.DES_EDE3_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.AES128_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.AES192_CBC;
import static org.bouncycastle.cms.CMSAlgorithm.AES256_CBC;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used for enveloping and encrypting a {@code messageData} to
 * produce the {@code pkcsPkiEnvelope} part of a SCEP secure message object.
 * 
 * @see PkcsPkiEnvelopeDecoder
 */
public final class PkcsPkiEnvelopeEncoder {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(PkcsPkiEnvelopeEncoder.class);
    private final X509Certificate recipient;
    private final ASN1ObjectIdentifier encAlgId;

    /**
     * Creates a new {@code PkcsPkiEnvelopeEncoder} for the entity identified
     * by the provided certificate.
     * 
     * @param recipient
     *            the entity for whom the {@code pkcsPkiEnvelope} is intended.
     */
    @Deprecated
    public PkcsPkiEnvelopeEncoder(final X509Certificate recipient) {
        this(recipient, "DES");
    }

    /**
     * Creates a new {@code PkcsPkiEnvelopeEncoder} for the entity identified
     * by the provided certificate.
     * 
     * @param recipient
     *            the entity for whom the {@code pkcsPkiEnvelope} is intended.
     * @param encAlg
     *            the encryption algorithm to use.
     */
    public PkcsPkiEnvelopeEncoder(final X509Certificate recipient,
            final String encAlg) {
        this.recipient = recipient;
        this.encAlgId = getAlgorithmId(encAlg);
    }

    /**
     * Encrypts and envelops the provided messageData.
     * 
     * @param messageData
     *            the message data to encrypt and envelop.
     * @return the enveloped data.
     * @throws MessageEncodingException
     *             if there are any problems encoding the message.
     */
    public CMSEnvelopedData encode(final byte[] messageData)
            throws MessageEncodingException {
        LOGGER.debug("Encoding pkcsPkiEnvelope");
        CMSEnvelopedDataGenerator edGenerator = new CMSEnvelopedDataGenerator();
        CMSTypedData envelopable = new CMSProcessableByteArray(messageData);
        RecipientInfoGenerator recipientGenerator;
        try {
            recipientGenerator = new JceKeyTransRecipientInfoGenerator(
                    recipient);
        } catch (CertificateEncodingException e) {
            throw new MessageEncodingException(e);
        }
        edGenerator.addRecipientInfoGenerator(recipientGenerator);
        LOGGER.debug(
                "Encrypting pkcsPkiEnvelope using key belonging to [dn={}; serial={}]",
                recipient.getSubjectX500Principal(), recipient.getSerialNumber());

        OutputEncryptor encryptor;
        try {
            encryptor = new JceCMSContentEncryptorBuilder(encAlgId).build();
        } catch (CMSException e) {
            throw new MessageEncodingException(e);
        }
        try {
            CMSEnvelopedData pkcsPkiEnvelope = edGenerator.generate(
                    envelopable, encryptor);

            LOGGER.debug("Finished encoding pkcsPkiEnvelope");
            return pkcsPkiEnvelope;
        } catch (CMSException e) {
            throw new MessageEncodingException(e);
        }
    }

    private ASN1ObjectIdentifier getAlgorithmId(String encAlg) {
        if ("DES".equals(encAlg)) {
            return DES_CBC;
        } 
        else if("AES".equals(encAlg) || "AES_128".equals(encAlg)){
            return AES128_CBC;
        }
        else if ("AES_192".equals(encAlg)) {
            return AES192_CBC;
        }
        else if ("AES_256".equals(encAlg)) {
            return AES256_CBC;
        }
        else if ("DESede".equals(encAlg)) {
            return DES_EDE3_CBC;
        }
        else {
            throw new IllegalArgumentException("Unknown algorithm: " + encAlg);
        }
    }
}
