package org.jscep.message;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.operator.InputDecryptor;
import org.slf4j.Logger;

/**
 * This class is used to decrypt the {@code pkcsPkiEnvelope} of a SCEP secure
 * message object and extract the {@code messageData} from within.
 *
 * @see PkcsPkiEnvelopeEncoder
 */
public final class PkcsPkiEnvelopeDecoder {
    private static final Logger LOGGER = getLogger(PkcsPkiEnvelopeDecoder.class);
    private final X509Certificate recipient;
    private final PrivateKey privKey;

    /**
     * Creates a {@code PkcsPkiEnveloperDecoder} for the provided certificate
     * and key.
     * <p>
     * The provided certificate is used to identify the envelope recipient info,
     * which is then used with the key unwrapped using the provided key.
     *
     * @param recipient
     *            the entity for whom the message was enveloped.
     * @param privKey
     *            the key to unwrap the symmetric encrypting key.
     */
    public PkcsPkiEnvelopeDecoder(final X509Certificate recipient,
            final PrivateKey privKey) {
        this.recipient = recipient;
        this.privKey = privKey;
    }

    /**
     * Decrypts the provided {@code pkcsPkiEnvelope}, and extracts the content.
     *
     * @param pkcsPkiEnvelope
     *            the envelope to decrypt and open.
     * @return the content of the {@code pkcsPkiEnvelope}, the SCEP
     *         {@code messageData}.
     * @throws MessageDecodingException
     *             if the envelope cannot be decoded.
     */
    public byte[] decode(final CMSEnvelopedData pkcsPkiEnvelope)
            throws MessageDecodingException {
        LOGGER.debug("Decoding pkcsPkiEnvelope");
        validate(pkcsPkiEnvelope);

        LOGGER.debug(
                "Decrypting pkcsPkiEnvelope using key belonging to [dn={}; serial={}]",
                recipient.getSubjectX500Principal(), recipient.getSerialNumber());
        final RecipientInformationStore recipientInfos = pkcsPkiEnvelope
                .getRecipientInfos();
        RecipientInformation info = recipientInfos
                .get(new JceKeyTransRecipientId(recipient));

        if (info == null) {
            throw new MessageDecodingException(
                    "Missing expected key transfer recipient " + recipient.getSubjectX500Principal());
        }

        LOGGER.debug("pkcsPkiEnvelope encryption algorithm: {}", info
                .getKeyEncryptionAlgorithm().getAlgorithm());

        try {
            byte[] messageData = info.getContent(getKeyTransRecipient());
            LOGGER.debug("Finished decoding pkcsPkiEnvelope");
            return messageData;
        } catch (CMSException e) {
            throw new MessageDecodingException(e);
        }
    }

    private JceKeyTransEnvelopedRecipient getKeyTransRecipient() {
        return new InternalKeyTransEnvelopedRecipient(privKey);
    }

    private void validate(final CMSEnvelopedData pkcsPkiEnvelope) {
        EnvelopedData ed = EnvelopedData.getInstance(pkcsPkiEnvelope
                .toASN1Structure().getContent());
        LOGGER.debug("pkcsPkiEnvelope version: {}", ed.getVersion());
        LOGGER.debug("pkcsPkiEnvelope encryptedContentInfo contentType: {}", ed
                .getEncryptedContentInfo().getContentType());
    }
    
    private static class InternalKeyTransEnvelopedRecipient extends JceKeyTransEnvelopedRecipient {
        private static final String RSA = "RSA/ECB/PKCS1Padding";
        private static final String DES = "DES";
        private final PrivateKey wrappingKey;
        
        public InternalKeyTransEnvelopedRecipient(PrivateKey wrappingKey) {
            super(wrappingKey);
            this.wrappingKey = wrappingKey;
        }
        
        @Override
        public RecipientOperator getRecipientOperator(
            final AlgorithmIdentifier notUsed,
            final AlgorithmIdentifier contentAlg,
            final byte[] wrappedKey)
            throws CMSException {
            if ("1.3.14.3.2.7".equals(contentAlg.getAlgorithm().getId())) {
                final Cipher dataCipher;
                try {
                    Key contentKey = unwrapKey(wrappingKey, wrappedKey);
                    dataCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                    dataCipher.init(Cipher.DECRYPT_MODE, contentKey, getIV(contentAlg));
                } catch (GeneralSecurityException e) {
                    throw new CMSException("Could not create DES cipher", e);
                }

                return new RecipientOperator(new InputDecryptor() {
                    @Override
                    public AlgorithmIdentifier getAlgorithmIdentifier() {
                        return contentAlg;
                    }

                    @Override
                    public InputStream getInputStream(final InputStream dataIn) {
                        return new CipherInputStream(dataIn, dataCipher);
                    }
                });
            }
            return super.getRecipientOperator(notUsed, contentAlg, wrappedKey);
        }
        
        private Key unwrapKey(PrivateKey wrappingKey, byte[] wrappedKey) throws GeneralSecurityException {
            Cipher unwrapper = Cipher.getInstance(RSA);
            unwrapper.init(Cipher.UNWRAP_MODE, wrappingKey);
            try {
                return unwrapper.unwrap(wrappedKey, DES, Cipher.SECRET_KEY);
            } catch (InvalidKeyException e) {
                LOGGER.error("Cannot unwrap symetric key.  Are you using a valid key pair?");
                throw e;
            }
        }
                
        private AlgorithmParameterSpec getIV(AlgorithmIdentifier envelopingAlgorithm) {
            ASN1Encodable ivParams = envelopingAlgorithm.getParameters();
            return new IvParameterSpec(ASN1OctetString.getInstance(ivParams).getOctets());
        }
    }
}
