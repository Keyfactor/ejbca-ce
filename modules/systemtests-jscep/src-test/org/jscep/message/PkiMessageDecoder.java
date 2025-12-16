package org.jscep.message;

import static org.jscep.asn1.ScepObjectIdentifier.*;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.asn1.ScepObjectIdentifier;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;
import org.slf4j.Logger;

import org.bouncycastle.util.Selector;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

/**
 * This class is used to decode a PKCS #7 signedData object into a
 * {@code pkiMessage}.
 *
 * @see PkiMessageEncoder
 */
public final class PkiMessageDecoder {
    private static final Logger LOGGER = getLogger(PkiMessageDecoder.class);
    private final PkcsPkiEnvelopeDecoder decoder;
    private final X509Certificate signer;
    private boolean checkSignatureTime;

    /**
     * Creates a new {@code PkiMessageDecoder}.
     *
     * @param signer
     *            the certificate used for verifying the {@code signedData}
     *            signature.
     * @param decoder
     *            the decoder used for extracting the {@code pkiMessage}.
     */
    public PkiMessageDecoder(final X509Certificate signer,
            final PkcsPkiEnvelopeDecoder decoder) {
        this.decoder = decoder;
        this.signer = signer;
        this.checkSignatureTime = true;
    }

    public void ignoreSigningTime() {
        this.checkSignatureTime = false;
    }

    /**
     * Decodes the provided PKCS #7 {@code signedData} into a
     * {@code PkiMessage}
     *
     * @param pkiMessage
     *            the {@code signedData} to decode.
     * @return the decoded {@code PkiMessage}
     * @throws MessageDecodingException
     *             if there is a problem decoding the {@code signedData}
     */
    @SuppressWarnings("unchecked")
    public PkiMessage<?> decode(final CMSSignedData pkiMessage)
            throws MessageDecodingException {
        LOGGER.debug("Decoding pkiMessage");
        validate(pkiMessage);

        // The signed content is always an octet string
        CMSProcessable signedContent = pkiMessage.getSignedContent();

        SignerInformationStore signerStore = pkiMessage.getSignerInfos();
        SignerInformation signerInfo = signerStore.get(new JcaSignerId(signer));
        if (signerInfo == null) {
            throw new MessageDecodingException("Could not for signerInfo for "
                    + signer.getSubjectX500Principal());
        }

        LOGGER.debug("pkiMessage digest algorithm: {}", signerInfo
                .getDigestAlgorithmID().getAlgorithm());
        LOGGER.debug("pkiMessage encryption algorithm: {}",
                signerInfo.getEncryptionAlgOID());

        
        SignerId signerId = signerInfo.getSID();
        Selector<X509CertificateHolder> selector = new X509CertificateHolderSelector(signerId.getIssuer(), signerId.getSerialNumber());

        Store<X509CertificateHolder> store = pkiMessage.getCertificates();
        Collection<X509CertificateHolder> certColl;
        try {
            certColl = store.getMatches(selector);
        } catch (StoreException e) {
            throw new MessageDecodingException(e);
        }
        if (certColl.size() > 0) {
            X509CertificateHolder cert = certColl.iterator().next();
            LOGGER.debug(
                    "Verifying pkiMessage using key belonging to [dn={}; serial={}]",
                    cert.getSubject(), cert.getSerialNumber());
            SignerInformationVerifier verifier;
            try {
                verifier = new JcaSimpleSignerInfoVerifierBuilder().build(cert);
                if (!this.checkSignatureTime) {
                    X509Certificate javaCert = new JcaX509CertificateConverter().setProvider( "BC" )
                            .getCertificate( cert );
                    verifier = new JcaSimpleSignerInfoVerifierBuilder().build(javaCert.getPublicKey());
                }
                if (signerInfo.verify(verifier) == false) {
                    final String msg = "pkiMessage verification failed.";
                    LOGGER.warn(msg);
                    throw new MessageDecodingException(msg);
                }

                LOGGER.debug("pkiMessage verified.");
            } catch (CMSException e) {
                throw new MessageDecodingException(e);
            } catch (OperatorCreationException e) {
                throw new MessageDecodingException(e);
            } catch (CertificateException e) {
                throw new MessageDecodingException(e);
            }
        } else {
            LOGGER.warn("Unable to verify message because the signedData contained no certificates.");
        }

        Hashtable<ASN1ObjectIdentifier, Attribute> attrTable = signerInfo
                .getSignedAttributes().toHashtable();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("pkiMessage has {} signed attributes:", signerInfo
                    .getSignedAttributes().size());
            for (Entry<ASN1ObjectIdentifier, Attribute> entry : attrTable
                    .entrySet()) {
                LOGGER.debug("  {}: {}", entry.getKey().getId(), entry
                        .getValue().getAttrValues());
            }
        }

        MessageType messageType = toMessageType(attrTable
                .get(toOid(MESSAGE_TYPE)));
        Nonce senderNonce = toNonce(attrTable.get(toOid(SENDER_NONCE)));
        TransactionId transId = toTransactionId(attrTable.get(toOid(TRANS_ID)));

        if (messageType == MessageType.CERT_REP) {
            PkiStatus pkiStatus = toPkiStatus(attrTable.get(toOid(PKI_STATUS)));
            Nonce recipientNonce = toNonce(attrTable
                    .get(toOid(RECIPIENT_NONCE)));

            if (pkiStatus == PkiStatus.FAILURE) {
                FailInfo failInfo = toFailInfo(attrTable.get(toOid(FAIL_INFO)));
                LOGGER.debug("Finished decoding pkiMessage");
                return new CertRep(transId, senderNonce, recipientNonce,
                        failInfo);
            } else if (pkiStatus == PkiStatus.PENDING) {
                LOGGER.debug("Finished decoding pkiMessage");
                return new CertRep(transId, senderNonce, recipientNonce);
            } else {
                final CMSEnvelopedData ed = getEnvelopedData(signedContent
                        .getContent());
                final byte[] envelopedContent = decoder.decode(ed);
                CMSSignedData messageData;
                try {
                    messageData = new CMSSignedData(envelopedContent);
                } catch (CMSException e) {
                    throw new MessageDecodingException(e);
                }
                LOGGER.debug("Finished decoding pkiMessage");
                return new CertRep(transId, senderNonce, recipientNonce,
                        messageData);
            }
        } else {
            CMSEnvelopedData ed = getEnvelopedData(signedContent.getContent());
            byte[] decoded = decoder.decode(ed);
            if (messageType == MessageType.GET_CERT) {
                IssuerAndSerialNumber messageData = IssuerAndSerialNumber
                        .getInstance(decoded);
                LOGGER.debug("Finished decoding pkiMessage");
                return new GetCert(transId, senderNonce, messageData);
            } else if (messageType == MessageType.GET_CERT_INITIAL) {
                IssuerAndSubject messageData = new IssuerAndSubject(decoded);
                LOGGER.debug("Finished decoding pkiMessage");
                return new GetCertInitial(transId, senderNonce, messageData);
            } else if (messageType == MessageType.GET_CRL) {
                IssuerAndSerialNumber messageData = IssuerAndSerialNumber
                        .getInstance(decoded);
                LOGGER.debug("Finished decoding pkiMessage");
                return new GetCrl(transId, senderNonce, messageData);
            } else {
                PKCS10CertificationRequest messageData;
                try {
                    messageData = new PKCS10CertificationRequest(decoded);
                } catch (IOException e) {
                    throw new MessageDecodingException(e);
                }
                LOGGER.debug("Finished decoding pkiMessage");
                return new PkcsReq(transId, senderNonce, messageData);
            }
        }
    }

    private void validate(final CMSSignedData pkiMessage) {
        SignedData sd = SignedData.getInstance(pkiMessage.toASN1Structure()
                .getContent());
        LOGGER.debug("pkiMessage version: {}", sd.getVersion());
        LOGGER.debug("pkiMessage contentInfo contentType: {}", sd
                .getEncapContentInfo().getContentType());
    }

    private ASN1ObjectIdentifier toOid(final ScepObjectIdentifier oid) {
        return new ASN1ObjectIdentifier(oid.id());
    }

    private CMSEnvelopedData getEnvelopedData(final Object bytes)
            throws MessageDecodingException {
        // We expect the byte array to be a sequence
        // ... and that sequence to be a ContentInfo (but might be the
        // EnvelopedData)
        try {
            return new CMSEnvelopedData((byte[]) bytes);
        } catch (CMSException e) {
            throw new MessageDecodingException(e);
        }
    }

    private Nonce toNonce(final Attribute attr) {
        // Sometimes we don't get a sender nonce.
        if (attr == null) {
            return null;
        }
        final DEROctetString octets = (DEROctetString) attr.getAttrValues()
                .getObjectAt(0);

        return new Nonce(octets.getOctets());
    }

    private MessageType toMessageType(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return MessageType.valueOf(Integer.valueOf(string.getString()));
    }

    private TransactionId toTransactionId(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return new TransactionId(string.getOctets());
    }

    private PkiStatus toPkiStatus(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return PkiStatus.valueOf(Integer.valueOf(string.getString()));
    }

    private FailInfo toFailInfo(final Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return FailInfo.valueOf(Integer.valueOf(string.getString()));
    }
}
