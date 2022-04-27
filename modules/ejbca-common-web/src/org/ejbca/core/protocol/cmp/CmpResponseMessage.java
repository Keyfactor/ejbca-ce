/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.util.CertTools;

/**
 * CMP certificate response message.
 */
public class CmpResponseMessage implements CertificateResponseMessage {

    /**
     * Determines if a de-serialized file is compatible with this class.
     * 
     * Maintainers must change this value if and only if the new version of this class is not compatible with old versions. See Sun docs for <a
     * href=http://java.sun.com/products/jdk/1.1/docs/guide /serialization/spec/version.doc.html> details. </a>
     * 
     */
    static final long serialVersionUID = 10003L;

    private static final Logger log = Logger.getLogger(CmpResponseMessage.class);

    /** The encoded response message */
    private byte[] responseMessage = null;

    /** status for the response */
    private ResponseStatus status = ResponseStatus.SUCCESS;

    /** Possible fail information in the response. Defaults to 'badRequest (2)'. */
    private FailInfo failInfo = FailInfo.BAD_REQUEST;

    /** Possible clear text error information in the response. Defaults to null. */
    private String failText = null;

    /**
     * SenderNonce. This is base64 encoded bytes
     */
    private String senderNonce = null;
    /**
     * RecipientNonce in a response is the senderNonce from the request. This is base64 encoded bytes
     */
    private String recipientNonce = null;

    /** transaction id */
    private String transactionId = null;

    /** Default digest algorithm for CMP response message, can be overridden */
    private String digest  = CMSSignedGenerator.DIGEST_SHA256;
    /** The default provider is BC, if nothing else is specified when setting SignKeyInfo */
    private String provider = BouncyCastleProvider.PROVIDER_NAME;

    /** Certificate to be in certificate response message, not serialized */
    private transient Certificate cert = null;
    /** The CA certificate to be included in the response message to be used to verify the end entity certificate */
    private transient List<Certificate> cacert = new ArrayList<Certificate>();
    /** Include the signing CA certificate at index 0 in the caPubs field. */
    private transient boolean includeCaCert = true;
    /** Certificate for the signer of the response message (CA) */
    private transient Collection<Certificate> signCertChain = null;
    /** Additions CA certificate for the outer PKI response message extraCerts field. */
    private transient Collection<Certificate> extraCerts = new ArrayList<Certificate>();
    /** Private key used to sign the response message */
    private transient PrivateKey signKey = null;
    /** The request message this response is for */
    private transient ICrmfRequestMessage reqMsg;
    /** used to choose response body type */
    private transient int requestType;
    /** used to match request with response */
    private transient int requestId;

    private transient int pbeIterationCount = 1024;
    private transient String pbeDigestAlg = null;
    private transient String pbeMacAlg = null;
    private transient String pbeKeyId = null;
    private transient String pbeKey = null;
    private transient boolean implicitConfirm = false;
    private transient CertificateData certificateData;
    private transient Base64CertData base64CertData;

    @Override
    public CertificateData getCertificateData() {
        return certificateData;
    }
    
    @Override
    public void setCertificateData(CertificateData certificateData) {
        if (certificateData != null) {
            this.certificateData = new CertificateData(certificateData);
        } else {
            this.certificateData = null;
        }
    }
    
    @Override
    public Base64CertData getBase64CertData() {
        return base64CertData;
    }
    
    @Override
    public void setBase64CertData(final Base64CertData base64CertData) {
        if (base64CertData != null) {
            this.base64CertData = new Base64CertData(base64CertData);
        } else {
            this.base64CertData = null;
        }
    }
    
    @Override
    public Certificate getCertificate() {
        try {
            return CertTools.getCertfromByteArray(cert.getEncoded(), Certificate.class);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not encode certificate. This should not happen", e);
        } catch (CertificateException e) {
            throw new IllegalStateException("Response was created without containing valid certificate. This should not happen", e);
        }
    }

    @Override
    public void setCertificate(Certificate cert) {
        this.cert = cert;
    }

    @Override
    public void setCrl(CRL crl) {
    }

    @Override
    public void setIncludeCACert(boolean includeCaCert) {
        this.includeCaCert = includeCaCert;
    }

    @Override
    public void setCACert(Certificate cACert) {
        this.cacert.clear();
        if (includeCaCert) {
            this.cacert.add(cACert);
        }
    }

    @Override
    public byte[] getResponseMessage() {
        return responseMessage;
    }

    @Override
    public void setStatus(ResponseStatus status) {
        this.status = status;
    }

    @Override
    public ResponseStatus getStatus() {
        return status;
    }

    @Override
    public void setFailInfo(FailInfo failInfo) {
        this.failInfo = failInfo;
    }

    @Override
    public FailInfo getFailInfo() {
        return failInfo;
    }

    @Override
    public void setFailText(String failText) {
        this.failText = failText;
    }

    @Override
    public String getFailText() {
        return this.failText;
    }

    @Override
    public boolean create() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean ret = false;
        // Some general stuff, common for all types of messages
        String issuer = null;
        String subject = null;
        Certificate signCert = null;
        if (CollectionUtils.isNotEmpty(signCertChain)) {
            signCert = signCertChain.iterator().next();            
        }
        if (cert != null) {
            final X509Certificate x509cert = (X509Certificate) cert;
            issuer = x509cert.getIssuerDN().getName();
            subject = x509cert.getSubjectDN().getName();
        } else if (signCert != null) {
            issuer = ((X509Certificate) signCert).getSubjectDN().getName();
            subject = "CN=fooSubject";
        } else {
            issuer = "CN=fooIssuer";
            subject = "CN=fooSubject";
        }

		final GeneralName issuerName = new GeneralName(new X500Name(issuer));
		final GeneralName subjectName = new GeneralName(new X500Name(subject));
		final PKIHeaderBuilder myPKIHeader = CmpMessageHelper.createPKIHeaderBuilder(issuerName, subjectName, senderNonce, recipientNonce, transactionId);
		PKIBody myPKIBody = null;
		final PKIMessage myPKIMessage;

        try {
            if (status.equals(ResponseStatus.SUCCESS)) {
                if (cert != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Creating a CertRepMessage 'accepted'");
                    }
                    PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(PKIStatus.granted); // 0 = accepted
                    ASN1InputStream certASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(cert.getEncoded()));
                    try {
                        try {
                            CMPCertificate cmpcert = CMPCertificate.getInstance(certASN1InputStream.readObject());
                            CertOrEncCert retCert = new CertOrEncCert(cmpcert);
                            CertifiedKeyPair myCertifiedKeyPair;
                            // If the requestMessage has a server generated key pair, and the requestMessage had a public key 
                            // "controls.protocolEncrKey" to encrypt the private key with
                            if (reqMsg != null && reqMsg.getServerGenKeyPair() != null && reqMsg.getProtocolEncrKey() != null) {
                                    log.debug("CMP request had a server generated key pair and controls.protocolEncrKey which we will use to encrypt the private key in the response");
                                    final KeyPair kp = reqMsg.getServerGenKeyPair();
                                    final PublicKey protocolEncrKey = reqMsg.getProtocolEncrKey();
                                    if (!protocolEncrKey.getAlgorithm().equals("RSA")) {
                                        final String msg = "CMP request had a controls.protocolEncrKey that is not an RSA key, can not create response: "+protocolEncrKey.getAlgorithm();
                                        log.debug(msg);
                                        throw new InvalidKeyException(msg);                                        
                                    }
                                    // JceAsymmetricKeyWrapper sets kp.getPublic to be the key used for wrapping
                                    // JceCRMFEncryptorBuilder sets AES256 CBC to be the symmetric encryption algorithm used 
                                    JcaEncryptedValueBuilder encBldr = new JcaEncryptedValueBuilder(
                                            new JceAsymmetricKeyWrapper(protocolEncrKey).setProvider(BouncyCastleProvider.PROVIDER_NAME),
                                            new JceCRMFEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build());
                                    // encBldr.build encrypts the privateKey using the wrapper above, i.e. encrypted with AES128_CBC with the symmkey wrapped with kp.getPublic
                                    // encBldr.build will encode the private key as a PrivateKeyInfo from RFC 5958
                                    myCertifiedKeyPair = new CertifiedKeyPair(retCert, encBldr.build(kp.getPrivate()), null);                                    
                            } else if (reqMsg != null && reqMsg.getServerGenKeyPair() != null && reqMsg.getProtocolEncrKey() == null) {
                                // We should actually check this in the outer CMP layers before trying to create a real certificate response, but of course we have to check in here as well
                                final String msg = "CMP request had a server generated key pair but no controls.protocolEncrKey, can not create response";
                                log.debug(msg);
                                throw new InvalidKeyException(msg);
                            } else {
                                myCertifiedKeyPair = new CertifiedKeyPair(retCert);                                
                            }
                            // If we have server generated keys, add privateKey
                            final CertResponse certResponse = new CertResponse(new ASN1Integer(requestId), myPKIStatusInfo, myCertifiedKeyPair, null);
                            final CertResponse[] certResponses = { certResponse };
                            
                            // Add the user certificates signing CA certificate (at index 0) and the others by the CMP configuration to the CMP 
                            // response 'caPubs' field (added previously to the response with CertificateResponseMessage.addAdditionalCaCertificates().
                            final List<CMPCertificate> caPubs = new ArrayList<CMPCertificate>();
                            for (Certificate certificate : this.cacert) {
                                try (ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(certificate.getEncoded()));) {
                                    caPubs.add(CMPCertificate.getInstance(stream.readObject()));
                                }
                            }

                            final CertRepMessage myCertRepMessage = new CertRepMessage(caPubs.size() > 0 ? caPubs.toArray( new CMPCertificate[] {}) : null, certResponses);
                            int respType = requestType + 1; // 1 = intitialization response, 3 = certification response etc
                            if (log.isDebugEnabled()) {
                                log.debug("Creating response body of type " + respType);
                            }
                            myPKIBody = new PKIBody(respType, myCertRepMessage);
                            // All good, see if we should add implicitConfirm
                            if (implicitConfirm) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Adding implicitConform (RFC4210 section 5.1.1.1) to CMP response message with transId: "+transactionId);
                                }
                                final InfoTypeAndValue genInfo = new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm);
                                myPKIHeader.setGeneralInfo(genInfo);                                
                            }
                        } finally {
                            certASN1InputStream.close();
                        }
                    } catch (IOException e) {
                        throw new IllegalStateException("Unexpected IOException caught.", e);
                    }
                }
            } else if (status.equals(ResponseStatus.FAILURE)) {
                if (log.isDebugEnabled()) {
                    log.debug("Creating a CertRepMessage 'rejected'");
                }
                // Create a failure message
                ASN1EncodableVector statusInfoV = new ASN1EncodableVector();
                statusInfoV.add(ASN1Integer.getInstance(PKIStatus.rejection.toASN1Primitive()));
                if (failText != null) {
                    statusInfoV.add(new PKIFreeText(new DERUTF8String(failText)));
                }
                statusInfoV.add(CmpMessageHelper.getPKIFailureInfo(failInfo.intValue()));
                PKIStatusInfo myPKIStatusInfo = PKIStatusInfo.getInstance(ASN1Sequence.getInstance(new DERSequence(statusInfoV)));
                myPKIBody = CmpMessageHelper.createCertRequestRejectBody(myPKIStatusInfo, requestId, requestType);
                
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Creating a 'waiting' message?");
                }
                // Not supported, lets create a PKIError failure instead
                // Create a failure message
                ASN1EncodableVector statusInfoV = new ASN1EncodableVector();
                statusInfoV.add(PKIStatus.rejection); // 2 = rejection
                if (failText != null) {
                    statusInfoV.add(new PKIFreeText(new DERUTF8String(failText)));
                }
                statusInfoV.add(CmpMessageHelper.getPKIFailureInfo(failInfo.intValue()));
                PKIStatusInfo myPKIStatusInfo = PKIStatusInfo.getInstance(new DERSequence(statusInfoV));
                
                ErrorMsgContent myErrorContent = new ErrorMsgContent(myPKIStatusInfo);
                myPKIBody = new PKIBody(23, myErrorContent); // 23 = error                
            }
            
            if ((pbeKeyId != null) && (pbeKey != null) && (pbeDigestAlg != null) && (pbeMacAlg != null)) {
                myPKIHeader.setProtectionAlg(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac));
                PKIHeader header = myPKIHeader.build();
                CMPCertificate [] extraCertsList = null;
                if (!extraCerts.isEmpty()) {
                    extraCertsList = new CMPCertificate[extraCerts.size()];
                    if (log.isDebugEnabled()) {
                        log.debug("Adding extraCerts to PBE protected message: " + extraCerts.size());
                    }
                    int i = 0;
                    for (Certificate certificate : extraCerts) {
                        extraCertsList[i++] = CMPCertificate.getInstance(((X509Certificate)certificate).getEncoded());
                    }
                }
                myPKIMessage = new PKIMessage(header, myPKIBody, null, extraCertsList);
                responseMessage = CmpMessageHelper.protectPKIMessageWithPBE(myPKIMessage, pbeKeyId, pbeKey, pbeDigestAlg, pbeMacAlg,
                        pbeIterationCount);
            } else {
                myPKIHeader.setProtectionAlg(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digest)));
                if (signCert != null) {
                	// set sender Key ID as well when the response is signed, so the signer (CA) can have multiple certificates out there
                	// with the same DN but different keys
                    myPKIHeader.setSenderKID(CertTools.getSubjectKeyId(signCert));
                }
                PKIHeader header = myPKIHeader.build();
                final Collection<Certificate> extraCertsList = new ArrayList<Certificate>(signCertChain);
                for (Certificate extraCert : extraCerts) {
                    if (log.isDebugEnabled()) {
                        log.debug("Adding extraCerts to Signature protected message: " + extraCerts.size());
                    }
                    if (!extraCertsList.contains(extraCert)) {
                        extraCertsList.add(extraCert);
                    }
                }
                myPKIMessage = new PKIMessage(header, myPKIBody);
                responseMessage = CmpMessageHelper.signPKIMessage(myPKIMessage, extraCertsList, signKey, digest, provider);
            }
            
            ret = true;
            
        } catch (CertificateEncodingException e) {
            log.error("Error creating CertRepMessage: ", e);
        } catch (InvalidKeyException e) {
            log.error("Error creating CertRepMessage: ", e);
        } catch (NoSuchProviderException e) {
            log.error("Error creating CertRepMessage: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("Error creating CertRepMessage: ", e);
        } catch (SecurityException e) {
            log.error("Error creating CertRepMessage: ", e);
        } catch (SignatureException e) {
            log.error("Error creating CertRepMessage: ", e);
        } catch (CRMFException e) {
            log.error("Error creating CertRepMessage: ", e);
        }

        return ret;
    }

    @Override
    public boolean requireSignKeyInfo() {
        return true;
    }

    @Override
    public void setSignKeyInfo(Collection<Certificate> certs, PrivateKey key, String provider) {
        this.signCertChain = certs;
        this.signKey = key;
        if (provider != null) {
            this.provider = provider;
        }
    }

    @Override
    public void setSenderNonce(String senderNonce) {
        this.senderNonce = senderNonce;
    }

    @Override
    public void setRecipientNonce(String recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    @Override
    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    @Override
    public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
    }

    @Override
    public void setPreferredDigestAlg(String digest){
        if(!StringUtils.isEmpty(digest)) { 
            this.digest = digest;
        }
    }

    @Override
    public void setRequestType(int reqtype) {
        this.requestType = reqtype;
    }

    @Override
    public void setRequestId(int reqid) {
        this.requestId = reqid;
    }

    @Override
    public void setProtectionParamsFromRequest(RequestMessage reqMsg) {
        if (reqMsg instanceof ICrmfRequestMessage) {
            ICrmfRequestMessage crmf = (ICrmfRequestMessage) reqMsg;
            this.reqMsg = crmf;
            this.pbeIterationCount = crmf.getPbeIterationCount();
            this.pbeDigestAlg = crmf.getPbeDigestAlg();
            this.pbeMacAlg = crmf.getPbeMacAlg();
            this.pbeKeyId = crmf.getPbeKeyId();
            this.pbeKey = crmf.getPbeKey();
            this.implicitConfirm = crmf.isImplicitConfirm();
        }
    }

    @Override
    public void addAdditionalCaCertificates(final List<Certificate> certificates) {
        if (CollectionUtils.isNotEmpty(certificates)) {
            for (Certificate certificate : certificates) {
                if (!this.cacert.contains(certificate)) {
                    this.cacert.add( certificate);
                }
            }
        }
    }

    @Override
    public void addAdditionalResponseExtraCertsCertificates(final List<Certificate> certificates) {
        if (CollectionUtils.isNotEmpty(certificates)) {
            for (Certificate certificate : certificates) {
                if (!this.extraCerts.contains(certificate)) {
                    this.extraCerts.add(certificate);
                }
            }
        }
    }
}
