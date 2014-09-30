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

package org.ejbca.core.protocol.scep;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;


/**
 * Class to handle SCEP request messages sent to the CA. 
 *
 * @version $Id$
 */
public class ScepRequestMessage extends PKCS10RequestMessage implements RequestMessage {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
	static final long serialVersionUID = -235623330828902051L;

    private static Logger log = Logger.getLogger(ScepRequestMessage.class);

    public static final String id_Verisign = "2.16.840.1.113733";
    public static final String id_pki = id_Verisign + ".1";
    public static final String id_attributes = id_pki + ".9";
    public static final String id_messageType = id_attributes + ".2";
    public static final String id_pkiStatus = id_attributes + ".3";
    public static final String id_failInfo = id_attributes + ".4";
    public static final String id_senderNonce = id_attributes + ".5";
    public static final String id_recipientNonce = id_attributes + ".6";
    public static final String id_transId = id_attributes + ".7";
    public static final String id_extensionReq = id_attributes + ".8";

    /** Raw form of the Scep message */
    private byte[] scepmsg;

    /**
     * The messageType attribute specify the type of operation performed by the transaction. This
     * attribute is required in all PKI messages. Currently, the following message types are
     * defined: 
     * PKCSReq (19)  -- Permits use of PKCS#10 certificate request 
     * CertRep (3)   -- Response to certificate or CRL request 
     * GetCertInitial (20)  -- Certificate polling in manual enrollment 
     * GetCert (21)  -- Retrieve a certificate 
     * GetCRL  (22)  -- Retrieve a CRL
     */
    private int messageType = 0;
    public static int SCEP_TYPE_PKCSREQ = 19;
    public static int SCEP_TYPE_GETCERTINITIAL = 20; // Used when request is in pending state.
    public static int SCEP_TYPE_GETCRL = 22;
    public static int SCEP_TYPE_GETCERT = 21;

    /**
     * SenderNonce in a request is used as recipientNonce when the server sends back a reply to the
     * client. This is base64 encoded bytes
     */
    private String senderNonce = null;

    /** transaction id */
    private String transactionId = null;

    /** request key info, this is the requestors self-signed certificate used to identify the senders public key */
    private byte[] requestKeyInfo = null;

    /** Type of error */
    private int error = 0;

    /** Error text */
    private String errorText = null;
    
    /** Issuer DN the message is sent to (CAs Issuer DN), contained in the 
     * request as recipientInfo.issuerAndSerialNumber in EnvelopeData part */
    private transient String issuerDN = null;
    
    /** SerialNumber of the CA cert of the CA the message is sent to, contained in the 
     * request as recipientInfo.issuerAndSerialNumber in EnvelopeData part */
    private transient BigInteger serialNo = null;

    /** Signed data, the whole enchilada to to speak... */
    private transient SignedData sd = null;

    /** Enveloped data, carrying the 'beef' of the request */
    private transient EnvelopedData envData = null;

    /** Enveloped data, carrying the 'beef' of the request */
    private transient ContentInfo envEncData = null;

    /** Private key used for decryption. */
    private transient PrivateKey privateKey = null;
    /** JCE Provider used when decrypting with private key. Default provider is BC. */
    private transient String jceProvider = "BC";

    /** IssuerAndSerialNUmber for CRL request */
    private transient IssuerAndSerialNumber issuerAndSerno = null;

    /** preferred digest algorithm to use in replies, if applicable.
     *  Defaults to CMSSignedGenerator.DIGEST_MD5 for SCEP messages. If SCEP request is 
     * digested with SHA1 it is set to SHA1 though. This is only for backwards compatibility issues, as specified in a SCEP draft.
     * Modern request/responses will use SHA-1.
     */
    private transient String preferredDigestAlg = CMSSignedGenerator.DIGEST_MD5;

	private transient Certificate signercert;

    /**
     * Constructs a new SCEP/PKCS7 message handler object.
     *
     * @param msg The DER encoded PKCS7 request.
     * @param incCACert if the CA certificate should be included in the response or not
     *
     * @throws IOException if the request can not be parsed.
     */
    public ScepRequestMessage(byte[] msg, boolean incCACert) throws IOException {
    	if (log.isTraceEnabled()) {
    		log.trace(">ScepRequestMessage");
    	}
        this.scepmsg = msg;
        this.includeCACert = incCACert;
        init();
        if (log.isTraceEnabled()) {
        	log.trace("<ScepRequestMessage");
        }
    }

    private void init() throws IOException {
    	if (log.isTraceEnabled()) {
    		log.trace(">init");
    	}
        try {
            CMSSignedData csd = new CMSSignedData(scepmsg);
            SignerInformationStore infoStore = csd.getSignerInfos();
            @SuppressWarnings("unchecked")
            Collection<SignerInformation> signers = infoStore.getSigners();
            Iterator<SignerInformation> iter = signers.iterator();
            if (iter.hasNext()) {
            	SignerInformation si = (SignerInformation)iter.next();
            	preferredDigestAlg = si.getDigestAlgOID();
            	log.debug("Set "+ preferredDigestAlg+" as preferred digest algorithm for SCEP");
            }        	
        } catch (CMSException e) {
        	// ignore, use default digest algo
        	log.error("CMSException trying to get preferred digest algorithm: ", e);
        }
        // Parse and verify the integrity of the PKIOperation message PKCS#7
        /* If this would have been done using the newer CMS it would have made me so much happier... */
        ASN1InputStream seqAsn1InputStream = new ASN1InputStream(new ByteArrayInputStream(scepmsg));
        ASN1Sequence seq = null;
        try {
            seq = (ASN1Sequence) seqAsn1InputStream.readObject();
        } finally {
            seqAsn1InputStream.close();
        }
        ContentInfo ci = new ContentInfo(seq);
        String ctoid = ci.getContentType().getId();

        if (ctoid.equals(CMSObjectIdentifiers.signedData.getId())) {
            // This is SignedData so it is a pkcsCertReqSigned,
            //  pkcsGetCertInitialSigned, pkcsGetCertSigned, pkcsGetCRLSigned
            // (could also be pkcsRepSigned or certOnly, but we don't receive them on the server side
            // Try to find out what kind of message this is
            sd = SignedData.getInstance((ASN1Sequence) ci.getContent());	

            // Get self signed cert to identify the senders public key
            ASN1Set certs = sd.getCertificates();
            if (certs.size() > 0) {
                // There should be only one...
                ASN1Encodable dercert = certs.getObjectAt(0);
                if (dercert != null) {
                    // Requestors self-signed certificate is requestKeyInfo
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    DEROutputStream dOut = new DEROutputStream(bOut);
                    dOut.writeObject(dercert);
                    if (bOut.size() > 0) {
                        requestKeyInfo = bOut.toByteArray();
                        //Create Certificate used for debugging
                        try {
							signercert = CertTools.getCertfromByteArray(requestKeyInfo);
							if (log.isDebugEnabled()) {
								log.debug("requestKeyInfo is SubjectDN: " + CertTools.getSubjectDN(signercert) +
										", Serial=" + CertTools.getSerialNumberAsString(signercert) +
										"; IssuerDN: "+ CertTools.getIssuerDN(signercert).toString());								
							}
						} catch (CertificateException e) {
							log.error("Error parsing requestKeyInfo : ", e);
						}
                        
                    }
                }
            }

            Enumeration<?> sis = sd.getSignerInfos().getObjects();

            if (sis.hasMoreElements()) {
                SignerInfo si = new SignerInfo((ASN1Sequence) sis.nextElement());
                Enumeration<?> attr = si.getAuthenticatedAttributes().getObjects();

                while (attr.hasMoreElements()) {
                    Attribute a = Attribute.getInstance((ASN1Sequence) attr.nextElement());
                    if (log.isDebugEnabled()) {
                    	log.debug("Found attribute: " + a.getAttrType().getId());
                    }
                    if (a.getAttrType().getId().equals(id_senderNonce)) {
                        Enumeration<?> values = a.getAttrValues().getObjects();
                        ASN1OctetString str = ASN1OctetString.getInstance(values.nextElement());
                        senderNonce = new String(Base64.encode(str.getOctets(), false));
                        if (log.isDebugEnabled()) {
                        	log.debug("senderNonce = " + senderNonce);
                        }
                    }
                    if (a.getAttrType().getId().equals(id_transId)) {
                        Enumeration<?> values = a.getAttrValues().getObjects();
                        DERPrintableString str = DERPrintableString.getInstance(values.nextElement());
                        transactionId = str.getString();
                        if (log.isDebugEnabled()) {
                        	log.debug("transactionId = " + transactionId);
                        }
                    }
                    if (a.getAttrType().getId().equals(id_messageType)) {
                        Enumeration<?> values = a.getAttrValues().getObjects();
                        DERPrintableString str = DERPrintableString.getInstance(values.nextElement());
                        messageType = Integer.parseInt(str.getString());
                        if (log.isDebugEnabled()) {
                        	log.debug("messagetype = " + messageType);
                        }
                    }
                }
            }

            // If this is a PKCSReq
            if ((messageType == ScepRequestMessage.SCEP_TYPE_PKCSREQ) || (messageType == ScepRequestMessage.SCEP_TYPE_GETCRL) || (messageType == ScepRequestMessage.SCEP_TYPE_GETCERTINITIAL)) {
                // Extract the contents, which is an encrypted PKCS10 if messageType == 19
                // , and an encrypted issuer and subject if messageType == 20 (not extracted)
                // and an encrypted IssuerAndSerialNumber if messageType == 22
                ci = sd.getEncapContentInfo();
                ctoid = ci.getContentType().getId();

                if (ctoid.equals(CMSObjectIdentifiers.data.getId())) {
                    ASN1OctetString content = (ASN1OctetString) ci.getContent();
                    if (log.isDebugEnabled()) {
                    	log.debug("envelopedData is " + content.getOctets().length + " bytes.");
                    }
                    ASN1InputStream seq1Asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(content.getOctets()));
                    ASN1Sequence seq1 = null;
                    try {
                        seq1 = (ASN1Sequence) seq1Asn1InputStream.readObject();
                    } finally {
                        seq1Asn1InputStream.close();
                    }
                    envEncData = new ContentInfo(seq1);
                    ctoid = envEncData.getContentType().getId();

                    if (ctoid.equals(CMSObjectIdentifiers.envelopedData.getId())) {
                        envData = new EnvelopedData((ASN1Sequence) envEncData.getContent());
                        ASN1Set recipientInfos = envData.getRecipientInfos();
                        Enumeration<?> e = recipientInfos.getObjects();
                        while (e.hasMoreElements()) {
                            RecipientInfo ri = RecipientInfo.getInstance(e.nextElement());
                            KeyTransRecipientInfo recipientInfo = KeyTransRecipientInfo.getInstance(ri.getInfo());
                            RecipientIdentifier rid = recipientInfo.getRecipientIdentifier();
                            IssuerAndSerialNumber iasn = IssuerAndSerialNumber.getInstance(rid.getId());
                            issuerDN = iasn.getName().toString();
                            serialNo = iasn.getSerialNumber().getValue();
                            if (log.isDebugEnabled()) {
                            	log.debug("IssuerDN: " + issuerDN);
                            	log.debug("SerialNumber: " + iasn.getSerialNumber().getValue().toString(16));
                            }
                        }
                    } else {
                        errorText = "EncapsulatedContentInfo does not contain PKCS7 envelopedData: ";
                        log.error(errorText + ctoid);
                        error = 2;
                    }
                } else {
                    errorText = "EncapsulatedContentInfo is not of type 'data': ";
                    log.error(errorText + ctoid);
                    error = 3;
                }
            } else {
                errorText = "This is not a certification request!";
                log.error(errorText);
                error = 4;
            }
        } else {
            errorText = "PKCSReq does not contain 'signedData': ";
            log.error(errorText + ctoid);
            error = 1;
        }

        log.trace("<init");
    } // init

    private void decrypt() throws CMSException, NoSuchProviderException, GeneralSecurityException, IOException {
        if (log.isTraceEnabled()) {
        	log.trace(">decrypt");
        }
        // Now we are getting somewhere (pheew),
        // Now we just have to get the damn key...to decrypt the PKCS10
        if (privateKey == null) {
            errorText = "Need private key to decrypt!";
            error = 5;
            log.error(errorText);
            return;
        }

        if (envEncData == null) {
            errorText = "No enveloped data to decrypt!";
            error = 6;
            log.error(errorText);
            return;
        }

        CMSEnvelopedData ed = new CMSEnvelopedData(envEncData);
        RecipientInformationStore recipients = ed.getRecipientInfos();
        @SuppressWarnings("unchecked")
        Collection<RecipientInformation> c = recipients.getRecipients();
        Iterator<RecipientInformation> it = c.iterator();
        byte[] decBytes = null;

        while (it.hasNext()) {
            RecipientInformation recipient = (RecipientInformation) it.next();
            if (log.isDebugEnabled()) {
            	log.debug("Privatekey : " + privateKey.getAlgorithm());
            }
            JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(privateKey);
            rec.setProvider(jceProvider); // Use the crypto token provides for asymmetric key operations
            rec.setContentProvider("BC"); // Use BC for the symmetric key operations
            decBytes = recipient.getContent(rec);
            break;
        }

        if (messageType == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
            pkcs10 = new JcaPKCS10CertificationRequest(decBytes);
            if (log.isDebugEnabled()) {
            	log.debug("Successfully extracted PKCS10:"+new String(Base64.encode(pkcs10.getEncoded())));
            }
        }
        if (messageType == ScepRequestMessage.SCEP_TYPE_GETCRL) {
            ASN1InputStream derAsn1InputStream = new ASN1InputStream(new ByteArrayInputStream(decBytes));
            ASN1Primitive derobj = null;
            try {
                derobj = derAsn1InputStream.readObject();
            } finally {
                derAsn1InputStream.close();
            }
            issuerAndSerno = IssuerAndSerialNumber.getInstance(derobj);
            log.debug("Successfully extracted IssuerAndSerialNumber.");
        }
        if (log.isTraceEnabled()) {
        	log.trace("<decrypt");
        }
    } // decrypt

    @Override
    public PublicKey getRequestPublicKey() {
        if (log.isTraceEnabled()) {
        	log.trace(">getRequestPublicKey()");
        }
        PublicKey ret = null;
        try {
            if (envData == null) {
                init();
                decrypt();
            }
            ret = super.getRequestPublicKey();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getRequestPublicKey()");
        }
        return ret;
    }

    @Override
    public String getRequestAltNames() {
        if (log.isTraceEnabled()) {
        	log.trace(">getRequestAltNames()");
        }
        String ret = null;
        try {
            if (envData == null) {
                init();
                decrypt();
            }
            ret = super.getRequestAltNames();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getRequestAltNames()");
        }
        return ret;
    }

    @Override
    public boolean verify() {
        if (log.isTraceEnabled()) {
        	log.trace(">verify()");
        }
        boolean ret = false;
        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }
            ret = super.verify();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<verify()");
        }
        return ret;
    }

    @Override
    public String getPassword() {
        if (log.isTraceEnabled()) {
        	log.trace(">getPassword()");
        }
        String ret = null;
        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }
            ret = super.getPassword();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getPassword()");
        }
        return ret;
    }

    @Override
    public String getUsername() {
        if (log.isTraceEnabled()) {
        	log.trace(">getUsername()");
        }
        String ret = null;
        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }
            ret = super.getUsername();
            if (ret == null) {
                // For Cisco boxes they can sometimes send DN as SN instead of CN
                String name = CertTools.getPartFromDN(getRequestDN(), "SN");
                if (name == null) {
                    log.error("No SN in DN: "+getRequestDN());
                    return null;
                }
                // Special if the DN contains unstructuredAddress where it becomes: 
                // SN=1728668 + 1.2.840.113549.1.9.2=pix.primekey.se
                // We only want the SN and not the oid-part.
                int index = name.indexOf(' ');
                ret = name; 
                if (index > 0) {
                    ret = name.substring(0,index);        
                } else {
                    // Perhaps there is no space, only +
                    index = name.indexOf('+');
                    if (index > 0) {
                        ret = name.substring(0, index);
                    }            	
                }
            }
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getUsername(): " + ret);
        }
        return ret;
    }

    @Override
    public String getIssuerDN() {
        if (log.isTraceEnabled()) {
        	log.trace(">getIssuerDN()");
        }
        String ret = null;
        try {
            if (envData == null) {
                init();
            }
            ret = issuerDN;
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getIssuerDN(): " + ret);
        }
        return ret;
    }

    @Override
    public BigInteger getSerialNo() {
        if (log.isTraceEnabled()) {
        	log.trace(">getSerialNo()");
        }
        // Use another method to do the decryption etc...
        getIssuerDN();
        return serialNo;
    }
    
    @Override
    public String getCRLIssuerDN() {
        if (log.isTraceEnabled()) {
        	log.trace(">getCRLIssuerDN()");
        }
        String ret = null;
        try {
            if (issuerAndSerno == null) {
                init();
                decrypt();
            }
            ret = CertTools.stringToBCDNString(issuerAndSerno.getName().toString());
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getCRLIssuerDN(): " + ret);
        }
        return ret;
    }

    @Override
    public BigInteger getCRLSerialNo() {
        if (log.isTraceEnabled()) {
        	log.trace(">getCRLSerialNo()");
        }
        BigInteger ret = null;
        try {
            if (issuerAndSerno == null) {
                init();
                decrypt();
            }
            ret = issuerAndSerno.getSerialNumber().getValue();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getCRLSerialNo(): " + ret);
        }
        return ret;
    }

    @Override
    public String getRequestDN() {
        if (log.isTraceEnabled()) {
        	log.trace(">getRequestDN()");
        }
        String ret = null;
        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }
            ret = super.getRequestDN();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getRequestDN(): " + ret);
        }
        return ret;
    }

    @Override
    public boolean requireKeyInfo() {
        return true;
    }

    @Override
    public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
        // We don't need the public key 
        // this.cert = cert;
        this.privateKey = key;
        if (provider == null) {
        	this.jceProvider = "BC";
        } else {
            this.jceProvider = provider;        	
        }
    }

    @Override
    public int getErrorNo() {
        return error;
    }

    @Override
    public String getErrorText() {
        return errorText;
    }

    @Override
    public String getSenderNonce() {
        return senderNonce;
    }

    @Override
    public String getTransactionId() {
        return transactionId;
    }

    @Override
    public byte[] getRequestKeyInfo() {
        return requestKeyInfo;
    }

    @Override
    public String getPreferredDigestAlg() {
    	return preferredDigestAlg;
    }
    
    /** Returns the type of SCEP message it is
     * 
     * @return value as defined by SCEP_TYPE_PKCSREQ, SCEP_TYPE_GETCRL, SCEP_TYPE_GETCERT  
     */
    public int getMessageType() {
        return messageType;

    }

    /**
     * Method returning the certificate used to sign the SCEP_TYPE_PKCSREQ pkcs7 request.
     * 
     * @return The certificate used for signing or null if it doesn't exist or not been initialized.
     */
    public Certificate getSignerCert(){
    	return signercert;
    }
        
} // ScepRequestMessage
