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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;

public class P10CrCertificationRequestMessage extends BaseCmpMessage implements ICrmfRequestMessage {
    
    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(P10CrCertificationRequestMessage.class);
    
    private transient JcaPKCS10CertificationRequest pc10Req = null;
    private int requestType = PKIBody.TYPE_P10_CERT_REQ;
    /** manually set username */
    private String username = null;
    private String extractUsernameComponent = null;
    private String password = null;
    /** Default CA DN */
    private String defaultCADN = null;
    protected Date notAfter = null;
    protected Date notBefore = null;
    
    /** Because PKIMessage is not serializable we need to have the serializable bytes save as well, so 
     * we can restore the PKIMessage after serialization/deserialization. */
    private byte[] pkimsgbytes = null;
    
    /** preferred digest algorithm to use in replies, if applicable */
    private String preferredDigestAlg = CMSSignedGenerator.DIGEST_SHA256;

    public P10CrCertificationRequestMessage(final PKIMessage pkiMessage, final String defaultCADN, final String extractUsernameComponent) {
        super();
        try {
            this.pkimsgbytes = pkiMessage.toASN1Primitive().getEncoded();
        } catch (IOException e) {
            log.error("Error getting encoded bytes from PKIMessage: ", e);
        }
        
        setMessage(pkiMessage);

        this.defaultCADN = defaultCADN;
        this.extractUsernameComponent = extractUsernameComponent;

        init();
    }
    
    private void init() {
        final PKIBody pkiBody = getPKIMessage().getBody();
        final PKIHeader pkiHeader = getPKIMessage().getHeader();
        requestType = pkiBody.getType();

        this.pc10Req = new JcaPKCS10CertificationRequest((CertificationRequest) pkiBody.getContent());

        setTransactionId(getBase64FromAsn1OctetString(pkiHeader.getTransactionID()));
        setSenderNonce(getBase64FromAsn1OctetString(pkiHeader.getSenderNonce()));
        setRecipient(pkiHeader.getRecipient());
        setSender(pkiHeader.getSender());
    }


    public PKIMessage getPKIMessage() {
        if (getMessage() == null) {
            setMessage(PKIMessage.getInstance(pkimsgbytes));
        }
        return getMessage();
    }
    
    // Returns the subject DN from the request, used from CrmfMessageHandler
    public String getSubjectDN() {
        String ret = null;
        final X500Name name = getRequest().getSubject();
        if (name != null) {
            ret = CertTools.stringToBCDNString(name.toString());
        }
        return ret;
    }
    
    @Override
    public String getUsername() {
        String ret = null;
        if (username != null) {
            ret = username;
        } else {
            // We can configure which part of the users DN should be used as username in EJBCA, for example CN or UID
            String component = extractUsernameComponent;
            if (StringUtils.isEmpty(component)) {
                component = "CN";
            }
            String name = CertTools.getPartFromDN(getRequestDN(), component);
            if (name == null) {
                log.error("No component " + component + " in DN: " + getRequestDN());
            } else {
                ret = name;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Username is: " + ret);
        }
        return ret;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getPassword() {
        if(password != null) {
            return this.password;
        }
        
        String pass = null;
        Attribute[] attributes = pc10Req.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
        ASN1Encodable obj = null;
        if (attributes.length == 0) {
            // See if we have it embedded in an extension request instead
            attributes = pc10Req.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attributes.length == 0) {
                return null;
            }
            if (log.isDebugEnabled()) {
                log.debug("got extension request");
            }
            ASN1Set values = attributes[0].getAttrValues();
            if (values.size() == 0) {
                return null;
            }
            Extensions exts = Extensions.getInstance(values.getObjectAt(0));
            Extension ext = exts.getExtension(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            if (ext == null) {
                if (log.isDebugEnabled()) {
                    log.debug("no challenge password extension");
                }
                return null;
            }
            obj = ext.getExtnValue();
        } else {
            // If it is a challengePassword directly, it's just to grab the value
            ASN1Set values = attributes[0].getAttrValues();
            obj = values.getObjectAt(0);
        }

        if (obj != null) {
            ASN1String str = null;
            try {
                // Should be any DirectoryString according to RFC2985, preferably a PrintableString or UTF8String
                str = DirectoryString.getInstance((obj));
            } catch (IllegalArgumentException ie) {
                // This was not a DirectoryString type, it could then be IA5string, breaking pkcs#9 v2.0
                // but some version of openssl have been known to produce IA5strings
                str = ASN1IA5String.getInstance((obj));
            }

            if (str != null) {
                pass = str.getString();
            }
        }
        return pass;
    }

    @Override
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    @Override
    public String getIssuerDN() {
        return this.defaultCADN;
    }
    
    public void setIssuerDN(final String issuer) {
        this.defaultCADN = issuer;
    }

    @Override
    public String getCASequence() {
        return null;
    }

    @Override
    public String getRequestDN() {
        String ret = null;
        final X500Name name = getRequestX500Name();
        if (name != null) {
            ret = CertTools.stringToBCDNString(name.toString());
        }
        if (log.isDebugEnabled()) {
            log.debug("Request DN is: " + ret);
        }
        return ret;
    }

    @Override
    public X500Name getRequestX500Name() {
        X500Name name = getRequest().getSubject();

        if (name != null) {
            name = X500Name.getInstance(new CeSecoreNameStyle(), name);
        }
        if (log.isDebugEnabled()) {
            log.debug("Request X500Name is: " + name);
        }
        return name;
    }

    private PKCS10CertificationRequest getRequest() {
        if (this.pc10Req == null) {
            init();
        }
        return this.pc10Req;
    }

    @Override
    public String getRequestAltNames() {
        String requestAltName = null;

        final PKCS10CertificationRequest request = getRequest();

        final Extension sanExtension = CertTools.getExtension(request, Extension.subjectAlternativeName.getId());

        if (sanExtension != null) {
            requestAltName = CertTools.getAltNameStringFromExtension(sanExtension);
        }
        if (log.isDebugEnabled()) {
            log.debug("Request altName is: " + requestAltName);
        }
        return requestAltName;
    }

    @Override
    public Date getRequestValidityNotBefore() {
        return notBefore;
    }

    @Override
    public Date getRequestValidityNotAfter() {
        return notAfter;
    }

    @Override
    public void setRequestValidityNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    @Override
    public Extensions getRequestExtensions() {
        final Attribute[] attributes = getRequest().getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (final Attribute attribute : attributes) {
            final ASN1Set attributeValues = attribute.getAttrValues();
            if (attributeValues.size()>0) {
                return Extensions.getInstance(attributeValues.getObjectAt(0));
            }
        }
        return null;
    }

    @Override
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        final SubjectPublicKeyInfo keyInfo = getRequestSubjectPublicKeyInfo();
        if (keyInfo == null) {
            return null;
        }
        return getPublicKey(keyInfo, BouncyCastleProvider.PROVIDER_NAME);
    }

    @Override
    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        PublicKey pubKey = new JcaPKCS10CertificationRequest(getRequest()).getPublicKey();
        ContentVerifierProvider contentVerifierProvider;
        try {
            contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubKey);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Exception while createing a contect verifier!", e);
        }
        try {
            return getRequest().isSignatureValid(contentVerifierProvider);
        } catch (PKCSException e) {
            throw new IllegalStateException("Exception while trying to verity the request! ", e);
        }

    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public int getErrorNo() {
        return 0;
    }

    @Override
    public String getPreferredDigestAlg() {
        return preferredDigestAlg;
    }
    
    public void setPreferredDigestAlg(String digestAlgo) {
        if(StringUtils.isNotEmpty(digestAlgo)) {
            preferredDigestAlg = digestAlgo;
        }
    }

    @Override
    public boolean includeCACert() {
        // Adapter from interface RequestMessage.includeCACert() 
        // to BaseCmpMessage.isIncludeCaCert()
        return super.isIncludeCaCert();
    }

    @Override
    public int getRequestType() {
        return requestType;
    }

    @Override
    public int getRequestId() {
        return 0; //cerReqId is undefined for p10cr request types, setting it to zero according to openssl
    }

    @Override
    public boolean isImplicitConfirm() {
        InfoTypeAndValue[] infos = this.getHeader().getGeneralInfo();
        if (infos != null) {
            for (int i = 0; i < infos.length; i++) {
                if (CMPObjectIdentifiers.it_implicitConfirm.equals(infos[i].getInfoType())) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public SubjectPublicKeyInfo getRequestSubjectPublicKeyInfo() {
        final PKCS10CertificationRequest request = getRequest();
        return request.getSubjectPublicKeyInfo();
    }

}
