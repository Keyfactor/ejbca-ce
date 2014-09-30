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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.X509Principal;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.hibernate.ObjectNotFoundException;
import org.junit.internal.ArrayComparisonFailure;

/**
 * Helper class for CMP Junit tests
 * 
 * @version $Id$
 */
public abstract class CmpTestCase extends CaTestCase {

    private static final Logger log = Logger.getLogger(CmpTestCase.class);

    private static final String resourceCmp = "publicweb/cmp";
    private static final int PORT_NUMBER = 5587;
    protected static final String CP_DN_OVERRIDE_NAME = "CP_DN_OVERRIDE_NAME";
    protected static final String EEP_DN_OVERRIDE_NAME = "EEP_DN_OVERRIDE_NAME";
    protected int eepDnOverrideId;
    protected int cpDnOverrideId;

    final private String httpReqPath; // = "http://127.0.0.1:8080/ejbca";
    final private String CMP_HOST; // = "127.0.0.1";

    final protected CertificateStoreSession certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    final protected ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    final protected EndEntityManagementSession endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    final protected SignSession signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    final protected CertificateProfileSession certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    final protected EndEntityProfileSession endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    static AuthenticationToken ADMIN = internalAdmin;
    public CmpTestCase() {
        final String httpServerPubHttp = SystemTestsConfiguration.getRemotePortHttp(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        this.CMP_HOST = SystemTestsConfiguration.getRemoteHost(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        this.httpReqPath = "http://" + this.CMP_HOST + ":" + httpServerPubHttp + "/ejbca";
    }
    @Override
    protected void setUp() throws Exception { // NOPMD: this is a test base class
        super.setUp();
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and
        // check "Allow validity override".
        if (this.certProfileSession.getCertificateProfile(CP_DN_OVERRIDE_NAME) == null) {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp.setAllowDNOverride(true);
            try {
                this.certProfileSession.addCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
            } catch (CertificateProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        this.cpDnOverrideId = this.certProfileSession.getCertificateProfileId(CP_DN_OVERRIDE_NAME);
        if (this.endEntityProfileSession.getEndEntityProfile(EEP_DN_OVERRIDE_NAME) == null) {
            // Create profile that is just using CP_DN_OVERRIDE_NAME
            final EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + this.cpDnOverrideId);
            try {
                this.endEntityProfileSession.addEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME, eep);
            } catch (EndEntityProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        this.eepDnOverrideId = this.endEntityProfileSession.getEndEntityProfileId(EEP_DN_OVERRIDE_NAME);
    }
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        this.endEntityProfileSession.removeEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME);
        this.certProfileSession.removeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME);
    }

    protected static PKIMessage genCertReq(String issuerDN, X500Name userDN, KeyPair keys, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
        return genCertReq(issuerDN, userDN, "UPN=fooupn@bar.com,rfc822Name=fooemail@bar.com", keys, cacert, nonce, transid, raVerifiedPopo,
                extensions, notBefore, notAfter, customCertSerno, pAlg, senderKID);
    }

    protected static PKIMessage genCertReq(String issuerDN, X500Name userDN, String altNames, KeyPair keys, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
        ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        if (notBefore != null) {
            nb = new org.bouncycastle.asn1.x509.Time(notBefore);
        }
        optionalValidityV.add(new DERTaggedObject(true, 0, nb));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date());
        if (notAfter != null) {
            na = new org.bouncycastle.asn1.x509.Time(notAfter);
        }
        optionalValidityV.add(new DERTaggedObject(true, 1, na));
        OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));

        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
        myCertTemplate.setValidity(myOptionalValidity);
        if(issuerDN != null) {
            myCertTemplate.setIssuer(new X500Name(issuerDN));
        }
        myCertTemplate.setSubject(userDN);
        byte[] bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
        dIn.close();
        myCertTemplate.setPublicKey(keyInfo);
        // If we did not pass any extensions as parameter, we will create some of our own, standard ones
        Extensions exts = extensions;
        if (exts == null) {
           
            // SubjectAltName
            // Some altNames
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream dOut = new ASN1OutputStream(bOut);
            ExtensionsGenerator extgen = new ExtensionsGenerator();
            if (altNames != null) {
                GeneralNames san = CertTools.getGeneralNamesFromAltName(altNames);
                dOut.writeObject(san);
                byte[] value = bOut.toByteArray();
                extgen.addExtension(Extension.subjectAlternativeName, false, value);
            }

            // KeyUsage
            int bcku = 0;
            bcku = KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation;
            KeyUsage ku = new KeyUsage(bcku);
            extgen.addExtension(Extension.keyUsage, false, new DERBitString(ku));

            // Make the complete extension package
            exts = extgen.generate();
        }
        myCertTemplate.setExtensions(exts);
        if (customCertSerno != null) {
            // Add serialNumber to the certTemplate, it is defined as a MUST NOT be used in RFC4211, but we will use it anyway in order
            // to request a custom certificate serial number (something not standard anyway)
            myCertTemplate.setSerialNumber(new ASN1Integer(customCertSerno));
        }

        CertRequest myCertRequest = new CertRequest(4, myCertTemplate.build(), null);

        // POPO
        /*
         * PKMACValue myPKMACValue = new PKMACValue( new AlgorithmIdentifier(new
         * ASN1ObjectIdentifier("8.2.1.2.3.4"), new DERBitString(new byte[] { 8,
         * 1, 1, 2 })), new DERBitString(new byte[] { 12, 29, 37, 43 }));
         * 
         * POPOPrivKey myPOPOPrivKey = new POPOPrivKey(new DERBitString(new
         * byte[] { 44 }), 2); //take choice pos tag 2
         * 
         * POPOSigningKeyInput myPOPOSigningKeyInput = new POPOSigningKeyInput(
         * myPKMACValue, new SubjectPublicKeyInfo( new AlgorithmIdentifier(new
         * ASN1ObjectIdentifier("9.3.3.9.2.2"), new DERBitString(new byte[] { 2,
         * 9, 7, 3 })), new byte[] { 7, 7, 7, 4, 5, 6, 7, 7, 7 }));
         */
        ProofOfPossession myProofOfPossession = null;
        if (raVerifiedPopo) {
            // raVerified POPO (meaning there is no POPO)
            myProofOfPossession = new ProofOfPossession();
        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DEROutputStream mout = new DEROutputStream(baos);
            mout.writeObject(myCertRequest);
            mout.close();
            byte[] popoProtectionBytes = baos.toByteArray();            
            String    sigalg = AlgorithmTools.getSignAlgOidFromDigestAndKey(null, keys.getPrivate().getAlgorithm()).getId();
            Signature sig = Signature.getInstance(sigalg, "BC");
            sig.initSign(keys.getPrivate());
            sig.update(popoProtectionBytes);
            DERBitString bs = new DERBitString(sig.sign());
            POPOSigningKey myPOPOSigningKey = new POPOSigningKey(null, new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigalg)), bs);
            myProofOfPossession = new ProofOfPossession(myPOPOSigningKey);
        }

        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
        AttributeTypeAndValue[] avs = {av};

        CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest, myProofOfPossession, avs);
        
        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(userDN), new GeneralName(new X500Name(
                issuerDN!=null? issuerDN : ((X509Certificate) cacert).getSubjectDN().getName())));
        
        myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        myPKIHeader.setProtectionAlg(pAlg);
        myPKIHeader.setSenderKID(senderKID);

        PKIBody myPKIBody = new PKIBody(0, myCertReqMessages); // initialization
                                                               // request
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        return myPKIMessage;
    }

    protected static PKIMessage genRevReq(String issuerDN, X500Name userDN, BigInteger serNo, Certificate cacert, byte[] nonce, byte[] transid,
            boolean crlEntryExtension, AlgorithmIdentifier pAlg, DEROctetString senderKID) throws IOException {
        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
        myCertTemplate.setIssuer(new X500Name(issuerDN));
        myCertTemplate.setSubject(userDN);
        myCertTemplate.setSerialNumber(new ASN1Integer(serNo));

        ExtensionsGenerator extgen = new ExtensionsGenerator();
        CRLReason crlReason;
        if (crlEntryExtension) {
            crlReason = CRLReason.lookup(CRLReason.cessationOfOperation);
        } else {
            crlReason = CRLReason.lookup(CRLReason.keyCompromise);
        }
        extgen.addExtension(Extension.reasonCode, false, crlReason);
        
        Extensions exts = extgen.generate();
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(myCertTemplate.build());
        v.add(exts);
        ASN1Sequence seq = new DERSequence(v);
        
        RevDetails myRevDetails = RevDetails.getInstance(seq); //new RevDetails(myCertTemplate.build(), exts);
        
        RevReqContent myRevReqContent = new RevReqContent(myRevDetails);

        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(userDN), new GeneralName(new X500Name(
                ((X509Certificate) cacert).getSubjectDN().getName())));
        myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
        myPKIHeader.setProtectionAlg(pAlg);
        myPKIHeader.setSenderKID(senderKID);

        PKIBody myPKIBody = new PKIBody(11, myRevReqContent); // revocation
                                                              // request
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        return myPKIMessage;
    }

    protected static PKIMessage genCertConfirm(X500Name userDN, Certificate cacert, byte[] nonce, byte[] transid, String hash, int certReqId) {

        String issuerDN = "CN=foobarNoCA";
        if(cacert != null) {
            issuerDN = ((X509Certificate) cacert).getSubjectDN().getName();
        }
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(userDN), 
                                                               new GeneralName(new X500Name(issuerDN)));
        myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));

        CertStatus cs = new CertStatus(hash.getBytes(), new BigInteger(Integer.toString(certReqId)));
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(cs);
        CertConfirmContent cc = CertConfirmContent.getInstance(new DERSequence(v));
        
        PKIBody myPKIBody = new PKIBody(24, cc); // Cert Confirm
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        return myPKIMessage;
    }

    protected static PKIMessage genRenewalReq(X500Name userDN, Certificate cacert, byte[] nonce, byte[] transid, KeyPair keys, boolean raVerifiedPopo, X500Name reqSubjectDN, String reqIssuerDN, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateEncodingException {
     
     CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();

     ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
     org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
     org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date());
     optionalValidityV.add(new DERTaggedObject(true, 0, nb));
     optionalValidityV.add(new DERTaggedObject(true, 1, na));
     OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));
     
     myCertTemplate.setValidity(myOptionalValidity);
     
     if(reqSubjectDN != null) {
         myCertTemplate.setSubject(reqSubjectDN);
     }
     if(reqIssuerDN != null) {
         myCertTemplate.setIssuer(new X500Name(reqIssuerDN));
     }
     
     
        byte[] bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream dIn = new ASN1InputStream(bIn);
        try {
            SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
            myCertTemplate.setPublicKey(keyInfo);
        } finally {
            dIn.close();
        }

     CertRequest myCertRequest = new CertRequest(4, myCertTemplate.build(), null);

     // POPO
     /*
      * PKMACValue myPKMACValue = new PKMACValue( new AlgorithmIdentifier(new
      * ASN1ObjectIdentifier("8.2.1.2.3.4"), new DERBitString(new byte[] { 8,
      * 1, 1, 2 })), new DERBitString(new byte[] { 12, 29, 37, 43 }));
      * 
      * POPOPrivKey myPOPOPrivKey = new POPOPrivKey(new DERBitString(new
      * byte[] { 44 }), 2); //take choice pos tag 2
      * 
      * POPOSigningKeyInput myPOPOSigningKeyInput = new POPOSigningKeyInput(
      * myPKMACValue, new SubjectPublicKeyInfo( new AlgorithmIdentifier(new
      * ASN1ObjectIdentifier("9.3.3.9.2.2"), new DERBitString(new byte[] { 2,
      * 9, 7, 3 })), new byte[] { 7, 7, 7, 4, 5, 6, 7, 7, 7 }));
      */
     ProofOfPossession myProofOfPossession = null;
     if (raVerifiedPopo) {
         // raVerified POPO (meaning there is no POPO)
         myProofOfPossession = new ProofOfPossession();
     } else {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         DEROutputStream mout = new DEROutputStream(baos);
         mout.writeObject(myCertRequest);
         mout.close();
         byte[] popoProtectionBytes = baos.toByteArray();
         String sigalg = AlgorithmTools.getSignAlgOidFromDigestAndKey(null, keys.getPrivate().getAlgorithm()).getId();
         Signature sig = Signature.getInstance(sigalg);
         sig.initSign(keys.getPrivate());
         sig.update(popoProtectionBytes);

         DERBitString bs = new DERBitString(sig.sign());

         POPOSigningKey myPOPOSigningKey = new POPOSigningKey(null, new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigalg)), bs);
         myProofOfPossession = new ProofOfPossession(myPOPOSigningKey);
     }

     // myCertReqMsg.addRegInfo(new AttributeTypeAndValue(new
     // ASN1ObjectIdentifier("1.3.6.2.2.2.2.3.1"), new
     // DERInteger(1122334455)));
     AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
     AttributeTypeAndValue[] avs = {av};

     CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest, myProofOfPossession, avs);
     
     CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

     PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(
             2, new GeneralName(userDN),
             new GeneralName(new JcaX509CertificateHolder((X509Certificate)cacert).getSubject()));
     myPKIHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
     // senderNonce
     myPKIHeader.setSenderNonce(new DEROctetString(nonce));
     // TransactionId
     myPKIHeader.setTransactionID(new DEROctetString(transid));
     myPKIHeader.setProtectionAlg(pAlg);
     myPKIHeader.setSenderKID(senderKID);

     PKIBody myPKIBody = new PKIBody(7, myCertReqMessages); // Key Update Request
     PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
     
     return myPKIMessage;

 }
    
    protected static PKIMessage protectPKIMessage(PKIMessage msg, boolean badObjectId, String password, int iterations) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        return protectPKIMessage(msg, badObjectId, password, "primekey", iterations);
    }

    protected static PKIMessage protectPKIMessage(PKIMessage msg, boolean badObjectId, String password, String keyId, int iterations)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        // Create the PasswordBased protection of the message
        PKIHeaderBuilder head = CmpMessageHelper.getHeaderBuilder(msg.getHeader());
        if(keyId != null) {
            head.setSenderKID(new DEROctetString(keyId.getBytes()));
        }
        // SHA1
        AlgorithmIdentifier owfAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        // 567 iterations
        int iterationCount = iterations;
        ASN1Integer iteration = new ASN1Integer(iterationCount);
        // HMAC/SHA1
        AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"));
        byte[] salt = "foo123".getBytes();
        DEROctetString derSalt = new DEROctetString(salt);

        // Create the new protected return message
        String objectId = "1.2.840.113533.7.66.13";
        if (badObjectId) {
            objectId += ".7";
        }
        PBMParameter pp = new PBMParameter(derSalt, owfAlg, iteration, macAlg);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(objectId), pp);
        head.setProtectionAlg(pAlg);
        PKIHeader header = head.build();
        // Calculate the protection bits
        byte[] raSecret = password.getBytes();
        byte[] basekey = new byte[raSecret.length + salt.length];
        System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
        for (int i = 0; i < salt.length; i++) {
            basekey[raSecret.length + i] = salt[i];
        }
        // Construct the base key according to rfc4210, section 5.1.3.1
        MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), "BC");
        for (int i = 0; i < iterationCount; i++) {
            basekey = dig.digest(basekey);
            dig.reset();
        }
        // For HMAC/SHA1 there is another oid, that is not known in BC, but the
        // result is the same so...
        String macOid = macAlg.getAlgorithm().getId();
        PKIBody body = msg.getBody();
        byte[] protectedBytes = CmpMessageHelper.getProtectedBytes(header, body);
        Mac mac = Mac.getInstance(macOid, "BC");
        SecretKey key = new SecretKeySpec(basekey, macOid);
        mac.init(key);
        mac.reset();
        mac.update(protectedBytes, 0, protectedBytes.length);
        byte[] out = mac.doFinal();
        DERBitString bs = new DERBitString(out);
        
        return new PKIMessage(header, body, bs);
    }
    
    protected byte[] sendCmpHttp(byte[] message, int httpRespCode) throws IOException {
        return sendCmpHttp(message, httpRespCode, null);
    }

    protected byte[] sendCmpHttp(byte[] message, int httpRespCode, String cmpAlias) throws IOException {
        // POST the CMP request
        // we are going to do a POST
        final String resource = resourceCmp + "/" + cmpAlias;
        final String urlString = getProperty("httpCmpProxyURL", this.httpReqPath + '/' + resource);
        log.info("http URL: " + urlString);
        URL url = new URL(urlString);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/pkixcmp");
        con.connect();
        // POST it
        OutputStream os = con.getOutputStream();
        os.write(message);
        os.close();

        assertEquals("Unexpected HTTP response code.", httpRespCode, con.getResponseCode());
        // Only try to read the response if we expected a 200 (ok) response
        if (httpRespCode != 200) {
            return null;
        }
            // Some appserver (Weblogic) responds with
            // "application/pkixcmp; charset=UTF-8"
            assertNotNull("No content type in response.", con.getContentType());
            assertTrue(con.getContentType().startsWith("application/pkixcmp"));
            // Check that the CMP respone has the cache-control headers as specified in 
            // http://tools.ietf.org/html/draft-ietf-pkix-cmp-transport-protocols-14
            final String cacheControl = con.getHeaderField("Cache-Control");
            assertNotNull(cacheControl);
            assertEquals("no-cache", cacheControl);
            final String pragma = con.getHeaderField("Pragma");
            assertNotNull(pragma);
            assertEquals("no-cache", pragma);
            // Now read in the bytes
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // This works for small requests, and CMP requests are small enough
            InputStream in = con.getInputStream();
            int b = in.read();
            while (b != -1) {
                baos.write(b);
                b = in.read();
            }
            baos.flush();
            in.close();
            byte[] respBytes = baos.toByteArray();
            assertNotNull(respBytes);
            assertTrue(respBytes.length > 0);
            return respBytes;
    }

    protected static void checkCmpResponseGeneral(byte[] retMsg, String issuerDN, X500Name userDN, Certificate cacert, byte[] senderNonce, byte[] transId,
            boolean signed, String pbeSecret, String expectedSignAlg) throws Exception {
        assertNotNull("No response from server.", retMsg);
        assertTrue("Response was of 0 length.", retMsg.length > 0);
        boolean pbe = (pbeSecret != null);
        //
        // Parse response message
        //
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(retMsg));
        PKIMessage respObject = null;
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        // The signer, i.e. the CA, check it's the right CA
        PKIHeader header = respObject.getHeader();

        // Check that the message is signed with the correct digest alg
        if(StringUtils.isEmpty(expectedSignAlg)) {
            expectedSignAlg = PKCSObjectIdentifiers.sha1WithRSAEncryption.getId();
        }
        // if cacert is ECDSA we should expect an ECDSA signature alg
        //if (AlgorithmTools.getSignatureAlgorithm(cacert).contains("ECDSA")) {
        //    expectedSignAlg = X9ObjectIdentifiers.ecdsa_with_SHA1.getId();
        //} else if(AlgorithmTools.getSignatureAlgorithm(cacert).contains("ECGOST3410")) {
        //    expectedSignAlg = CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001.getId();
        //} else if(AlgorithmTools.getSignatureAlgorithm(cacert).contains("DSTU4145")) {
        //    expectedSignAlg = (new ASN1ObjectIdentifier(CesecoreConfiguration.getOidDstu4145())).getId();
        //}
        if (signed) {
            AlgorithmIdentifier algId = header.getProtectionAlg();
            assertNotNull("Protection algorithm was null when expecting a signed response, this was propably an unprotected error message: "+header.getFreeText(), algId);
            assertEquals(expectedSignAlg, algId.getAlgorithm().getId());
        }
        if (pbe) {
            AlgorithmIdentifier algId = header.getProtectionAlg();
            assertNotNull("Protection algorithm was null when expecting a pbe protected response, this was propably an unprotected error message: "+header.getFreeText(), algId);
            assertEquals("Protection algorithm id: " + algId.getAlgorithm().getId(), CMPObjectIdentifiers.passwordBasedMac.getId(), algId
                    .getAlgorithm().getId()); // 1.2.840.113549.1.1.5 - SHA-1 with RSA Encryption
        }

        // Check that the signer is the expected CA    
        assertEquals(header.getSender().getTagNo(), 4);
        
        X500Name expissuer = new X500Name(issuerDN);
        X500Name actissuer = new X500Name(header.getSender().getName().toString());     
        assertEquals(expissuer, actissuer);
        if (signed) {
            // Verify the signature
            byte[] protBytes = CmpMessageHelper.getProtectedBytes(respObject);
            DERBitString bs = respObject.getProtection();
            Signature sig;
            try {
                sig = Signature.getInstance(expectedSignAlg, "BC");
                sig.initVerify(cacert);
                sig.update(protBytes);
                boolean ret = sig.verify(bs.getBytes());
                assertTrue(ret);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                assertTrue(false);
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
                assertTrue(false);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
                assertTrue(false);
            } catch (SignatureException e) {
                e.printStackTrace();
                assertTrue(false);
            }
        }
        if (pbe) {
            ASN1OctetString os = header.getSenderKID();
            assertNotNull(os);
            String keyId = CmpMessageHelper.getStringFromOctets(os);
            log.debug("Found a sender keyId: " + keyId);
            // Verify the PasswordBased protection of the message
            byte[] protectedBytes = CmpMessageHelper.getProtectedBytes(respObject);
            DERBitString protection = respObject.getProtection();
            AlgorithmIdentifier pAlg = header.getProtectionAlg();
            log.debug("Protection type is: " + pAlg.getAlgorithm().getId());
            PBMParameter pp = PBMParameter.getInstance(pAlg.getParameters());
            int iterationCount = pp.getIterationCount().getPositiveValue().intValue();
            log.debug("Iteration count is: " + iterationCount);
            AlgorithmIdentifier owfAlg = pp.getOwf();
            // Normal OWF alg is 1.3.14.3.2.26 - SHA1
            log.debug("Owf type is: " + owfAlg.getAlgorithm().getId());
            AlgorithmIdentifier macAlg = pp.getMac();
            // Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
            log.debug("Mac type is: " + macAlg.getAlgorithm().getId());
            byte[] salt = pp.getSalt().getOctets();
            // log.info("Salt is: "+new String(salt));
            byte[] raSecret = pbeSecret!=null ? pbeSecret.getBytes() : new byte[0];
            byte[] basekey = new byte[raSecret.length + salt.length];
            System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
            for (int i = 0; i < salt.length; i++) {
                basekey[raSecret.length + i] = salt[i];
            }
            // Construct the base key according to rfc4210, section 5.1.3.1
            MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), "BC");
            for (int i = 0; i < iterationCount; i++) {
                basekey = dig.digest(basekey);
                dig.reset();
            }
            // HMAC/SHA1 os normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7
            String macOid = macAlg.getAlgorithm().getId();
            Mac mac = Mac.getInstance(macOid, "BC");
            SecretKey key = new SecretKeySpec(basekey, macOid);
            mac.init(key);
            mac.reset();
            mac.update(protectedBytes, 0, protectedBytes.length);
            byte[] out = mac.doFinal();
            // My out should now be the same as the protection bits
            byte[] pb = protection.getBytes();
            boolean ret = Arrays.equals(out, pb);
            assertTrue(ret);
        }

        // --SenderNonce
        // SenderNonce is something the server came up with, but it should be 16
        // chars
        byte[] nonce = header.getSenderNonce().getOctets();
        assertEquals(nonce.length, 16);

        // --Recipient Nonce
        // recipient nonce should be the same as we sent away as sender nonce
        nonce = header.getRecipNonce().getOctets();
        assertEquals(new String(nonce), new String(senderNonce));

        // --Transaction ID
        // transid should be the same as the one we sent
        nonce = header.getTransactionID().getOctets();
        assertEquals(new String(nonce), new String(transId));

    }

    protected static String getProperty(String key, String defaultValue) {
        final String result = System.getProperty(key);
        if (result == null || result.length() < 1 || result.startsWith("$")) {
            return defaultValue;
        }
        return result;
    }

    private static int getProperty(String key, int defaultValue) {
        final String sResult = getProperty(key, (String) null);
        if (sResult == null) {
            return defaultValue;
        }
        return Integer.parseInt(sResult);
    }

    /**
     * 
     * @param message
     * @param type set to 5 when sending a PKI request, 3 when sending a PKIConf
     * @return
     * @throws IOException
     * @throws NoSuchProviderException
     */
    protected byte[] sendCmpTcp(byte[] message, int type) throws IOException, NoSuchProviderException {
        final String host = getProperty("tcpCmpProxyIP", this.CMP_HOST);
        final int port = getProperty("tcpCmpProxyPort", PORT_NUMBER);
        try {
            final Socket socket = new Socket(host, port);

            final byte[] msg = createTcpMessage(message);
            try {
                final BufferedOutputStream os = new BufferedOutputStream(socket.getOutputStream());
                os.write(msg);
                os.flush();

                DataInputStream dis = new DataInputStream(socket.getInputStream());

                // Read the length, 32 bits
                final int len = dis.readInt();
                log.info("Got a message claiming to be of length: " + len);
                // Read the version, 8 bits. Version should be 10 (protocol draft nr
                // 5)
                final int ver = dis.readByte();
                log.info("Got a message with version: " + ver);
                assertEquals(ver, 10);

                // Read flags, 8 bits for version 10
                final byte flags = dis.readByte();
                log.info("Got a message with flags (1 means close): " + flags);
                // Check if the client wants us to close the connection (LSB is 1 in
                // that case according to spec)

                // Read message type, 8 bits
                final int msgType = dis.readByte();
                log.info("Got a message of type: " + msgType);
                assertEquals(msgType, type);

                // Read message
                final ByteArrayOutputStream baos = new ByteArrayOutputStream(3072);
                while (dis.available() > 0) {
                    baos.write(dis.read());
                }

                log.info("Read " + baos.size() + " bytes");
                final byte[] respBytes = baos.toByteArray();
                assertNotNull(respBytes);
                assertTrue(respBytes.length > 0);
                return respBytes;
            } finally {
                socket.close();
            }
        } catch (ConnectException e) {
            assertTrue("This test requires a CMP TCP listener to be configured on " + host + ":" + port + ". Edit conf/cmptcp.properties and redeploy.",
                    false);
        } catch (EOFException e) {
            assertTrue("Response was malformed.", false);
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        return null;
    }

    /**
     * Normally not overrided. Could be overrided if DN in cert is changed from request by a {@link org.ejbca.core.protocol.ExtendedUserDataHandler}.
     * 
     * @param expected
     * @param actual
     * @throws IOException 
     * @throws ArrayComparisonFailure 
     */
    @SuppressWarnings("static-method")
    protected void checkDN(X500Name expected, X500Name actual) throws ArrayComparisonFailure, IOException {
        assertArrayEquals("Was '"+actual+"' expected '"+expected+"'.", expected.getEncoded(), actual.getEncoded() );
    }

    protected X509Certificate checkCmpCertRepMessage(X500Name userDN, Certificate cacert, byte[] retMsg, int requestId) throws IOException,
            CertificateException {
        //
        // Parse response message
        //
        assertTrue(cacert instanceof X509Certificate);
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(retMsg));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        int tag = body.getType();
        assertEquals(1, tag);
        CertRepMessage c = (CertRepMessage) body.getContent();
        assertNotNull(c);
        CertResponse resp = c.getResponse()[0];
        assertNotNull(resp);
        assertEquals(resp.getCertReqId().getValue().intValue(), requestId);
        PKIStatusInfo info = resp.getStatus();
        assertNotNull(info);
        assertEquals(0, info.getStatus().intValue());
        CertifiedKeyPair kp = resp.getCertifiedKeyPair();
        assertNotNull(kp);
        CertOrEncCert cc = kp.getCertOrEncCert();
        assertNotNull(cc);
        final CMPCertificate cmpcert = cc.getCertificate();
        assertNotNull(cmpcert);
        final X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(cmpcert.getEncoded());
        checkDN(userDN, new JcaX509CertificateHolder(cert).getSubject());
        assertArrayEquals(cert.getIssuerX500Principal().getEncoded(), ((X509Certificate)cacert).getSubjectX500Principal().getEncoded());
        return cert;
    }

    protected static void checkCmpPKIConfirmMessage(X500Name userDN, Certificate cacert, byte[] retMsg) throws IOException {
        //
        // Parse response message
        //
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(retMsg));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);
        PKIHeader header = respObject.getHeader();
        assertEquals(header.getSender().getTagNo(), 4);
        
        X509Principal responseDN = new X509Principal(header.getSender().getName().toString());
        X509Principal expectedDN = new X509Principal(((X509Certificate) cacert).getSubjectDN().getName().toString());
        assertEquals(expectedDN.getName(), responseDN.getName());
        
        responseDN = new X509Principal(header.getRecipient().getName().toString());
        expectedDN = new X509Principal(userDN);
        assertEquals(expectedDN.getName(), responseDN.getName());

        PKIBody body = respObject.getBody();
        int tag = body.getType();
        assertEquals(19, tag);
        PKIConfirmContent n = (PKIConfirmContent) body.getContent();
        assertNotNull(n);
        assertEquals(DERNull.INSTANCE, n.toASN1Primitive());
    }

    protected static void checkCmpRevokeConfirmMessage(String issuerDN, X500Name userDN, BigInteger serno, Certificate cacert, byte[] retMsg, boolean success)
            throws IOException {
        //
        // Parse response message
        //
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(retMsg));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);
        PKIHeader header = respObject.getHeader();
        assertEquals(header.getSender().getTagNo(), 4);
        
        X509Principal responseDN = new X509Principal(header.getSender().getName().toString());
        X509Principal expectedDN = new X509Principal(issuerDN);
        assertEquals(expectedDN.getName(), responseDN.getName());
        
        responseDN = new X509Principal(header.getRecipient().getName().toString());
        expectedDN = new X509Principal(userDN);
        assertEquals(expectedDN.getName(), responseDN.getName());

        PKIBody body = respObject.getBody();
        int tag = body.getType();
        assertEquals(tag, 12);
        RevRepContent n = (RevRepContent) body.getContent();
        assertNotNull(n);
        PKIStatusInfo info = n.getStatus()[0];
        if (success) {
            assertEquals("If the revocation was successful, status should be 0.", 0, info.getStatus().intValue());
        } else {
            assertEquals("If the revocation was unsuccessful, status should be 2.", 2, info.getStatus().intValue());
        }

    }

    /**
     * 
     * @param retMsg
     * @param failMsg expected fail message
     * @param tag 1 is answer to initialisation resp, 3 certification resp etc, 23 is error
     * @param err a number from FailInfo
     * @throws IOException
     */
    protected static void checkCmpFailMessage(byte[] retMsg, String failMsg, int exptag, int requestId, int err, int expectedPKIFailInfo) throws IOException {
        //
        // Parse response message
        //
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(retMsg));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        final int tag = body.getType();
        assertEquals(exptag, tag);
        final PKIStatusInfo info;
        if (exptag == CmpPKIBodyConstants.ERRORMESSAGE) {
            ErrorMsgContent c = (ErrorMsgContent) body.getContent();
            assertNotNull(c);
            info = c.getPKIStatusInfo();
            assertNotNull(info);
            assertEquals(ResponseStatus.FAILURE.getValue(), info.getStatus().intValue());
            int i = info.getFailInfo().intValue();
            assertEquals(err, i);
        } else if (exptag == CmpPKIBodyConstants.REVOCATIONRESPONSE) {
            RevRepContent rrc = (RevRepContent) body.getContent();
            assertNotNull(rrc);
            info = rrc.getStatus()[0];
            assertNotNull(info);
            assertEquals(ResponseStatus.FAILURE.getValue(), info.getStatus().intValue());
            assertEquals(PKIFailureInfo.badRequest, info.getFailInfo().intValue());
        } else {
            CertRepMessage c = null;
            if (exptag == CmpPKIBodyConstants.INITIALIZATIONRESPONSE || exptag == CmpPKIBodyConstants.CERTIFICATIONRESPONSE) {
                c = (CertRepMessage) body.getContent();
            }
            assertNotNull(c);
            CertResponse resp = c.getResponse()[0];
            assertNotNull(resp);
            assertEquals(resp.getCertReqId().getValue().intValue(), requestId);
            info = resp.getStatus();
            assertNotNull(info);
            int error = info.getStatus().intValue();
            assertEquals(ResponseStatus.FAILURE.getValue(), error); // 2 is
                                                                    // rejection
            assertEquals(expectedPKIFailInfo, info.getFailInfo().intValue());
        }
        log.debug("expected fail message: '" + failMsg + "'. received fail message: '" + info.getStatusString().getStringAt(0).getString() + "'.");
        assertEquals(failMsg, info.getStatusString().getStringAt(0).getString());
    }

    protected static void checkCmpPKIErrorMessage(byte[] retMsg, String sender, X500Name recipient, int errorCode, String errorMsg) throws IOException {
        //
        // Parse response message
        //
        PKIMessage respObject = null;
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(retMsg));
        try {
            respObject = PKIMessage.getInstance(asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        assertNotNull(respObject);
        PKIHeader header = respObject.getHeader();
        assertEquals(header.getSender().getTagNo(), 4);
        {
            final X500Name name = X500Name.getInstance(header.getSender().getName());
            assertEquals(name.toString(), sender);
        }
        {
            final X500Name name = X500Name.getInstance(header.getRecipient().getName());
            assertArrayEquals(name.getEncoded(), recipient.getEncoded());
        }

        PKIBody body = respObject.getBody();
        int tag = body.getType();
        assertEquals(tag, 23);
        ErrorMsgContent n = (ErrorMsgContent) body.getContent();
        assertNotNull(n);
        PKIStatusInfo info = n.getPKIStatusInfo();
        assertNotNull(info);
        BigInteger i = info.getStatus();
        assertEquals(i.intValue(), 2);
        DERBitString b = info.getFailInfo();
        assertEquals("Return wrong error code.", errorCode, b.intValue());
        if (errorMsg != null) {
            PKIFreeText freeText = info.getStatusString();
            DERUTF8String utf = freeText.getStringAt(0);
            assertEquals(errorMsg, utf.getString());
        }
    }

    protected int checkRevokeStatus(String issuerDN, BigInteger serno) {
        int ret = RevokedCertInfo.NOT_REVOKED;
        CertificateStatus info = this.certificateStoreSession.getStatus(issuerDN, serno);
        ret = info.revocationReason;
        return ret;
    }

    protected static void updatePropertyOnServer(String property, String value) {
        log.debug("Setting property on server: " + property + "=" + value);
        assertTrue("Failed to set property \"" + property + "\" to \"" + value + "\"",
                EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST).updateProperty(property, value));
    }

    protected EndEntityInformation createUser(String username, String subjectDN, String password, int caid) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
    EjbcaException, Exception {

        EndEntityInformation user = new EndEntityInformation(username, subjectDN, caid, null, username+"@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            this.endEntityManagementSession.addUser(ADMIN, user, false);
            // usersession.addUser(ADMIN,"cmptest","foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,EndEntityTypes.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            this.endEntityManagementSession.changeUser(ADMIN, user, false);
            this.endEntityManagementSession.setUserStatus(ADMIN, username, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        return user;
    }

    protected Certificate createRACertificate(String username, String password, String raCertsPath, String cmpAlias, KeyPair keys, Date notBefore, 
            Date notAfter, String certProfile, int caid) throws AuthorizationDeniedException, EjbcaException, CertificateException, FileNotFoundException,
            IOException, UserDoesntFullfillEndEntityProfile, ObjectNotFoundException, Exception {
                
        createUser(username, "CN="+username, password, caid);
        Certificate racert = this.signSession.createCertificate(ADMIN, username, password, keys.getPublic(), X509KeyUsage.digitalSignature|X509KeyUsage.keyCertSign, notBefore, notAfter, this.certProfileSession.getCertificateProfileId(certProfile), caid);

        
        List<Certificate> certCollection = new ArrayList<Certificate>();
        certCollection.add(racert);
        byte[] pemRaCert = CertTools.getPemFromCertificateChain(certCollection);
        
        String filename = raCertsPath + "/" + username + ".pem";
        FileOutputStream fout = new FileOutputStream(filename);
        fout.write(pemRaCert);
        fout.flush();
        fout.close();        
        
        this.endEntityManagementSession.deleteUser(ADMIN, username);
        
        return racert;
    }



    //
    // Private methods
    //

    private static byte[] createTcpMessage(byte[] msg) throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bao);
        // 0 is pkiReq
        int msgType = 0;
        int len = msg.length;
        // return msg length = msg.length + 3; 1 byte version, 1 byte flags and
        // 1 byte message type
        dos.writeInt(len + 3);
        dos.writeByte(10);
        dos.writeByte(0); // 1 if we should close, 0 otherwise
        dos.writeByte(msgType);
        dos.write(msg);
        dos.flush();
        return bao.toByteArray();
    }

}
