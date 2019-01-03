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
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
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
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
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
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.hibernate.ObjectNotFoundException;
import org.junit.internal.ArrayComparisonFailure;

/**
 * Helper class for CMP Junit tests. 
 * You can run this test against a CMP Proxy instead of directoy to the CA by setting the system property httpCmpProxyURL, 
 * for example to "http://localhost:8080/cmpProxy-6.4.0"
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

    private final String httpReqPath; // = "http://127.0.0.1:8080/ejbca";
    private final String CMP_HOST; // = "127.0.0.1";

    protected final CertificateStoreSession certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    protected final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected final EndEntityManagementSession endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    protected final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    protected final CertificateProfileSession certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    protected final EndEntityProfileSession endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    protected final static AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken("CmpTestCase");

    public CmpTestCase() {
        final String httpServerPubHttp = SystemTestsConfiguration.getRemotePortHttp(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        this.CMP_HOST = SystemTestsConfiguration.getRemoteHost(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        this.httpReqPath = "http://" + this.CMP_HOST + ":" + httpServerPubHttp + "/ejbca";
    }
    
    @Override
    protected void setUp() throws Exception { // NOPMD: this is a test base class
        super.setUp();
        cleanup();
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and
        // check "Allow validity override".
        this.cpDnOverrideId = addCertificateProfile(CP_DN_OVERRIDE_NAME);
        this.eepDnOverrideId = addEndEntityProfile(EEP_DN_OVERRIDE_NAME, this.cpDnOverrideId);
    } 
    
    /**
     * Adds a certificate profile for end entities and sets {@link CertificateProfile#setAllowDNOverride(boolean)} to true.
     * 
     * @param name the name.
     * @return the id of the newly created certificate profile.
     */
    protected final int addCertificateProfile(final String name) {
        assertTrue("Certificate profile with name " + name + " already exists. Clear test data first.", this.certProfileSession.getCertificateProfile(name) == null);
        final CertificateProfile result = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        result.setAllowDNOverride(true);
        int id = -1;
        try {
            this.certProfileSession.addCertificateProfile(ADMIN, name, result);
            id = this.certProfileSession.getCertificateProfileId(name);
            log.info("Certificate profile '" + name + "' and id " + id + " created.");
        } catch (AuthorizationDeniedException | CertificateProfileExistsException e) {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        }
        return id;
    }
    
    /**
     * Adds a certificate profile and sets {@link CertificateProfile#setAllowDNOverride(boolean)} to true.
     * 
     * @param name the name of the certificate profile.
     * @return the ID of the newly created certificate profile.
     */
    /**
     * Adds an end entity profile and links it with the default certificate profile for test {@link EndEntityProfile#setDefaultCertificateProfile(int)}.
     * 
     * @param name the name of the end entity profile.
     * @param certificateProfileId the default certificate profiles ID.
     * @return the ID of the newly created end entity profile. 
     */
    protected final int addEndEntityProfile(final String name, final int certificateProfileId) {
        assertTrue("End entity profile with name " + name + " already exists. Clear test data first.", this.endEntityProfileSession.getEndEntityProfile(name)  == null);
        // Create profile that is just using CP_DN_OVERRIDE_NAME
        final EndEntityProfile result = new EndEntityProfile(true);
        result.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certificateProfileId));
        int id = 0;
        try {
            this.endEntityProfileSession.addEndEntityProfile(ADMIN,name, result);
            id = this.endEntityProfileSession.getEndEntityProfileId(name);
        } catch (AuthorizationDeniedException | EndEntityProfileExistsException | EndEntityProfileNotFoundException e) {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        }
        return id;
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        cleanup();
    }
    
    private void cleanup() throws AuthorizationDeniedException {
        endEntityProfileSession.removeEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME);
        certProfileSession.removeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME);
    }

    public static PKIMessage genCertReq(String issuerDN, X500Name userDN, KeyPair keys, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID, boolean implicitConfirm)
            throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        return genCertReq(issuerDN, userDN, userDN, "UPN=fooupn@bar.com,rfc822Name=fooemail@bar.com", keys, null, null, cacert, nonce, transid, raVerifiedPopo,
                extensions, notBefore, notAfter, customCertSerno, pAlg, senderKID, implicitConfirm);
    }

    public static PKIMessage genCertReq(String issuerDN, X500Name userDN, KeyPair keys, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID)
            throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        return genCertReq(issuerDN, userDN, userDN, "UPN=fooupn@bar.com,rfc822Name=fooemail@bar.com", keys, null, null, cacert, nonce, transid, raVerifiedPopo,
                extensions, notBefore, notAfter, customCertSerno, pAlg, senderKID, false);
    }
    
    public static PKIMessage genCertReqWithSAN(String issuerDN, X500Name userDN, KeyPair keys, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID)
            throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        return genCertReq(issuerDN, userDN, userDN, "UPN=fooupn@bar.com,rfc822Name=fooemail@bar.com,directoryName=CN=foobar\\,C=SE", keys, null, null, cacert, nonce, transid, raVerifiedPopo,
                extensions, notBefore, notAfter, customCertSerno, pAlg, senderKID, false);
    }
    
    public static PKIMessage genCertReqAssertNotNull(String issuerDN, X500Name userDN, KeyPair keys, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID)
            throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        final PKIMessage result = genCertReq(issuerDN, userDN, userDN, "UPN=fooupn@bar.com,rfc822Name=fooemail@bar.com", keys, null, null, cacert, nonce, transid, raVerifiedPopo,
                extensions, notBefore, notAfter, customCertSerno, pAlg, senderKID, false);
        log.debug("Created CMRF with userDN: "+ userDN);
        assertNotNull("Generating CrmfRequest failed.", result);
        return result;
    }

    protected static PKIMessage genCertReq(String issuerDN, X500Name userDN, X500Name senderDN, String altNames, KeyPair keys, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID)
            throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        return genCertReq(issuerDN, userDN, userDN, "UPN=fooupn@bar.com,rfc822Name=fooemail@bar.com", keys, null, null, cacert, nonce, transid, raVerifiedPopo,
                extensions, notBefore, notAfter, customCertSerno, pAlg, senderKID, false);
    }
    /** 
     * 
     * @param issuerDN
     * @param userDN the subjectDN in the CSR, can be set to null, but typically is not
     * @param senderDN senderDN is usually the same as userDN
     * @param altNames
     * @param keys
     * @param cacert
     * @param nonce
     * @param transid
     * @param raVerifiedPopo
     * @param extensions
     * @param notBefore
     * @param notAfter
     * @param customCertSerno
     * @param pAlg
     * @param senderKID
     * @return PKIMessage, to be protected
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    protected static PKIMessage genCertReq(String issuerDN, X500Name userDN, X500Name senderDN, String altNames, KeyPair keys, SubjectPublicKeyInfo spkInfo,  
            KeyPair protocolEncrKey, Certificate cacert, byte[] nonce, byte[] transid,
            boolean raVerifiedPopo, Extensions extensions, Date notBefore, Date notAfter, BigInteger customCertSerno, 
            AlgorithmIdentifier pAlg, DEROctetString senderKID, boolean implicitConfirm)
            throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {
        // Validity can have notBefore, notAfter or both
        ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
        if (notBefore != null) {
            org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(notBefore);
            optionalValidityV.add(new DERTaggedObject(true, 0, nb));
        }
        if (notAfter != null) {
            org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(notAfter);
            optionalValidityV.add(new DERTaggedObject(true, 1, na));
        }
        OptionalValidity optionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));

        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        if (notBefore != null || notAfter != null) {
            certTemplateBuilder.setValidity(optionalValidity);
        }
        if(issuerDN != null) {
            certTemplateBuilder.setIssuer(new X500Name(issuerDN));
        }
        if (userDN != null) {
            // This field can be empty in the spec, and it has happened for real that someone has used empty value here
            certTemplateBuilder.setSubject(userDN);
        }
        if (keys != null) {
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
            certTemplateBuilder.setPublicKey(keyInfo);
        } else if (spkInfo != null) {
            // If we didn't have a public key, perhaps we passed a SubjectPublicKeyInfo, which can
            // be a AlgorithmIdentifier followed by a zero-length BIT STRING as specified for server key generation
            // for CMP in RFC4210
            certTemplateBuilder.setPublicKey(spkInfo);
        }
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
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation);
            extgen.addExtension(Extension.keyUsage, false, new DERBitString(keyUsage));

            // Make the complete extension package
            exts = extgen.generate();
        }
        certTemplateBuilder.setExtensions(exts);
        if (customCertSerno != null) {
            // Add serialNumber to the certTemplate, it is defined as a MUST NOT be used in RFC4211, but we will use it anyway in order
            // to request a custom certificate serial number (something not standard anyway)
            certTemplateBuilder.setSerialNumber(new ASN1Integer(customCertSerno));
        }

        // Add controls, if we have any
        Controls controls = null;
        if (protocolEncrKey != null) {
            SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(protocolEncrKey.getPublic().getEncoded());
            AttributeTypeAndValue av = new AttributeTypeAndValue(CrmfRequestMessage.id_regCtrl_protocolEncrKey, pkinfo);
            controls = new Controls(av);
        }
        CertRequest certRequest = new CertRequest(4, certTemplateBuilder.build(), controls);

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
        ProofOfPossession proofOfPossession = null;
        if (raVerifiedPopo) {
            // raVerified POPO (meaning there is no POPO)
            proofOfPossession = new ProofOfPossession();
        } else if (keys != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DEROutputStream mout = new DEROutputStream(baos);
            mout.writeObject(certRequest);
            mout.close();
            byte[] popoProtectionBytes = baos.toByteArray();            
            try {
                final String sigalg = AlgorithmTools.getSignAlgOidFromDigestAndKey(null, keys.getPrivate().getAlgorithm()).getId();
                final Signature signature = Signature.getInstance(sigalg, BouncyCastleProvider.PROVIDER_NAME);
                signature.initSign(keys.getPrivate());
                signature.update(popoProtectionBytes);
                DERBitString bs = new DERBitString(signature.sign());
                POPOSigningKey popoSigningKey = new POPOSigningKey(null, new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigalg)), bs);
                proofOfPossession = new ProofOfPossession(popoSigningKey);
            } catch (NoSuchProviderException e) {
               throw new IllegalStateException("BouncyCastle provider not found.", e);
            }
        }

        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
        AttributeTypeAndValue[] avs = {av};

        CertReqMsg certReqMsg = new CertReqMsg(certRequest, proofOfPossession, avs);
        CertReqMessages certReqMessages = new CertReqMessages(certReqMsg);

        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(senderDN), new GeneralName(new X500Name(
                issuerDN!=null? issuerDN : ((X509Certificate) cacert).getSubjectDN().getName())));
        
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        pkiHeaderBuilder.setProtectionAlg(pAlg);
        pkiHeaderBuilder.setSenderKID(senderKID);
        if (implicitConfirm) {
            final InfoTypeAndValue genInfo = new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm);
            pkiHeaderBuilder.setGeneralInfo(genInfo);
        }
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        return pkiMessage;
    }

    protected static PKIMessage genRevReq(String issuerDN, X500Name userDN, BigInteger serNo, Certificate cacert, byte[] nonce, byte[] transid,
            boolean noRevocationReason, AlgorithmIdentifier pAlg, DEROctetString senderKID) throws IOException {
        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        certTemplateBuilder.setIssuer(new X500Name(issuerDN));
        certTemplateBuilder.setSubject(userDN);
        certTemplateBuilder.setSerialNumber(new ASN1Integer(serNo));

        
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(certTemplateBuilder.build());
        if (noRevocationReason) {
            // NOOP, crlEntryDetails are optional
        } else {
            ExtensionsGenerator extgen = new ExtensionsGenerator();
            CRLReason crlReason = CRLReason.lookup(CRLReason.keyCompromise);
            extgen.addExtension(Extension.reasonCode, false, crlReason);
            Extensions exts = extgen.generate();
            v.add(exts);
        }
        ASN1Sequence seq = new DERSequence(v);
        RevDetails revDetails = RevDetails.getInstance(seq);
        RevReqContent revReqContent = new RevReqContent(revDetails);

        final GeneralName recipient;
        // Recipient can be empty according to RFC4210 section D.1
        if (cacert != null) {
            recipient = new GeneralName(new X500Name(((X509Certificate) cacert).getSubjectDN().getName()));
        } else {
            RDN[] emptyRDN = new RDN[0]; 
            recipient = new GeneralName(new X500Name(emptyRDN));
        }
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(userDN), recipient);
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        pkiHeaderBuilder.setProtectionAlg(pAlg);
        if (senderKID != null) {
            pkiHeaderBuilder.setSenderKID(senderKID);
        }
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, revReqContent);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        return pkiMessage;
    }

    protected static PKIMessage genCertConfirm(X500Name userDN, Certificate cacert, byte[] nonce, byte[] transid, String hash, int certReqId) {
        String issuerDN = "CN=foobarNoCA";
        if(cacert != null) {
            issuerDN = ((X509Certificate) cacert).getSubjectDN().getName();
        }
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(userDN), new GeneralName(new X500Name(issuerDN)));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        CertStatus certStatus = new CertStatus(hash.getBytes(), new BigInteger(Integer.toString(certReqId)));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(certStatus);
        CertConfirmContent certConfirmContent = CertConfirmContent.getInstance(new DERSequence(v));
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirmContent);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        return pkiMessage;
    }

    protected static PKIMessage genRenewalReq(X500Name userDN, Certificate cacert, byte[] nonce, byte[] transid, KeyPair keys, boolean raVerifiedPopo,
            X500Name reqSubjectDN, String reqIssuerDN, AlgorithmIdentifier pAlg, DEROctetString senderKID)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateEncodingException {
 
     CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

     ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
     org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
     org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date());
     optionalValidityV.add(new DERTaggedObject(true, 0, nb));
     optionalValidityV.add(new DERTaggedObject(true, 1, na));
     OptionalValidity optionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));
     certTemplateBuilder.setValidity(optionalValidity);
     
     if(reqSubjectDN != null) {
         certTemplateBuilder.setSubject(reqSubjectDN);
     }
     if(reqIssuerDN != null) {
         certTemplateBuilder.setIssuer(new X500Name(reqIssuerDN));
     }

     SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
     certTemplateBuilder.setPublicKey(keyInfo);

     CertRequest certRequest = new CertRequest(4, certTemplateBuilder.build(), null);

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
     ProofOfPossession proofOfPossession = null;
     if (raVerifiedPopo) {
         // raVerified POPO (meaning there is no POPO)
         proofOfPossession = new ProofOfPossession();
     } else {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         DEROutputStream mout = new DEROutputStream(baos);
            try {
                mout.writeObject(certRequest);
                mout.close();
                byte[] popoProtectionBytes = baos.toByteArray();
                String sigalg = AlgorithmTools.getSignAlgOidFromDigestAndKey(null, keys.getPrivate().getAlgorithm()).getId();
                final Signature signature = Signature.getInstance(sigalg, BouncyCastleProvider.PROVIDER_NAME);
                signature.initSign(keys.getPrivate());
                signature.update(popoProtectionBytes);
                DERBitString bs = new DERBitString(signature.sign());
                POPOSigningKey popoSigningKey = new POPOSigningKey(null, new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigalg)), bs);
                proofOfPossession = new ProofOfPossession(popoSigningKey);
            } catch (NoSuchProviderException | IOException e) {
                throw new IllegalStateException(e);
            }
     }

     // certReqMsg.addRegInfo(new AttributeTypeAndValue(new ASN1ObjectIdentifier("1.3.6.2.2.2.2.3.1"), new DERInteger(1122334455)));
     AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
     AttributeTypeAndValue[] avs = {av};

     CertReqMsg certReqMsg = new CertReqMsg(certRequest, proofOfPossession, avs);
     CertReqMessages certReqMessages = new CertReqMessages(certReqMsg);

     PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(userDN),
             new GeneralName(new JcaX509CertificateHolder((X509Certificate)cacert).getSubject()));
     pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
     pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
     pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
     pkiHeaderBuilder.setProtectionAlg(pAlg);
     pkiHeaderBuilder.setSenderKID(senderKID);

     PKIBody pkiBody = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ, certReqMessages);
     return new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
 }
    
    protected static PKIMessage protectPKIMessage(PKIMessage msg, boolean badObjectId, String password, int iterations) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        return protectPKIMessage(msg, badObjectId, password, "primekey", iterations);
    }

    protected static PKIMessage protectPKIMessage(PKIMessage msg, boolean badObjectId, String password, String keyId, int iterations)
            throws NoSuchAlgorithmException, InvalidKeyException {
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
        try {
            // Construct the base key according to rfc4210, section 5.1.3.1
            MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
            for (int i = 0; i < iterationCount; i++) {
                basekey = dig.digest(basekey);
                dig.reset();
            }
            // For HMAC/SHA1 there is another oid, that is not known in BC, but the
            // result is the same so...
            String macOid = macAlg.getAlgorithm().getId();
            PKIBody body = msg.getBody();
            byte[] protectedBytes = CmpMessageHelper.getProtectedBytes(header, body);
            Mac mac = Mac.getInstance(macOid, BouncyCastleProvider.PROVIDER_NAME);
            SecretKey key = new SecretKeySpec(basekey, macOid);
            mac.init(key);
            mac.reset();
            mac.update(protectedBytes, 0, protectedBytes.length);
            byte[] out = mac.doFinal();
            DERBitString bs = new DERBitString(out);

            return new PKIMessage(header, body, bs);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle couldn't be found as a provider.");
        }
    }
    
    protected byte[] sendCmpHttp(byte[] message, int httpRespCode) throws IOException {
        return sendCmpHttp(message, httpRespCode, null);
    }

    protected byte[] sendCmpHttp(byte[] message, int httpRespCode, String cmpAlias) throws IOException {
        // POST the CMP request
        // we are going to do a POST
        final String urlString = getProperty("httpCmpProxyURL", this.httpReqPath + '/' + resourceCmp) + '/' + cmpAlias;
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
            assertNotNull("'Cache-Control' header is not present.", cacheControl);
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

    public static PKIMessage checkCmpResponseGeneral(byte[] retMsg, String issuerDN, X500Name userDN, Certificate cacert, byte[] senderNonce, byte[] transId,
            boolean signed, String pbeSecret, String expectedSignAlg) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        return checkCmpResponseGeneral(retMsg, issuerDN, userDN, cacert, senderNonce, transId, signed, pbeSecret, expectedSignAlg, false, null);
    }

    public static PKIMessage checkCmpResponseGeneral(byte[] retMsg, String issuerDN, X500Name userDN, Certificate cacert, byte[] senderNonce, byte[] transId,
            boolean signed, String pbeSecret, String expectedSignAlg, boolean implicitConfirm, String requiredKeyId) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        assertNotNull("No response from server.", retMsg);
        assertTrue("Response was of 0 length.", retMsg.length > 0);
        boolean pbe = (pbeSecret != null);
        //
        // Parse response message
        //
        final PKIMessage respObject = PKIMessage.getInstance(retMsg);
        assertNotNull(respObject);

        // The signer, i.e. the CA, check it's the right CA
        PKIHeader header = respObject.getHeader();

        // Check that the message is signed with the correct digest alg
        if(StringUtils.isEmpty(expectedSignAlg)) {
            expectedSignAlg = PKCSObjectIdentifiers.sha1WithRSAEncryption.getId();
        }
        if (signed) {
            AlgorithmIdentifier algId = header.getProtectionAlg();
            assertNotNull("Protection algorithm was null when expecting a signed response, this was probably an unprotected error message: "+header.getFreeText(), algId);
            assertEquals(expectedSignAlg, algId.getAlgorithm().getId());
        }
        if (pbe) {
            AlgorithmIdentifier algId = header.getProtectionAlg();
            assertNotNull("Protection algorithm was null when expecting a pbe protected response, this was probably an unprotected error message: "+header.getFreeText(), algId);
            assertEquals("Protection algorithm id: " + algId.getAlgorithm().getId(), CMPObjectIdentifiers.passwordBasedMac.getId(), algId
                    .getAlgorithm().getId()); // 1.2.840.113549.1.1.5 - SHA-1 with RSA Encryption
        }

        // Check that the signer is the expected CA    
        assertEquals(4, header.getSender().getTagNo());
        
        X500Name expissuer = new X500Name(issuerDN);
        X500Name actissuer = new X500Name(header.getSender().getName().toString());
        assertEquals("The sender in the response is not the expected", expissuer, actissuer);
        if (signed) {
            // Verify the signature
            byte[] protBytes = CmpMessageHelper.getProtectedBytes(respObject);
            DERBitString bs = respObject.getProtection();
            try {
                final Signature signature = Signature.getInstance(expectedSignAlg, BouncyCastleProvider.PROVIDER_NAME);
                signature.initVerify(cacert);
                signature.update(protBytes);
                assertTrue(signature.verify(bs.getBytes()));
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
                log.debug(e.getMessage(), e);
                fail(e.getMessage());
            }
            // Check that the senderKID is also set when the response is signed
            // The sender Key ID is there so the signer (CA) can have multiple certificates out there
            // with the same DN but different keys
            ASN1OctetString str = header.getSenderKID();
            assertNotNull("senderKID should not be null when response is signed from the CA", str);
            final byte[] senderKID = header.getSenderKID().getOctets();
            final byte[] verifyKID = CertTools.getSubjectKeyId(cacert);
            assertEquals("senderKID in the response is not the expected as in the certificate we plan to verify with.", Hex.toHexString(verifyKID), Hex.toHexString(senderKID));
        }
        if (pbe) {
            String keyId;
            ASN1OctetString os = header.getSenderKID();
            if (os != null) {
                assertNotNull(os);
                keyId = CmpMessageHelper.getStringFromOctets(os);
                log.debug("Found a sender keyId: " + keyId);
                if (requiredKeyId != null) {
                    assertEquals("KeyId should be the required one: ", requiredKeyId, keyId);
                }
            } else if (requiredKeyId != null) {
                assertTrue("RequiredKey should be "+requiredKeyId+" but was null", false);
            }
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
            try {
                MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
                for (int i = 0; i < iterationCount; i++) {
                    basekey = dig.digest(basekey);
                    dig.reset();
                }
                // HMAC/SHA1 os normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7
                String macOid = macAlg.getAlgorithm().getId();
                Mac mac = Mac.getInstance(macOid, BouncyCastleProvider.PROVIDER_NAME);
                SecretKey key = new SecretKeySpec(basekey, macOid);
                mac.init(key);
                mac.reset();
                mac.update(protectedBytes, 0, protectedBytes.length);
                byte[] out = mac.doFinal();
                // My out should now be the same as the protection bits
                byte[] pb = protection.getBytes();
                boolean ret = Arrays.equals(out, pb);
                assertTrue(ret);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
            }
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
        
        if (implicitConfirm) {
            // We expect implicit confirm to be present in the message
            InfoTypeAndValue[] infos = header.getGeneralInfo();
            assertNotNull("expected one InfoTypeAndValue", infos);
            assertEquals("expected one InfoTypeAndValue", 1, infos.length);
            assertEquals("Expected implicitConfirm in response header", CMPObjectIdentifiers.it_implicitConfirm, infos[0].getInfoType());
        } else {
            InfoTypeAndValue[] infos = header.getGeneralInfo();
            assertTrue("expected no InfoTypeAndValue", infos == null);
        }
        return respObject;
    }

    protected static String getProperty(String key, String defaultValue) {
        //If being run from command line
        String result = System.getProperty(key);
        log.debug("System.getProperty("+key+"): " + result);
        if (result == null) {
            //If being run from Eclipse
            final String testProperties = System.getProperty("sun.java.command");
            int cutFrom = testProperties.indexOf(key + "=");
            if (cutFrom >= 0) {
                int to = testProperties.indexOf(" ", cutFrom + key.length() + 1);
                result = testProperties.substring(cutFrom + key.length() + 1, (to >= 0 ? to : testProperties.length())).trim();
            }
        }
        return StringUtils.defaultIfEmpty(result, defaultValue);
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
            fail("This test requires a CMP TCP listener to be configured on " + host + ":" + port + ". Edit conf/cmptcp.properties and redeploy.");
        } catch (EOFException e) {
            fail("Response was malformed.");
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
            fail(e.getMessage());
        }
        return null;
    }

    /**
     * Normally not overridden. Could be overridden if DN in certificate is changed from request by a {@link org.ejbca.core.protocol.ExtendedUserDataHandler}.
     * 
     * @param userDn the users subject DN.
     * @param certificateDn the certificates subject DN.
     * @throws IOException any IOException.
     * @throws ArrayComparisonFailure any ArrayComparisonFailure.
     */
    protected void checkDnIncludingAttributeOrder(final X500Name userDn, final X500Name certificateDn) throws ArrayComparisonFailure, IOException {
        assertArrayEquals("User DN '" + userDn + "' was given, but certificate DN is '" + certificateDn + "'.", userDn.getEncoded(), certificateDn.getEncoded());
    }

    protected X509Certificate checkCmpCertRepMessage(X500Name userDN, X509Certificate cacert, byte[] pkiMessageBytes, int requestId) throws Exception {
        return checkCmpCertRepMessage(userDN, cacert, pkiMessageBytes, requestId, ResponseStatus.SUCCESS.getValue());
    }
    
    protected X509Certificate checkCmpCertRepMessage(X500Name userDN, X509Certificate cacert, byte[] pkiMessageBytes, int requestId, int responseStatus) throws Exception {
        // Parse response message
        final PKIMessage pkiMessage = PKIMessage.getInstance(pkiMessageBytes);
        assertNotNull(pkiMessage);
        // Verify body type
        final PKIBody pkiBody = pkiMessage.getBody();
//        final int tag = pkiBody.getType();
//        assertEquals(PKIBody.TYPE_INIT_REP, tag);
        // Verify the response
        if (pkiBody.getContent() instanceof CertRepMessage) {
            final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
            assertNotNull(certRepMessage);
            final CertResponse certResponse = certRepMessage.getResponse()[0];
            assertNotNull(certResponse);
            assertEquals(certResponse.getCertReqId().getValue().intValue(), requestId);
            // Verify response status
            final PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
            assertNotNull(pkiStatusInfo);
            assertEquals("Expected PKI response status " + responseStatus, responseStatus, pkiStatusInfo.getStatus().intValue());
            if (ResponseStatus.FAILURE.getValue() != responseStatus) {
                // Verify response certificate
                final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
                assertNotNull(certifiedKeyPair);
                final CertOrEncCert certOrEncCert = certifiedKeyPair.getCertOrEncCert();
                assertNotNull(certOrEncCert);
                final CMPCertificate cmpCertificate = certOrEncCert.getCertificate();
                assertNotNull(cmpCertificate);
                final X509Certificate leafCertificate = CertTools.getCertfromByteArray(cmpCertificate.getEncoded(), X509Certificate.class);
                checkDnIncludingAttributeOrder(userDN, new JcaX509CertificateHolder(leafCertificate).getSubject());
                assertArrayEquals(leafCertificate.getIssuerX500Principal().getEncoded(), cacert.getSubjectX500Principal().getEncoded());
                // Verify the issuer of cert
                final CMPCertificate respCmpCaCert = certRepMessage.getCaPubs()[0];
                final X509Certificate respCaCert = CertTools.getCertfromByteArray(respCmpCaCert.getEncoded(), X509Certificate.class);
                assertEquals(CertTools.getFingerprintAsString(cacert), CertTools.getFingerprintAsString(respCaCert));
                assertTrue(CertTools.verify(leafCertificate, Arrays.asList(cacert)));
                assertTrue(CertTools.verify(leafCertificate, Arrays.asList(respCaCert)));
                return leafCertificate;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
        
    protected X509Certificate checkKurCertRepMessage(X500Name eeDN, X509Certificate issuerCert, byte[] pkiMessageBytes, int requestId)
            throws CertificateParsingException, CertPathValidatorException {
        // Parse response message
        final PKIMessage pkiMessage = PKIMessage.getInstance(pkiMessageBytes);
        assertNotNull(pkiMessage);
        // Verify body type
        final PKIBody pkiBody = pkiMessage.getBody();
        final int tag = pkiBody.getType();
        assertEquals(PKIBody.TYPE_KEY_UPDATE_REP, tag);
        // Verify the response
        final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
        assertNotNull(certRepMessage);
        final CertResponse certResponse = certRepMessage.getResponse()[0];
        assertNotNull(certResponse);
        assertEquals(certResponse.getCertReqId().getValue().intValue(), requestId);
        // Verify response status
        final PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
        assertNotNull(pkiStatusInfo);
        assertEquals(ResponseStatus.SUCCESS.getValue(), pkiStatusInfo.getStatus().intValue());
        // Verify response certificate
        final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
        assertNotNull(certifiedKeyPair);
        final CertOrEncCert certOrEncCert = certifiedKeyPair.getCertOrEncCert();
        assertNotNull(certOrEncCert);
        final CMPCertificate cmpCertificate = certOrEncCert.getCertificate();
        assertNotNull(cmpCertificate);
        try {
            final X509Certificate leafCertificate = CertTools.getCertfromByteArray(cmpCertificate.getEncoded(), X509Certificate.class);
            final X500Name name = new X500Name(CertTools.getSubjectDN(leafCertificate));
            assertArrayEquals(eeDN.getEncoded(), name.getEncoded());
            assertEquals(CertTools.stringToBCDNString(CertTools.getIssuerDN(leafCertificate)), CertTools.getSubjectDN(issuerCert));
            // Verify the issuer of cert
            final CMPCertificate respCmpCaCert = certRepMessage.getCaPubs()[0];
            final X509Certificate respCaCert = CertTools.getCertfromByteArray(respCmpCaCert.getEncoded(), X509Certificate.class);
            assertEquals(CertTools.getFingerprintAsString(issuerCert), CertTools.getFingerprintAsString(respCaCert));
            assertTrue(CertTools.verify(leafCertificate, Arrays.asList(issuerCert)));
            assertTrue(CertTools.verify(leafCertificate, Arrays.asList(respCaCert)));
            return leafCertificate;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected static void checkCmpPKIConfirmMessage(X500Name userDN, Certificate cacert, byte[] pkiMessageBytes) throws IOException {
        final PKIMessage pkiMessage = PKIMessage.getInstance(pkiMessageBytes);
        assertNotNull(pkiMessage);
        final PKIHeader pkiHeader = pkiMessage.getHeader();
        assertEquals(4, pkiHeader.getSender().getTagNo());
        final X500Name senderDN = new X500Name(pkiHeader.getSender().getName().toString());
        final X500Name expectedDN = new X500Name(((X509Certificate) cacert).getSubjectDN().getName().toString());
        assertEquals(expectedDN, senderDN);
        final X500Name recipientDN = new X500Name(pkiHeader.getRecipient().getName().toString());
        assertEquals(userDN, recipientDN);
        final PKIBody pkiBody = pkiMessage.getBody();
        final int tag = pkiBody.getType();
        assertEquals(PKIBody.TYPE_CONFIRM, tag);
        final PKIConfirmContent pkiConfirmContent = (PKIConfirmContent) pkiBody.getContent();
        assertNotNull(pkiConfirmContent);
        assertEquals(DERNull.INSTANCE, pkiConfirmContent.toASN1Primitive());
    }

    protected static void checkCmpRevokeConfirmMessage(String issuerDN, X500Name userDN, BigInteger serno, Certificate cacert, byte[] pkiMessageBytes, boolean success)
            throws IOException {
        final PKIMessage pkiMessage = PKIMessage.getInstance(pkiMessageBytes);
        assertNotNull(pkiMessage);
        final PKIHeader pkiHeader = pkiMessage.getHeader();
        assertEquals(4, pkiHeader.getSender().getTagNo());
        final X500Name senderDN = new X500Name(pkiHeader.getSender().getName().toString());
        final X500Name expectedDN = new X500Name(issuerDN);
        assertEquals(expectedDN, senderDN);
        final X500Name recipientDN = new X500Name(pkiHeader.getRecipient().getName().toString());
        assertEquals(userDN, recipientDN);
        final PKIBody pkiBody = pkiMessage.getBody();
        int tag = pkiBody.getType();
        assertEquals(PKIBody.TYPE_REVOCATION_REP, tag);
        final RevRepContent revRepContent = (RevRepContent) pkiBody.getContent();
        assertNotNull(revRepContent);
        final PKIStatusInfo pkiStatusInfo = revRepContent.getStatus()[0];
        if (success) {
            assertEquals("If the revocation was successful, status should be 0.", ResponseStatus.SUCCESS.getValue(), pkiStatusInfo.getStatus().intValue());
        } else {
            assertEquals("If the revocation was unsuccessful, status should be 2.", ResponseStatus.FAILURE.getValue(), pkiStatusInfo.getStatus().intValue());
        }
    }

    /**
     * 
     * @param pkiMessageBytes the encoded response message
     * @param failMsg expected fail message
     * @param tag 1 is answer to initialisation resp, 3 certification resp etc, 23 is error
     * @param err a number from FailInfo
     * @throws IOException
     */
    protected static void checkCmpFailMessage(byte[] pkiMessageBytes, String failMsg, int exptag, int requestId, int err, int expectedPKIFailInfo) throws IOException {
        final PKIMessage pkiMessage = PKIMessage.getInstance(pkiMessageBytes);
        assertNotNull(pkiMessage);
        final PKIBody pkiBody = pkiMessage.getBody();
        final int tag = pkiBody.getType();
        assertEquals(exptag, tag);
        final PKIStatusInfo pkiStatusInfo;
        assertNotNull(pkiBody.getContent());
        if (exptag == CmpPKIBodyConstants.ERRORMESSAGE) {
            final ErrorMsgContent errorMsgContent = (ErrorMsgContent) pkiBody.getContent();
            pkiStatusInfo = errorMsgContent.getPKIStatusInfo();
            assertNotNull(pkiStatusInfo);
            assertEquals(ResponseStatus.FAILURE.getValue(), pkiStatusInfo.getStatus().intValue());
            int i = pkiStatusInfo.getFailInfo().intValue();
            assertEquals(err, i);
        } else if (exptag == CmpPKIBodyConstants.REVOCATIONRESPONSE) {
            RevRepContent revRepContent = (RevRepContent) pkiBody.getContent();
            pkiStatusInfo = revRepContent.getStatus()[0];
            assertNotNull(pkiStatusInfo);
            assertEquals(ResponseStatus.FAILURE.getValue(), pkiStatusInfo.getStatus().intValue());
            assertEquals(expectedPKIFailInfo, pkiStatusInfo.getFailInfo().intValue());
        } else if (exptag == CmpPKIBodyConstants.INITIALIZATIONRESPONSE || exptag == CmpPKIBodyConstants.CERTIFICATIONRESPONSE) {
            CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
            CertResponse resp = certRepMessage.getResponse()[0];
            assertNotNull(resp);
            assertEquals(resp.getCertReqId().getValue().intValue(), requestId);
            pkiStatusInfo = resp.getStatus();
            assertNotNull(pkiStatusInfo);
            int error = pkiStatusInfo.getStatus().intValue();
            assertEquals(ResponseStatus.FAILURE.getValue(), error); // 2 is rejection
            assertEquals(expectedPKIFailInfo, pkiStatusInfo.getFailInfo().intValue());
        } else {
            pkiStatusInfo = null;
            fail("Unsuported exptag '"+exptag+"'");
        }
        log.debug("expected fail message: '" + failMsg + "'. received fail message: '" + pkiStatusInfo.getStatusString().getStringAt(0).getString() + "'.");
        assertEquals(failMsg, pkiStatusInfo.getStatusString().getStringAt(0).getString());
    }

    public static void checkCmpPKIErrorMessage(byte[] pkiMessageBytes, String sender, X500Name recipient, int expectedErrorCode, String errorMsg) throws IOException {
        final PKIMessage pkiMessage = PKIMessage.getInstance(pkiMessageBytes);
        assertNotNull("Response should not be null", pkiMessage);
        final PKIHeader pkiHeader = pkiMessage.getHeader();
        assertEquals(pkiHeader.getSender().getTagNo(), 4);
        final X500Name senderName = X500Name.getInstance(pkiHeader.getSender().getName());
        assertEquals("Not the expected sender.", sender, senderName.toString());
        final X500Name recipientName = X500Name.getInstance(pkiHeader.getRecipient().getName());
        assertEquals("Not the expected recipient.", recipient, recipientName);
        final PKIBody pkiBody = pkiMessage.getBody();
        final int tag = pkiBody.getType();
        assertEquals("Unexpected response PKIBody type", PKIBody.TYPE_ERROR, tag);
        final ErrorMsgContent errorMsgContent = (ErrorMsgContent) pkiBody.getContent();
        assertNotNull("Expected present ErrorMsgContent in body content.", errorMsgContent);
        final PKIStatusInfo pkiStatusInfo = errorMsgContent.getPKIStatusInfo();
        assertNotNull("Expected present PKIStatusInfo.", pkiStatusInfo);
        assertEquals("Unexpected status.", 2, pkiStatusInfo.getStatus().intValue());
        final PKIFreeText pkiFreeText = pkiStatusInfo.getStatusString();
        if (log.isDebugEnabled() && pkiFreeText!=null) {
            log.debug("Response error message: " + pkiFreeText.getStringAt(0).getString());
        }
        assertEquals("Return wrong error code.", expectedErrorCode, pkiStatusInfo.getFailInfo().intValue());
        if (errorMsg != null) {
            assertEquals(errorMsg, pkiFreeText.getStringAt(0).getString());
        }
    }

    /** @return one of the RevokedCertInfo constants */
    protected int checkRevokeStatus(String issuerDN, BigInteger serno) {
        return this.certificateStoreSession.getStatus(issuerDN, serno).revocationReason;
    }

    protected static void updatePropertyOnServer(String property, String value) {
        log.debug("Setting property on server: " + property + "=" + value);
        assertTrue("Failed to set property \"" + property + "\" to \"" + value + "\"",
                EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST).updateProperty(property, value));
    }

    protected EndEntityInformation createUser(String username, String subjectDN, String password, int caid)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException, NoSuchEndEntityException,
            CADoesntExistsException, CertificateSerialNumberException, IllegalNameException, ApprovalException, CustomFieldException {
        EndEntityInformation user = new EndEntityInformation(username, subjectDN, caid, null, username + "@primekey.se",
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            this.endEntityManagementSession.addUser(ADMIN, user, false);
            log.debug("created user: " + username);
        } catch (EndEntityExistsException e) {
            log.debug("User " + username + " could not be created because it may exist(" + e.getMessage() + "). Try to setting the user status to NEW.", e);
            this.endEntityManagementSession.changeUser(ADMIN, user, false);
            this.endEntityManagementSession.setUserStatus(ADMIN, username, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        return user;
    }
    
    protected X500Name createCmpUser(String username, String password, String dn, boolean useDnOverride, int caid, int eeProfileID, int certificateProfileID)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException, CADoesntExistsException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, ApprovalException, CustomFieldException {
        // Make USER that we know...
        int cpID = certificateProfileID;
        if (cpID == -1 ) {
            cpID = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
        }
        
        int eepID = eeProfileID;
        if (eepID == -1) {
            eepID = EndEntityConstants.EMPTY_END_ENTITY_PROFILE;
        }
        X500Name userDN = new X500Name(StringTools.strip(CertTools.stringToBCDNString(dn)));
        if (useDnOverride) {
            cpID = this.cpDnOverrideId;
            eepID = this.eepDnOverrideId;
            userDN = new X500Name(dn);
        }
        final EndEntityInformation user = new EndEntityInformation(username, dn, caid, null, username + "@primekey.se",
                new EndEntityType(EndEntityTypes.ENDUSER), eepID, cpID, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        log.debug("Trying to add/edit USER: " + user.getUsername() + ", foo123, " + userDN+", ");
        try {
            this.endEntityManagementSession.addUser(ADMIN, user, true);
        } catch (EndEntityExistsException e) {
            log.debug("USER already exists: " + user.getUsername() + ", foo123, " + userDN);
            this.endEntityManagementSession.changeUser(ADMIN, user, true);
            this.endEntityManagementSession.setUserStatus(ADMIN, user.getUsername(), EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        return userDN;
    }

    protected Certificate createRACertificate(String username, String password, String raCertsPath, String cmpAlias, KeyPair keys, Date notBefore,
            Date notAfter, String certProfile, int caid) throws AuthorizationDeniedException, CertificateException, FileNotFoundException,
            IOException, EndEntityProfileValidationException, ObjectNotFoundException, CouldNotRemoveEndEntityException, CADoesntExistsException,
            WaitingForApprovalException, IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException,
            CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, NoSuchEndEntityException, ApprovalException,
            NoSuchEndEntityException, CustomFieldException {
           
        createUser(username, "CN="+username, password, caid);
        final int certificateProfileId;
        if (certProfile==null) {
            certificateProfileId = CertificateProfileConstants.CERTPROFILE_NO_PROFILE;
        } else {
            certificateProfileId = certProfileSession.getCertificateProfileId(certProfile);
        }
        Certificate racert = this.signSession.createCertificate(ADMIN, username, password, new PublicKeyWrapper(keys.getPublic()),
                X509KeyUsage.digitalSignature | X509KeyUsage.keyCertSign, notBefore, notAfter,
                certificateProfileId, caid);
        
        byte[] pemRaCert = CertTools.getPemFromCertificateChain(Arrays.asList(racert));
        
        String filename = raCertsPath + "/" + username + ".pem";
        try (final FileOutputStream fos = new FileOutputStream(filename);) {
            fos.write(pemRaCert);
            fos.flush();
        }
        this.endEntityManagementSession.deleteUser(ADMIN, username);
        return racert;
    }

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
