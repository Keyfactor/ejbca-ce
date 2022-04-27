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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.hibernate.ObjectNotFoundException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * This will the the different kind of CMP messages that can be sent as NestedMessageContent and if 
 * they are verified correctly.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class NestedMessageContentTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(NestedMessageContentTest.class);
    
    private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("NestedMessageContentTest");
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final EndEntityProfileSession eeProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    
    private final int caid;
    private final X509Certificate cacert;
    private final CA testx509ca;
    private static final X500Name SUBJECT_DN= CertTools.stringToBcX500Name("O=  Nested Inc., CN= nestedCMPTest, O=SE");
    private final String issuerDN;
    private final CmpConfiguration cmpConfiguration;
    private static final String cmpAlias = "NestedMessageContentTstConfAlias";
    private static final String CMPTESTPROFILE = "CMPTESTPROFILE";
    private String raCertsPath = "/tmp/racerts";
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("NestedMessageContentTest");
        EndEntityManagementSession endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        for (final String username : Arrays.asList("cmpTestAdmin", "nestedCMPTest")) {
            try {
                endEntityManagementSession.revokeAndDeleteUser(admin, username, ReasonFlags.keyCompromise);
            } catch (Exception e){
                log.debug(e.getMessage());
            }
        }
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        internalCertificateStoreSession.removeCertificatesBySubject(SUBJECT_DN.toString());
    }

    public NestedMessageContentTest() throws Exception {
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);

        this.issuerDN = "CN=TestCA";
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        this.testx509ca = CaTestUtils.createTestX509CA(this.issuerDN, null, false, keyusage);
        this.caid = this.testx509ca.getCAId();
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        this.caSession.addCA(this.admin, this.testx509ca); 

        // Create a temporary directory to store ra certificates, use JUnits TemporaryFolder that is deleted on exit
        final File createdFolder = this.folder.newFolder("racerts");
        this.raCertsPath = createdFolder.getCanonicalPath();
        
        // Configure CMP for this test, we allow custom certificate serial numbers
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowValidityOverride(true);
        profile.setAllowDNOverride(true);
        profile.saveData();
        this.certProfileSession.removeCertificateProfile(this.admin, CMPTESTPROFILE);
        try {
            this.certProfileSession.addCertificateProfile(this.admin, CMPTESTPROFILE, profile);
        } catch (CertificateProfileExistsException e) {
            log.error("Could not create certificate profile.", e);
        }
        int cpId = this.certProfileSession.getCertificateProfileId(CMPTESTPROFILE);
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES,0, "" + cpId);
        eep.addField(DnComponents.COMMONNAME);
        eep.addField(DnComponents.ORGANIZATION);
        eep.addField(DnComponents.COUNTRY);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false);  // Don't use field from "email" data
        this.eeProfileSession.removeEndEntityProfile(this.admin, CMPTESTPROFILE);
        try {
            this.eeProfileSession.addEndEntityProfile(this.admin, CMPTESTPROFILE, eep);
        } catch (EndEntityProfileExistsException e) {
            log.error("Could not create end entity profile.", e);
        }
        final int eepId = eeProfileSession.getEndEntityProfileId(CMPTESTPROFILE);
        
        // Configure CMP for this test
        this.cmpConfiguration.addAlias(cmpAlias);
        this.cmpConfiguration.setRAMode(cmpAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(cmpAlias, true);
        this.cmpConfiguration.setRAEEProfile(cmpAlias, String.valueOf(eepId));
        this.cmpConfiguration.setRACertProfile(cmpAlias, CMPTESTPROFILE);
        this.cmpConfiguration.setRACAName(cmpAlias, "TestCA");
        this.cmpConfiguration.setRANameGenScheme(cmpAlias, "DN");
        this.cmpConfiguration.setRANameGenParams(cmpAlias, "CN");
        this.cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "TestCA;foo123");
        this.cmpConfiguration.setRACertPath(cmpAlias, this.raCertsPath);
        this.globalConfigurationSession.saveConfiguration(this.admin, this.cmpConfiguration);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();        
        // The TemporaryFolder and all it's contents are guaranteed to be deleted automaticallly by JUnit
        // so we don't have to delete temporary files
        
        CaTestUtils.removeCa(this.admin, testx509ca.getCAInfo());
        
        this.cmpConfiguration.removeAlias(cmpAlias);
        this.globalConfigurationSession.saveConfiguration(this.admin, this.cmpConfiguration);
        
        this.certProfileSession.removeCertificateProfile(this.admin, CMPTESTPROFILE);
        this.eeProfileSession.removeEndEntityProfile(this.admin, CMPTESTPROFILE);
    }

    @Test
    public void test01CrmfReq() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException,
            EjbcaException, EndEntityProfileValidationException, WaitingForApprovalException, Exception {
        
        //-----------------Creating CRMF request
        //PKIMessage crmfMsg = createEESignedCrmfReq(this.subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        Date nb = new Date((new Date()).getTime() - 31536000000L); // not before a year ago
        Date na = new Date((new Date()).getTime() + 31536000000L); // not afer a yeat from now
        assertNotNull(nb);
        assertNotNull(na);

        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage crmfMsg = genCertReq(this.issuerDN, SUBJECT_DN, keys, this.cacert, senderNonce, transactionID, false, null, nb, na, null, pAlg, new DEROctetString(senderNonce));

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate[] cmpcert = getCMPCert(admCert);
        crmfMsg = CmpMessageHelper.buildCertBasedPKIProtection(crmfMsg, cmpcert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(crmfMsg);
        CertReqMessages ir = (CertReqMessages) crmfMsg.getBody().getContent();
        int reqID = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
              
        //------------------Creating NestedMessageContent
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name(reqSubjectDN)), 
                    new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
      
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, seq);
        assertNotNull("Failed to create nested Message PKIBody", pkiBody);
        
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        assertNotNull("Failed to created nested message PKIMessage", pkiMessage);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        assertEquals("RACertPath is suppose to be '" + this.raCertsPath + "', instead it is '" + this.cmpConfiguration.getRACertPath(cmpAlias) + "'.", this.cmpConfiguration.getRACertPath(cmpAlias), this.raCertsPath);
        createRACertificate("raCrmfSigner", "foo123", this.raCertsPath, cmpAlias, raKeys, null, null, CMPTESTPROFILE, this.caid);
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
            
            
        assertNotNull("Failed to create pkiIHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);

        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, this.issuerDN, SUBJECT_DN, this.cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), 
                            crmfMsg.getHeader().getTransactionID().getOctets(), false, null, 
                            PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        final Certificate cert = checkCmpCertRepMessage(cmpConfiguration, cmpAlias, SUBJECT_DN, this.cacert, resp, reqID);
        assertTrue(cert instanceof X509Certificate);
        log.debug("Subject DN of created certificate: "+X500Name.getInstance(((X509Certificate)cert).getSubjectX500Principal().getEncoded()));
        assertNotNull("CrmfRequest did not return a certificate", cert);
        
        removeAuthenticationToken(adminToken, admCert, adminName);
    }
    
    @Test
    public void test02Verify() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException,
            EndEntityProfileValidationException, WaitingForApprovalException, Exception {
        
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(this.subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        Date nb = new Date((new Date()).getTime() - 31536000000L); // not before a year ago
        Date na = new Date((new Date()).getTime() + 31536000000L); // not afer a yeat from now
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(this.issuerDN, SUBJECT_DN, keys, this.cacert, senderNonce, transactionID, false, null, 
                nb, na, null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);
        
        // ---------------- Creating the NestedMessageContent ----------------------
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name(reqSubjectDN)),
                new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        //pkiHeaderBuilder.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, crmfMsg);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raSignerVerify", "foo123", this.raCertsPath, cmpAlias, raKeys, null, null, CMPTESTPROFILE, this.caid);
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), null, BouncyCastleProvider.PROVIDER_NAME);

        assertNotNull("Failed to create pkiHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);
            
        NestedMessageContent nestedMsg = new NestedMessageContent(pkiMessage, this.cmpConfiguration, cmpAlias);
        boolean verify = nestedMsg.verify();
        assertTrue("NestedMessageVerification failed.", verify);
    }
    
    @Test
    public void test03RevReq()
            throws NoSuchAlgorithmException, AuthorizationDeniedException, EjbcaException, IOException, InvalidAlgorithmParameterException,
            RoleNotFoundException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchEndEntityException,
            CertificateException, CADoesntExistsException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException, EndEntityProfileValidationException, CouldNotRemoveEndEntityException,
            WaitingForApprovalException, NoSuchEndEntityException, ObjectNotFoundException, javax.ejb.ObjectNotFoundException {
        Collection<Certificate> certs = this.certificateStoreSession.findCertificatesBySubjectAndIssuer(SUBJECT_DN.toString(), this.issuerDN);
        log.debug("Found " + certs.size() + " certificates for userDN \"" + SUBJECT_DN + "\"");
        Certificate cert = null;
        for(Certificate tmp : certs) {
            if(!this.certificateStoreSession.isRevoked(this.issuerDN, CertTools.getSerialNumber(tmp))) {
                cert = tmp;
                break;
            }
        }
        assertNotNull("Could not find a suitable certificate to revoke.", cert);
    
        //----------- creating the revocation signed request-------------------
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage revMsg = genRevReq(this.issuerDN, SUBJECT_DN, CertTools.getSerialNumber(cert), this.cacert, nonce, transid, false, pAlg, new DEROctetString(nonce)); 
        assertNotNull("Generating CrmfRequest failed." + revMsg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE");
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate[] cmpcert = getCMPCert(admCert);
        revMsg = CmpMessageHelper.buildCertBasedPKIProtection(revMsg, cmpcert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(revMsg);
        
        
        //----------------- Creating the nested PKIMessage -----------------------
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] reqNonce = CmpMessageHelper.createSenderNonce();
        final byte[] reqTransid = CmpMessageHelper.createSenderNonce();
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name(reqSubjectDN)),
                new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(reqNonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(reqTransid));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( revMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, seq);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raRevSigner", "foo123", this.raCertsPath, cmpAlias, raKeys, null, null, CMPTESTPROFILE, this.caid);
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
            
        assertNotNull("Failed to create pkiHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);

        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);        
        checkCmpResponseGeneral(resp, this.issuerDN, SUBJECT_DN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        int revStatus = checkRevokeStatus(this.issuerDN, CertTools.getSerialNumber(cert));
        assertNotEquals("Revocation request failed to revoke the certificate", Integer.valueOf(RevokedCertInfo.NOT_REVOKED), Integer.valueOf(revStatus));
        
        removeAuthenticationToken(adminToken, admCert, adminName);
    }

    @Test
    public void test04CrmfRACertExist() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException,
            EjbcaException, EndEntityProfileValidationException, WaitingForApprovalException, Exception {
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(this.subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        Date nb = new Date((new Date()).getTime() - 31536000000L); // not before a year ago
        Date na = new Date((new Date()).getTime() + 31536000000L); // not afer a yeat from now
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfReqMsg = genCertReq(this.issuerDN, SUBJECT_DN, keys, this.cacert, senderNonce, transactionID, false, null, 
                nb, na, null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfReqMsg);
        PKIMessage crmfMsg = protectPKIMessage(crmfReqMsg, false, "foo123", 567);
        CertReqMessages ir = (CertReqMessages) crmfMsg.getBody().getContent();
        int reqID = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        
        // ---------------- Creating the NestedMessageContent ----------------------
        X500Name reqSubjectDN = new X500Name("CN=bogusSubjectNested");
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(reqSubjectDN),
                new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, seq);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raSignerTest04", "foo123", this.raCertsPath, cmpAlias, raKeys, null, null, CMPTESTPROFILE, this.caid);
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), null, BouncyCastleProvider.PROVIDER_NAME);
            
        assertNotNull("Failed to create pkiHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);

        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, this.issuerDN, reqSubjectDN, this.cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), 
                        crmfMsg.getHeader().getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        final Certificate cert = checkCmpCertRepMessage(cmpConfiguration, cmpAlias, SUBJECT_DN, this.cacert, resp, reqID);
        assertNotNull("CrmfRequest did not return a certificate", cert);
        assertTrue(cert instanceof X509Certificate);
        log.debug("Subject DN of created certificate: "+X500Name.getInstance(((X509Certificate)cert).getSubjectX500Principal().getEncoded()));
        
        NestedMessageContent nestedContent = new NestedMessageContent(pkiMessage, this.cmpConfiguration, cmpAlias);
        boolean ret = nestedContent.verify();
        assertTrue("The message verification failed, yet the a certificate was returned.", ret);
        
    }

    @Test
    public void test05CrmfRACertDoesNotExist() throws ObjectNotFoundException, InvalidKeyException, SignatureException, Exception {
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(this.subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        Date nb = new Date((new Date()).getTime() - 31536000000L); // not before a year ago
        Date na = new Date((new Date()).getTime() + 31536000000L); // not afer a yeat from now
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(this.issuerDN, SUBJECT_DN, keys, this.cacert, senderNonce, transactionID, false, null, 
                nb, na, null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name(reqSubjectDN)),
                new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setRecipNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, crmfMsg);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        // Don't create a certificate, so there is no RA cert authorized on the server side.
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), null, BouncyCastleProvider.PROVIDER_NAME);
            
        assertNotNull("Failed to create pkiHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);

        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);

        PKIMessage respObject = PKIMessage.getInstance(resp);
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(PKIBody.TYPE_ERROR, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA, signature verification on NestedMessageContent failed.", errMsg);
        
        NestedMessageContent nestedContent = new NestedMessageContent(pkiMessage, this.cmpConfiguration, cmpAlias);
        boolean ret = nestedContent.verify();
        assertFalse("The message verification failed, yet the a certificate was returned.", ret);
    }
    
    @Test
    public void test06NotNestedMessage() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, EndEntityProfileValidationException, WaitingForApprovalException, Exception {
        
        ASN1EncodableVector optionaValidityV = new ASN1EncodableVector();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        optionaValidityV.add(new DERTaggedObject(true, 0, nb));
        optionaValidityV.add(new DERTaggedObject(true, 1, na));
        OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionaValidityV));

        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        certTemplateBuilder.setValidity( myOptionalValidity );
        certTemplateBuilder.setIssuer(new X500Name(this.issuerDN));
        certTemplateBuilder.setSubject(SUBJECT_DN);
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        certTemplateBuilder.setPublicKey(keyInfo);
        // If we did not pass any extensions as parameter, we will create some of our own, standard ones

        final Extensions exts;
        {
            X509KeyUsage keyUsage = new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment | X509KeyUsage.nonRepudiation);
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream.create(bOut, ASN1Encoding.DER).writeObject(keyUsage);
            byte[] value = bOut.toByteArray();
            ExtensionsGenerator extgen = new ExtensionsGenerator();
            extgen.addExtension(Extension.keyUsage, false, new DEROctetString(value));
            // Make the complete extension package
            exts = extgen.generate();
        }
        certTemplateBuilder.setExtensions(exts);
        CertRequest certRequest = new CertRequest(4, certTemplateBuilder.build(), null);
        ProofOfPossession proofOfPossession = new ProofOfPossession();
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
        AttributeTypeAndValue[] avs = {av};
        CertReqMsg certReqMsg = new CertReqMsg(certRequest, proofOfPossession, avs);
        CertReqMessages certReqMessages = new CertReqMessages(certReqMsg);

        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(SUBJECT_DN),
                new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, certReqMessages);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raSignerTest06", "foo123", this.raCertsPath, cmpAlias, raKeys, null, null, CMPTESTPROFILE, this.caid);
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), null, BouncyCastleProvider.PROVIDER_NAME);
        
        assertNotNull("Failed to create PKIHeader", pkiHeaderBuilder);
        assertNotNull("Failed to create PKIBody", pkiBody);
        assertNotNull("Failed to create PKIMessage", pkiMessage);
        
        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);

        PKIMessage respObject = PKIMessage.getInstance(resp);
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(PKIBody.TYPE_ERROR, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("unknown object in getInstance: org.bouncycastle.asn1.DLSequence", errMsg);
    }
    
    @Test
    public void test07ExpiredRACert() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException,
            EjbcaException, EndEntityProfileValidationException, WaitingForApprovalException, Exception {
        log.info(">test07ExpiredRACert()");
        //------------------- Creating Certificate Request ---------------
        //PKIMessage crmfMsg = createEESignedCrmfReq(this.subjectDN);
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        Date nb = new Date((new Date()).getTime() - 31536000000L); // not before a year ago
        Date na = new Date((new Date()).getTime() + 31536000000L); // not afer a yeat from now
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(this.issuerDN, SUBJECT_DN, keys, this.cacert, senderNonce, transactionID, false, null, 
                nb, na, null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        
        final X500Name reqSubjectDN = new X500Name("CN=bogusSubjectNested");
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(reqSubjectDN),
                new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        pkiHeaderBuilder.setRecipNonce(new DEROctetString(nonce));

        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, crmfMsg);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        
        long nbTime = (new Date()).getTime() - 1000000L;
        createRACertificate("raExpiredSignerTest07", "foo123", this.raCertsPath, cmpAlias, raKeys, new Date(nbTime), new Date(), CMPTESTPROFILE, this.caid);
        Thread.sleep(5000);
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), null, BouncyCastleProvider.PROVIDER_NAME);
        
        assertNotNull("Failed to create pkiHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);

        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        // do not check signing if we expect a failure (sFailMessage==null)
        
        checkCmpResponseGeneral(resp, this.issuerDN, reqSubjectDN, this.cacert, pkiMessage.getHeader().getSenderNonce().getOctets(), 
                            pkiMessage.getHeader().getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        PKIMessage respObject = PKIMessage.getInstance(resp);
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(PKIBody.TYPE_ERROR, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA, signature verification on NestedMessageContent failed.", errMsg);
        log.info("<test07ExpiredRACert()");
    }
    
    @Test
    public void test08MissingSignature() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, EndEntityProfileValidationException, WaitingForApprovalException, Exception {
        log.info(">test07ExpiredRACert()");
        //------------------- Creating Certificate Request ---------------
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        Date nb = new Date((new Date()).getTime() - 31536000000L); // not before a year ago
        Date na = new Date((new Date()).getTime() + 31536000000L); // not afer a yeat from now
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage crmfMsg = genCertReq(this.issuerDN, SUBJECT_DN, keys, this.cacert, senderNonce, transactionID, false, null, 
                nb, na, null, null, null);
        assertNotNull("Failed to create crmfMsg.", crmfMsg);        
        
        // ---------------- Creating the NestedMessageContent ----------------------
        
        final X500Name reqSubjectDN = new X500Name("CN=bogusSubjectNested");
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(reqSubjectDN), 
                new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        pkiHeaderBuilder.setRecipNonce(new DEROctetString(nonce));

        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, crmfMsg);
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
            
        assertNotNull("Failed to create pkiHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);

        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        // do not check signing if we expect a failure (sFailMessage==null)
        
        checkCmpResponseGeneral(resp, this.issuerDN, reqSubjectDN, this.cacert, pkiMessage.getHeader().getSenderNonce().getOctets(), 
                            pkiMessage.getHeader().getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        PKIMessage respObject = PKIMessage.getInstance(resp);
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(PKIBody.TYPE_ERROR, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("Wrong error message", "Could not verify the RA, signature verification on NestedMessageContent failed.", errMsg);
        log.info("<test07ExpiredRACert()");
    }
    
    @Test
    public void test09CrmfWrongIssuerAndDoNotCheckAdmin() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, EndEntityProfileValidationException, WaitingForApprovalException, Exception {
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "-;foo123");
        this.cmpConfiguration.setOmitVerificationsInECC(cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(this.admin, this.cmpConfiguration);
        //-----------------Creating CRMF request
        byte[] senderNonce = CmpMessageHelper.createSenderNonce();
        byte[] transactionID = CmpMessageHelper.createSenderNonce();
        Date nb = new Date((new Date()).getTime() - 31536000000L); // not before a year ago
        Date na = new Date((new Date()).getTime() + 31536000000L); // not afer a yeat from now
        assertNotNull(nb);
        assertNotNull(na);
        
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage crmfMsg = genCertReq(this.issuerDN, SUBJECT_DN, keys, this.cacert, senderNonce, transactionID, false, null, 
                nb, na, null, pAlg, new DEROctetString(senderNonce));

        KeyPair nonAdminKeys = KeyTools.genKeys("1024", "RSA");
        Certificate nonAdminCert = CertTools.genSelfCert("CN=cmpTestAdmin,C=SE", 365, null, nonAdminKeys.getPrivate(), nonAdminKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        CMPCertificate[] cmpcert = getCMPCert(nonAdminCert);
        crmfMsg = CmpMessageHelper.buildCertBasedPKIProtection(crmfMsg, cmpcert, nonAdminKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(crmfMsg);
        CertReqMessages ir = (CertReqMessages) crmfMsg.getBody().getContent();
        int reqID = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        
        //------------------Creating NestedMessageContent
        String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
        PKIHeaderBuilder pkiHeaderBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name(reqSubjectDN)), 
                    new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
        pkiHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeaderBuilder.setSenderNonce(new DEROctetString(nonce));
        pkiHeaderBuilder.setTransactionID(new DEROctetString(transid));
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( crmfMsg );
        DERSequence seq = new DERSequence(v);
        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_NESTED, seq);
        assertNotNull("Failed to create nested Message PKIBody", pkiBody);
        
        PKIMessage pkiMessage = new PKIMessage(pkiHeaderBuilder.build(), pkiBody);
        assertNotNull("Failed to created nested message PKIMessage", pkiMessage);
        KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
        createRACertificate("raCrmfSigner", "foo123", this.raCertsPath, cmpAlias, raKeys, null, null, CMPTESTPROFILE, this.caid);
        pkiMessage = CmpMessageHelper.buildCertBasedPKIProtection(pkiMessage, null, raKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            
            
        assertNotNull("Failed to create pkiHeader", pkiHeaderBuilder);
        assertNotNull("pkiBody is null", pkiBody);
        assertNotNull("pkiMessage is null", pkiMessage);

        final byte[] ba = CmpMessageHelper.pkiMessageToByteArray(pkiMessage);
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, this.issuerDN, SUBJECT_DN, this.cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), 
                        crmfMsg.getHeader().getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        final Certificate cert = checkCmpCertRepMessage(cmpConfiguration, cmpAlias, SUBJECT_DN, this.cacert, resp, reqID);
        assertNotNull("CrmfRequest did not return a certificate", cert);
        assertTrue(cert instanceof X509Certificate);
        log.debug("Subject DN of created certificate: "+X500Name.getInstance(((X509Certificate)cert).getSubjectX500Principal().getEncoded()));
    }   
    
    private static X509Certificate getCertFromCredentials(AuthenticationToken authToken) {
        X509Certificate certificate = null;
        Set<?> inputcreds = authToken.getCredentials();
        if (inputcreds != null) {
            for (Object object : inputcreds) {
                if (object instanceof X509Certificate) {
                    certificate = (X509Certificate) object;
                }
            }           
        }
        return certificate;
    }
    
    private AuthenticationToken createAdminToken(KeyPair keys, String name, String dn) throws RoleNotFoundException, AuthorizationDeniedException {
        Set<Principal> principals = new HashSet<>();
        X500Principal p = new X500Principal(dn);
        principals.add(p);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        AuthenticationToken token = createTokenWithCert(name, subject, keys);
        X509Certificate cert = (X509Certificate) token.getCredentials().iterator().next();

        // Initialize the role mgmt system with this role that is allowed to edit roles
        String roleName = getRoleName();
        final Role role = roleSession.getRole(ADMIN, null, roleName);
        roleMemberSession.persist(ADMIN, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                CertTools.getIssuerDN(cert).hashCode(), X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), CertTools.getSerialNumberAsString(cert), role.getRoleId(), null));
        return token;
    }
    
    private AuthenticationToken createTokenWithCert(String adminName, AuthenticationSubject subject, KeyPair keys) {
        // A small check if we have added a "fail" credential to the subject.
        // If we have we will return null, so we can test authentication failure.
        Set<?> usercredentials = subject.getCredentials();
        if ((usercredentials != null) && (usercredentials.size() > 0)) {
            Object o = usercredentials.iterator().next();
            if (o instanceof String) {
                String str = (String) o;
                if (StringUtils.equals("fail", str)) {
                    return null;
                }
            }
        }
        // If there was no certificate input, create a self signed
        String dn = "C=SE,O=Test,CN=Test"; // default
        // If we have created a subject with an X500Principal we will use this DN to create the dummy certificate.
        {
            final Set<Principal> principals = subject.getPrincipals();
            if ((principals != null) && (principals.size() > 0)) {
                final Principal p = principals.iterator().next();
                if (p instanceof X500Principal) {
                    X500Principal xp = (X500Principal)p;
                    dn = xp.getName();
                }
            }
        }
        try {
            createUser(adminName, dn, "foo123", this.caid);
        } catch (AuthorizationDeniedException | EndEntityProfileValidationException | WaitingForApprovalException | EjbcaException |
                NoSuchEndEntityException | CADoesntExistsException | CertificateSerialNumberException | IllegalNameException | RuntimeException e) {
            throw new IllegalStateException("Error encountered when creating this.admin user", e);
        }
        X509Certificate certificate = null;
        try {
            certificate = (X509Certificate) this.signSession.createCertificate(this.admin, adminName, "foo123",
                    new PublicKeyWrapper(keys.getPublic()));
        } catch (IllegalKeyException | CertificateCreateException | IllegalNameException | CertificateRevokeException
                | CertificateSerialNumberException | CryptoTokenOfflineException | IllegalValidityException | CAOfflineException
                | InvalidAlgorithmException | CustomCertificateSerialNumberException | CADoesntExistsException | AuthorizationDeniedException
                | NoSuchEndEntityException | AuthStatusException | AuthLoginException e) {
            throw new IllegalStateException("Error encountered when creating certificate", e);
        }
        // We cannot use the X509CertificateAuthenticationToken here, since it can only be used internally in a JVM.
        AuthenticationToken result = new TestX509CertificateAuthenticationToken(certificate);
        return result;
    }
    
    private void removeAuthenticationToken(AuthenticationToken authToken, Certificate cert, String adminName) throws RoleNotFoundException,
            AuthorizationDeniedException, ApprovalException, NoSuchEndEntityException, WaitingForApprovalException, CouldNotRemoveEndEntityException {
        String rolename = getRoleName();
        if (cert!=null) {
            final Role role = roleSession.getRole(ADMIN, null, rolename);
            if (role!=null) {
                final String tokenMatchValue = CertTools.getSerialNumberAsString(cert);
                for (final RoleMember roleMember : roleMemberSession.getRoleMembersByRoleId(ADMIN, role.getRoleId())) {
                    if (tokenMatchValue.equals(roleMember.getTokenMatchValue())) {
                        roleMemberSession.remove(ADMIN, roleMember.getId());
                    }
                }
            }
        }
        this.endEntityManagementSession.revokeAndDeleteUser(this.admin, adminName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);        
    }
    
    private static CMPCertificate[] getCMPCert(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        try {
            ASN1Primitive pcert = ins.readObject();
            org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
            CMPCertificate[] res = {new CMPCertificate(c)};
            return res;
        } finally {
            ins.close();
        }
    }
}
