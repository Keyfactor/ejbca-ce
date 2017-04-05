package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.RemoveException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
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
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class DefaultProfileTest extends CmpTestCase {
    
    private static final Logger log = Logger.getLogger(AuthenticationModulesTest.class);

    private static final String USERNAME = "DefaultProfileTestUser";
    private static final X500Name USERDN = new X500Name("CN=" + USERNAME);
    private final byte[] nonce;
    private final byte[] transid;
    private final CmpConfiguration cmpConfiguration;
    private final static String ALIAS = "DefaultProfileTestConfAlias";

    private final int caid1;
    private final X509Certificate cacert1;
    private final X509CA ca1;
    
    private final int caid2;
    private final X509Certificate cacert2;
    private final X509CA ca2;
    
    private final String EEP_NAME = "CmpEndEntityProfile";
    private int eepid;
    private final String CP_NAME = "CmpCertificateProfile";
    private int cpid;


    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final EndEntityAccessSession eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

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
        Role role = roleSession.getRole(ADMIN, null, "DefaultProfileTest");
        roleSession.deleteRoleIdempotent(ADMIN, role.getRoleId());
    }
    
    public DefaultProfileTest() throws Exception {
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);

        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        ca1 = CaTestUtils.createTestX509CA("CN=CmpTestCA1", null, false, keyusage);
        caid1 = ca1.getCAId();
        cacert1 = (X509Certificate) ca1.getCACertificate();
        caSession.addCA(ADMIN, ca1);

        ca2 = CaTestUtils.createTestX509CA("CN=CmpTestCA2", null, false, keyusage);
        caid2 = ca2.getCAId();
        cacert2 = (X509Certificate) ca2.getCACertificate();
        caSession.addCA(ADMIN, ca2);

        nonce = CmpMessageHelper.createSenderNonce();
        transid = CmpMessageHelper.createSenderNonce();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        CertificateProfile cp = new CertificateProfile();
        ArrayList<Integer> availablecas = new ArrayList<Integer>();
        availablecas.add(caid1);
        availablecas.add(caid2);
        cp.setAvailableCAs(availablecas);
        cpid = certProfileSession.addCertificateProfile(ADMIN, CP_NAME, cp);
        
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setAvailableCAs(availablecas);
        eep.setValue(EndEntityProfile.DEFAULTCA, 0, ""+caid1);
        ArrayList<Integer> availablecps = new ArrayList<Integer>();
        availablecps.add(cpid);
        availablecps.add(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        eep.setAvailableCertificateProfileIds(availablecps);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, ""+cpid);
        endEntityProfileSession.addEndEntityProfile(ADMIN, EEP_NAME, eep);
        eepid = endEntityProfileSession.getEndEntityProfileId(EEP_NAME);

        cmpConfiguration.addAlias(ALIAS);
        cmpConfiguration.setRAMode(ALIAS, true);
        cmpConfiguration.setRAEEProfile(ALIAS, String.valueOf(eepid));
        cmpConfiguration.setExtractUsernameComponent(ALIAS, "CN");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        cmpConfiguration.removeAlias(ALIAS);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        endEntityProfileSession.removeEndEntityProfile(ADMIN, EEP_NAME);
        certProfileSession.removeCertificateProfile(ADMIN, CP_NAME);
        
        CryptoTokenTestUtils.removeCryptoToken(null, ca1.getCAToken().getCryptoTokenId());
        caSession.removeCA(ADMIN, caid1);
        
        CryptoTokenTestUtils.removeCryptoToken(null, ca2.getCAToken().getCryptoTokenId());
        caSession.removeCA(ADMIN, caid2);

    }


    @Test
    public void test01CrmfHMACCertProfileDefault() throws Exception {
        log.trace(">test01CrmfHMACCertProfileDefault()");

        String fingerprint = null;
        
        // First try with a specific certificate profile set
        try {
            cmpConfiguration.setRACertProfile(ALIAS, certProfileSession.getCertificateProfileName(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
            cmpConfiguration.setRACAName(ALIAS, ca1.getName());
            globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
            
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            // Using the CMP RA Authentication secret 
            PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            fingerprint = getCertFpFromCMPResponse(msg, resp, cacert1);
            
            EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
            assertNotNull("Failed to create end entity", ee);
            assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, ee.getCertificateProfileId());
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fingerprint);
        }
        

        // Now try with the default certificate profile
        try {
            cmpConfiguration.setRACertProfile(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
            cmpConfiguration.setRACAName(ALIAS, ca1.getName());
            globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
            
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            // Using the CMP RA Authentication secret 
            PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            fingerprint = getCertFpFromCMPResponse(msg, resp, cacert1);
            
            EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
            assertNotNull("Failed to create end entity", ee);
            assertEquals(cpid, ee.getCertificateProfileId());
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fingerprint);
        }
        
        log.trace("<test01CrmfHMACCertProfileDefault()");
    }

    

    @Test
    public void test02CrmfHMACCADefault() throws Exception {
        log.trace(">test02CrmfHMACCADefault()");

        String fingerprint = null;
        
        // First try with a specific CA set
        try {
            cmpConfiguration.setRACertProfile(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
            cmpConfiguration.setRACAName(ALIAS, ca2.getName());
            globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
            
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            // Using the CMP RA Authentication secret 
            PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            fingerprint = getCertFpFromCMPResponse(msg, resp, cacert2);
            
            EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
            assertNotNull("Failed to create end entity", ee);
            assertEquals(cpid, ee.getCertificateProfileId());
            assertEquals(caid2, ee.getCAId());
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fingerprint);
        }
        

        // Now try with the default CA
        try {
            cmpConfiguration.setRACertProfile(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
            cmpConfiguration.setRACAName(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
            globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
            
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            // Using the CMP RA Authentication secret 
            PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            fingerprint = getCertFpFromCMPResponse(msg, resp, cacert1);
            
            EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
            assertNotNull("Failed to create end entity", ee);
            assertEquals(cpid, ee.getCertificateProfileId());
            assertEquals(caid1, ee.getCAId());
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fingerprint);
        }

        
        log.trace("<test02CrmfHMACCADefault()");
    }

   
    @Test
    public void test03CrmfEECCertProfileDefault() throws Exception {
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, ca1.getName());

        final String admUsername = "cmpAdminUsername";
        final KeyPair admkeys = KeyTools.genKeys("512", "RSA");
        final AuthenticationToken admToken = createAdminToken(admkeys, admUsername, "CN="+admUsername+",C=SE", caid1, eepid,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final Certificate admCert = getCertFromCredentials(admToken);
        final CMPCertificate[] extraCert = getCMPCert(admCert);

        try {
            String fp = "";
            
            // Try with a specific certificate profile first
            try {
                cmpConfiguration.setRACertProfile(ALIAS, certProfileSession.getCertificateProfileName(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
                cmpConfiguration.setRACAName(ALIAS, ca1.getName());
                globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
                
                KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, pAlg,
                        new DEROctetString(nonce));
                assertNotNull("Generating CrmfRequest failed.", msg);
                msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
                assertNotNull(msg);
    
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
                fp = getCertFpFromCMPResponse(msg, resp, cacert1);
                
                EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
                assertNotNull("Failed to create end entity", ee);
                assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, ee.getCertificateProfileId());
            } finally {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
                internalCertStoreSession.removeCertificate(fp);
            }
            
            // Try with end entity profile default certificate profile
            try {
                cmpConfiguration.setRACertProfile(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
                cmpConfiguration.setRACAName(ALIAS, ca1.getName());
                globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
                
                KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, pAlg,
                        new DEROctetString(nonce));
                assertNotNull("Generating CrmfRequest failed.", msg);
                msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
                assertNotNull(msg);
    
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
                fp = getCertFpFromCMPResponse(msg, resp, cacert1);
                
                EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
                assertNotNull("Failed to create end entity", ee);
                assertEquals(cpid, ee.getCertificateProfileId());
            } finally {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
                internalCertStoreSession.removeCertificate(fp);
            }
      
        } finally {
            removeAuthenticationToken(admToken, admCert, admUsername); // also removes testUsername
        }
    }
    
    @Test
    public void test04CrmfEECCAProfileDefault() throws Exception {
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, ca1.getName());

        final String admUsername = "cmpAdminUsername";
        final KeyPair admkeys = KeyTools.genKeys("512", "RSA");
        final AuthenticationToken admToken = createAdminToken(admkeys, admUsername, "CN="+admUsername+",C=SE", caid1, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final Certificate admCert = getCertFromCredentials(admToken);
        final CMPCertificate[] extraCert = getCMPCert(admCert);

        try {
            String fp = "";
            
            // Try with a specific CA first
            try {
                cmpConfiguration.setRACertProfile(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
                cmpConfiguration.setRACAName(ALIAS, ca2.getName());
                globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
                
                KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, pAlg,
                        new DEROctetString(nonce));
                assertNotNull("Generating CrmfRequest failed.", msg);
                msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
                assertNotNull(msg);
    
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
                fp = getCertFpFromCMPResponse(msg, resp, cacert2);
                
                EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
                assertNotNull("Failed to create end entity", ee);
                assertEquals(cpid, ee.getCertificateProfileId());
                assertEquals(caid2, ee.getCAId());
            } finally {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
                internalCertStoreSession.removeCertificate(fp);
            }
            
            // Try with end entity profile default CA
            try {
                cmpConfiguration.setRACertProfile(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
                cmpConfiguration.setRACAName(ALIAS, CmpConfiguration.PROFILE_DEFAULT);
                globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
                
                KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                PKIMessage msg = genCertReq(ca1.getSubjectDN(), USERDN, keys, cacert1, nonce, transid, false, null, null, null, null, pAlg,
                        new DEROctetString(nonce));
                assertNotNull("Generating CrmfRequest failed.", msg);    
                msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
                assertNotNull(msg);
    
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200, ALIAS);
                fp = getCertFpFromCMPResponse(msg, resp, cacert1);
                
                EndEntityInformation ee = eeAccessSession.findUser(ADMIN, USERNAME);
                assertNotNull("Failed to create end entity", ee);
                assertEquals(cpid, ee.getCertificateProfileId());
                assertEquals(caid1, ee.getCAId());
            } finally {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
                internalCertStoreSession.removeCertificate(fp);
            }
        } finally {
            removeAuthenticationToken(admToken, admCert, admUsername); // also removes testUsername
        }
    } 

    @Test
    public void test05KeyUpdateDefaultCAAndCertProfile() throws Exception {
        if(log.isTraceEnabled()) {
            log.trace(">test05KeyUpdateDefaultCAAndCertProfile");
        }
        
        cmpConfiguration.setRACertProfile(ALIAS, certProfileSession.getCertificateProfileName(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER)); // ENDUSER
        cmpConfiguration.setRACAName(ALIAS, CmpConfiguration.PROFILE_DEFAULT); // testx509ca1
        cmpConfiguration.setCMPDefaultCA(ALIAS, ca1.getName());
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(ALIAS, ca1.getName());
        cmpConfiguration.setKurAllowAutomaticUpdate(ALIAS, true);
        cmpConfiguration.setKurAllowSameKey(ALIAS, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
        
        final String admUsername = "cmpAdminUsername";
        final KeyPair admkeys = KeyTools.genKeys("512", "RSA");
        final AuthenticationToken admToken = createAdminToken(admkeys, admUsername, "CN="+admUsername+",C=SE", caid1, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final Certificate admCert = getCertFromCredentials(admToken);
        final CMPCertificate[] extraCert = getCMPCert(admCert);
        
        String fp1="", fp2="";
        
        try {
            createUser(USERNAME, USERDN.toString(), "foo123", true, caid2, eepid, cpid);
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final Certificate certificate = signSession.createCertificate(ADMIN, USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
            assertNotNull("Failed to create a test certificate", certificate);
            fp1 = CertTools.getFingerprintAsString(certificate);
    
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage req = genRenewalReq(USERDN, cacert2, nonce, transid, keys, false, USERDN, ca2.getSubjectDN(), pAlg, new DEROctetString(nonce));
            assertNotNull("Failed to generate a CMP renewal request", req);
            CertReqMessages kur = (CertReqMessages) req.getBody().getContent();
            final int reqId = kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(req);
            
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, ALIAS);
            
            checkCmpResponseGeneral(resp, ca2.getSubjectDN(), USERDN, cacert2, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkKurCertRepMessage(USERDN, cacert2, resp, reqId);
            assertNotNull("Failed to renew the certificate", cert);
            fp2 = CertTools.getFingerprintAsString(cert);
            
            // Verify that the new certificate was issued by testx509ca2 even though the CMP configuration was pointing to textx509ca1
            assertEquals(CertTools.getSubjectDN(cacert2), CertTools.getIssuerDN(cert));
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fp1);
            internalCertStoreSession.removeCertificate(fp2);
            removeAuthenticationToken(admToken, admCert, admUsername); // also removes testUsername
        }
        
        if(log.isTraceEnabled()) {
            log.trace("<test05KeyUpdateDefaultCAAndCertProfile");
        }

    }

    
    
    
    
    
    
    private String getCertFpFromCMPResponse(final PKIMessage respMsg, final byte[] response, final X509Certificate cacert) throws Exception {
        CertReqMessages ir = (CertReqMessages) respMsg.getBody().getContent();
        Certificate cert = checkCmpCertRepMessage(USERDN, cacert, response, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        return CertTools.getFingerprintAsString(cert);
    }
    
    private static CMPCertificate[] getCMPCert(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        ASN1Primitive pcert = ins.readObject();
        ins.close();
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
        CMPCertificate[] res = { new CMPCertificate(c) };
        return res;
    }

    private EndEntityInformation createUser(String username, String subjectDN, String password, boolean clearpassword, int _caid, int eepid, int cpid)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException, EjbcaException, Exception {

        EndEntityInformation user = new EndEntityInformation(username, subjectDN, _caid, null, username + "@primekey.se", new EndEntityType(
                EndEntityTypes.ENDUSER), eepid, cpid, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            endEntityManagementSession.addUser(ADMIN, username, password, subjectDN, "rfc822name=" + username + "@primekey.se", username
                    + "@primekey.se", clearpassword, eepid, cpid, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, _caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            endEntityManagementSession.changeUser(ADMIN, user, clearpassword);
            endEntityManagementSession.setUserStatus(ADMIN, username, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        return user;

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

    private AuthenticationToken createAdminToken(KeyPair keys, String name, String dn, int _caid, int eepid, int cpid) throws RoleNotFoundException,
            AuthorizationDeniedException {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(dn);
        principals.add(p);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        AuthenticationToken token = createTokenWithCert(name, subject, keys, _caid, eepid, cpid);
        assertNotNull(token);
        X509Certificate cert = (X509Certificate) token.getCredentials().iterator().next();
        assertNotNull(cert);

        // Initialize the role mgmt system with this role that is allowed to edit roles
        String roleName = getRoleName();
        final Role role = roleSession.getRole(ADMIN, null, roleName);
        roleMemberSession.persist(ADMIN, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                CertTools.getIssuerDN(cert).hashCode(), X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), CertTools.getSerialNumberAsString(cert), role.getRoleId(), null));
        return token;
    }

    private AuthenticationToken createTokenWithCert(String adminName, AuthenticationSubject subject, KeyPair keys, int _caid, int eepid, int cpid) {

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

        X509Certificate certificate = null;
        // If there was no certificate input, create a self signed
        String dn = "C=SE,O=Test,CN=Test"; // default
        // If we have created a subject with an X500Principal we will use this DN to create the dummy certificate.
        {
            Set<Principal> principals = subject.getPrincipals();
            if ((principals != null) && (principals.size() > 0)) {
                Principal p = principals.iterator().next();
                if (p instanceof X500Principal) {
                    X500Principal xp = (X500Principal) p;
                    dn = xp.getName();
                }
            }
        }

        try {
            createUser(adminName, dn, "foo123", true, _caid, eepid, cpid);
            certificate = (X509Certificate) signSession.createCertificate(ADMIN, adminName, "foo123", new PublicKeyWrapper(keys.getPublic()));
        } catch (Exception e1) {
            throw new IllegalStateException("Error encountered when creating admin user", e1);
        }
        assertNotNull(certificate);
        // We cannot use the X509CertificateAuthenticationToken here, since it can only be used internally in a JVM.
        AuthenticationToken result = new TestX509CertificateAuthenticationToken(certificate);
        assertNotNull(result);
        return result;
    }

    private void removeAuthenticationToken(AuthenticationToken authToken, Certificate cert, String adminName) throws RoleNotFoundException,
            AuthorizationDeniedException, ApprovalException, NoSuchEndEntityException, WaitingForApprovalException, RemoveException {
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
        endEntityManagementSession.revokeAndDeleteUser(ADMIN, adminName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        internalCertStoreSession.removeCertificate(cert);
    }
    
}
