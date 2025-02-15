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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import jakarta.servlet.http.HttpServletResponse;

//
// NOTES:
//
// Addd this class to the SystemTest build file.
// To run tests, use "ant test:runweb". Note that EJBCA must be in 'Non-Production' mode. 
//



// Execute tests in order as some tests depend upon a previous test
@FixMethodOrder(MethodSorters.NAME_ASCENDING)

public class ScepRenewalSystemTest extends ScepTestBase {
    private static final Logger log = Logger.getLogger(ScepRenewalSystemTest.class);

     
    private static final String TestScepCAName = "TestScepCA";
    private static final String scepAlias = TestScepCAName;
    private static final String resourceScep = "publicweb/apply/scep/" + scepAlias + "/pkiclient.exe";

    private static ScepConfiguration scepConfiguration;
    
    // Remote access to EJBs
    private static final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ProtocolScepHttpTest"));
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
//    private static final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);;
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);


    // User#1. This is the main test user
    private static final String user1Name = "ScepUserSelfTest";
    private static final String user1DN = "C=AU,O=SelfTest,CN=" + user1Name;
    private static X509Certificate user1Cert1 = null;
    private static X509Certificate user1Cert2 = null;
    private static KeyPair user1Key1 = null;
    private static KeyPair user1Key2 = null;

    // User#2. Used for one test case.
    private static final String user2Name = "ScepUserSelfTest2";
    private static final String user2DN = "C=SE,O=Selftest,CN=" + user2Name;

    private static String httpBaseUrl = "";
    
    // Details for the CA
    private static int testCAID;
    private static X509Certificate testCACert = null;
    private static CAInfo testCAinfo ;
    
    private static int eeProfileWithRenewals_2yr;
    private static int eeProfileWithRenewals_1wk;
    
    private Random rand = new Random();
    private String senderNonce = null;
    private String transId = null;
    

 
    // One-time setup
    @BeforeClass
    public static void setUp() throws Exception {
            
            CryptoProviderTools.installBCProviderIfNotAvailable();
            
            // Create a CA
            testCAID = createTestCA( TestScepCAName);
            
            // Get CA's cert
            testCAinfo = caSessionRemote.getCAInfo(admin, TestScepCAName);
            testCACert = (X509Certificate)testCAinfo.getCertificateChain().get(0);
            testCAinfo.setDoEnforceKeyRenewal(true);
            caSessionRemote.editCA(admin, testCAinfo);

            // Setup SCEP for the test CA
            scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
            scepConfiguration.addAlias(scepAlias);
            scepConfiguration.setClientCertificateRenewal(scepAlias, true);
            scepConfiguration.setAllowClientCertificateRenewalWithOldKey(scepAlias,false);
            globalConfigSession.saveConfiguration(admin, scepConfiguration);

            String httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
            String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
            httpBaseUrl = "http://" + httpHost + ":" + httpPort+"/ejbca/"+resourceScep;
            
            // Need End-ntity profiles for test Users. One profile to allow renewal 7 days before expiry, and another to allow renewals
            // two years before expiry. Allowing 2 yrs before expire will ensure renewals can occur straight away.
            EndEntityProfile profile = new EndEntityProfile( true); // need to use the true option.
            profile.setRenewDaysBeforeExpirationUsed(true);
            profile.setRenewDaysBeforeExpiration( 7);
            eeProfileWithRenewals_1wk = endEntityProfileSession.addEndEntityProfile( admin, "TestScepClientEEP_1W", profile);
            
            profile.setRenewDaysBeforeExpiration( 2*366);
            eeProfileWithRenewals_2yr = endEntityProfileSession.addEndEntityProfile( admin, "TestScepClientEEP_2y", profile);
    }

    // One-time teardown
    @AfterClass
    public static void tearDown() throws Exception {
        
        // Remove issued certs
        internalCertStoreSession.removeCertificatesByIssuer("CN="+TestScepCAName);
        internalCertStoreSession.removeCertificatesByIssuer("CN="+"TempScepTestCA");
        
        // remove users and other configuration
        try {
            endEntityManagementSession.deleteUser(admin, user1Name);
            log.debug("deleted user: " + user1Name);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.deleteUser(admin, user2Name);
            log.debug("deleted user: " + user2Name);
        } catch (Exception e) {
            // NOPMD: ignore
        }

        scepConfiguration.removeAlias(scepAlias);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        // Remove the EEPs
        endEntityProfileSession.removeEndEntityProfile(admin, "TestScepClientEEP_1W");
        endEntityProfileSession.removeEndEntityProfile(admin, "TestScepClientEEP_2y");
        
        // Remove the CAs
        org.ejbca.core.ejb.ca.CaTestCase.removeTestCA(TestScepCAName); 
        org.ejbca.core.ejb.ca.CaTestCase.removeTestCA("TempScepTestCA"); 
    }
    
    // Create a test CA
    public static int createTestCA( String caName) throws Exception {
        return org.ejbca.core.ejb.ca.CaTestCase.createTestCA( caName, 2048, "CN="+caName, CAInfo.SELFSIGNED, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, null);
    }

    
    // Change the EEP for the specified User
    protected void changeScepUserEEP(String userName, int  endEntityPolicy) throws Exception {
        EndEntityInformation data = endEntityAccessSession.findUser(admin, userName);
        data.setEndEntityProfileId(endEntityPolicy);
        endEntityManagementSession.changeUser(admin, data, false);
    }

    // Change the Status for the specified User
    protected void changeScepUserStatus(String userName, int status) throws Exception {
        endEntityManagementSession.setUserStatus(admin, userName, status);
    }



    @Test
    public void test_01_CACapsIncludesRenewal() throws Exception {
        // Check that CA capability response includes 'Renewal'
        try {
            byte[] ba = this.sendGetCACapsRequest("", 200); // Note that the Scep ALias in the URL selects the CA.
            String s = new String( ba);
            assertTrue("The CA Caps is to include 'Renewal'.",s.contains("Renewal"));
            
        } catch (IOException e) {
            fail("IO exception not expected."+e.getMessage());
        }
        
    }

    
    @Test
    public void test_02_GetCACertUsingScepAlias() throws Exception {
        // Check the Scep Alias can be used to associate the CA with the same name.
        // This is not strictly a Renewal test, but an assumed change that has been implemented (Issue#419). The
        // idea of this change is that the CA can be selected using the Scep Alias rather than including the CA Name 
        // in the 'message' string within the SCEP URL.
        // Note: The tests below assume that this change is implemented.
        
        // Check correct CA Cert is returned. Code based upon ProtocolScepHttpTest.java
        URL url = new URL(httpBaseUrl+ "?operation=GetCACert");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code is not 200 (OK)", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/x-x509-ca-cert; charset=UTF-8"
        assertEquals("application/x-x509-ca-cert", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        
        // Get the CA cert
        X509Certificate certReturned = CertTools.getCertfromByteArray(respBytes, X509Certificate.class);
        
        // Check that we got the right cert back
        assertTrue("Cert returned was not the correct CA.", certReturned.getSubjectDN().getName().equals(testCACert.getSubjectDN().getName()));
    }
    
    
    @Test
    public void test_03_SetupUserWithPasswordAuth() throws Exception {
        // Setup a test User#1 to get a certificate using SCEP, but will use password authentication (initial enrolment)
        
        //Create the User#1
        createScepUser(user1Name, user1DN, testCAID);
        changeScepUserEEP(user1Name, eeProfileWithRenewals_2yr);
        
        // Generate 1st test key for User1
        try {
            user1Key1 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1Key1, BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, null, null);
        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);

        // Get the User's first certificate
        user1Cert1 = getUserCertFromScepResponse( scepRespInBytes, testCACert, user1Key1);
        assertNotNull("User#1 certificate should have been issued.", user1Cert1);
        
        assertTrue("User#1 cert should contain '"+user1Name+"'.",user1Cert1.getSubjectDN().getName().contains(user1Name));
    }

    
    @Test
    public void test_04_PasswordAuthWNowFailsAsPasswordRandomised() throws Exception {
        // Try to request another cert using password authentication, but this should fail as the User's password has changed.
        // Note that User one is set to allow renewal 2yrs befre expiry, so the failure is the password and not the profile. 
        
        // Generate a temp new key for User1
        KeyPair tempKeyPair = null;
        try {
            tempKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, tempKeyPair, BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, null, null);
        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_UNAUTHORIZED);
    }

    
    @Test
    public void test_05_RenewalAttempt_TooEarly() throws Exception {
        // Test that a SCEP renewal will fail if the User has a fresh certificate and EEP is set for 1 week before expiry.
      
        // Set the EEP to ensure we are too early
        changeScepUserEEP(user1Name, eeProfileWithRenewals_1wk);

        // Generate 2nd test key for User1
        try {
            user1Key2 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        // Create a SCEP renewal message. The request is signed by the first key/cert.
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1Key2, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user1Key1, user1Cert1);

        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        String res = getFailedScepResponse( scepRespInBytes);
        assertEquals("SCEP response should be BadRequest.","2",res); 
    }
 

    @Test
    public void test_06_RenewalAttempt_BadSignature() throws Exception {
        // Test that a SCEP renewal will fail if signed with the wrong key. This
        // is to demonstrate that the P7 signature is verified correctly.
        
        // Generate a different key for User1
        KeyPair badTestKey = null;
        try {
            badTestKey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        // Create a SCEP renewal message. Will sign with the 'bad' key, but provide the first certificate.
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1Key2, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, badTestKey, user1Cert1);

        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        String res = getFailedScepResponse( scepRespInBytes);
        assertEquals("SCEP response should be BadMessageCheck.","1",res); 
    }
    

  
    @Test
    public void test_07_RenewalWithClientAuth() throws Exception {
        // Test that a SCEP renewal will be permitted using certificate authentication
        
        // We need to change EEP to allow for early renewal
        changeScepUserEEP(user1Name, eeProfileWithRenewals_2yr);
        
        // Reuse 2nd test key for User1 which was generated already in Test#04.
       
        // Create a SCEP renewal message.  Lets try a different longer SHA setting for fun!
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA512, user1DN, user1Key2, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user1Key1, user1Cert1);

        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        // Get the User's second certificate
        user1Cert2 = getUserCertFromScepResponse( scepRespInBytes, testCACert, user1Key1);
        assertNotNull("User#1 certificate should have been issued.", user1Cert2);
        
        assertTrue("User#1 cert should contain '"+user1Name+"'.",user1Cert2.getSubjectDN().getName().contains(user1Name));
    }

    
    
    @Test
    public void test_08_RenewalAttempt_OldKeyNotPermitted() throws Exception {
        // Test that a SCEP renewal will fail if the User has used the same key as before. Assumes the SCEP configuration
        // is set to deny this.
        
        // Make Cert request with key1, but signed by key 2
        
        // Create a SCEP renewal message. The request is signed by the 2nd key/cert.
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1Key1, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user1Key2, user1Cert2);

        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        String res = getFailedScepResponse( scepRespInBytes);
        assertEquals("SCEP response should be BadRequest.","2",res); 
    }

    
    
    @Test
    public void test_09_RenewalAttempt_OldKeyPermittedButCAMayPreventKeyRenewal() throws Exception {
        // Test that a SCEP renewal will fail if the User has used the same key as before. in this case,
        // SCEP config allows it, but not the CA config
        
        // Change the SCEP configuration
        scepConfiguration.setAllowClientCertificateRenewalWithOldKey(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        // Create a SCEP renewal message. The request is signed by the 2nd key/cert.
        byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1Key1, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user1Key2, user1Cert2);

        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        String res = getFailedScepResponse( scepRespInBytes);
        assertEquals("SCEP response should be BadRequest.","2",res); 
        
        // Now let the CA allow key renewals
        testCAinfo.setDoEnforceKeyRenewal(false);
        caSessionRemote.editCA(admin, testCAinfo);
        
        // Send message again. Try a different encryption for fun!
        scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1Key1, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.aES128_CBC, user1Key2, user1Cert2);
        scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);

        // Get the User's third certificate
        X509Certificate user1Cert3= getUserCertFromScepResponse( scepRespInBytes, testCACert, user1Key2);
        assertNotNull("User#1 certificate should have been issued.", user1Cert3);
        
        assertTrue("User#1 cert should contain '"+user1Name+"'.",user1Cert3.getSubjectDN().getName().contains(user1Name));
    }


  

    @Test
    public void test_10_RenewalAttempt_RevokedCert() throws Exception {
        // Test that a SCEP renewal will fail if signed by revoked cert.
        
        // Revoke the user's second cert that was issued earlier
        endEntityManagementSession.revokeCert(admin, user1Cert2.getSerialNumber(),user1Cert2.getIssuerDN().getName(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);

         // Generate test key for User1
        KeyPair testKey = null;
        try {
            testKey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
         
        // Create a SCEP renewal message and sign with the 2nd key/cert
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, testKey, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user1Key2, user1Cert2);

        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        String res = getFailedScepResponse( scepRespInBytes);
        assertEquals("SCEP response should be BadMessageIntegrity.","1",res); 
    }

    
    @Test
    public void test_11_RenewalAttempt_WrongStatus() throws Exception {
        // Test that a SCEP renewal will fail if the User is not at GENERATED status.
        // The GENERATED state indicate that the User has at least one cert. Any other state
        // should be a concern and we don't wish to allow Renewals unless GENERATED state.
        
        // Generate test key for User1
        KeyPair testKey = null;
        try {
            testKey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        // Note: Status will be changed to NEW.
        changeScepUserStatus(user1Name, EndEntityConstants.STATUS_NEW);
        
        // Create a SCEP renewal message. Use 1st key/cert.
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, testKey, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user1Key1, user1Cert1);

        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        
        // Put status back to GENERATED
        changeScepUserStatus(user1Name, EndEntityConstants.STATUS_GENERATED);

        
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        String res = getFailedScepResponse( scepRespInBytes);
        assertEquals("SCEP response should be BadRequest.","2",res); 
    }


    @Test
    public void test_12_RenewalAttemp_WrongUserCert() throws Exception {
        // Check a renewal cannot be performed using a certificate belonging to another User. 
        // Setup a test User#2 to get a certificate using SCEP. Use password authentication for this.
        
        //Create the User#2
        this.createScepUser(user2Name, user2DN, testCAID);
        KeyPair user2Key = null;
       
        // Generate key for User2
        try {
            user2Key = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        final byte[] scepReqInBytes2 = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user2DN, user2Key, BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, null, null);
        // Send message with POST
        byte[] scepRespInBytes = sendScep(true, scepReqInBytes2, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        X509Certificate user2Cert = null;
        user2Cert = getUserCertFromScepResponse( scepRespInBytes, testCACert, user2Key);

        // Now renewal attempt for User#1, but sign with User#2
        // Generate test key for User1
        KeyPair user1testKey = null;
        try {
            user1testKey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        
        // Create a SCEP renewal message for User#1, but sign with User#2
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1testKey, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user2Key, user2Cert);

        // Send message with POST
       scepRespInBytes = sendScep(true, scepReqInBytes, HttpServletResponse.SC_OK);
        assertNotNull( "SCEP response should not be Null.", scepRespInBytes);
        
        String res = getFailedScepResponse( scepRespInBytes);
        assertEquals("SCEP response should be BadMessageIntegrity.","1",res); 
    }
    
    
    @Test
    public void test_13_RenewalUsingCertIssuedByAnotherCA() throws Exception {
        // Test that a SCEP renewal will succeed even if the signer of SCEP message is from
        // a different CA, but still belongs to the User.
        
        // Need another Test CA
        
        int tempCAID = createTestCA( "TempScepTestCA");
        CAInfo tempCaInfo = caSessionRemote.getCAInfo(admin, "TempScepTestCA");

        // need to add another cert for User1 that is issued by the temp CA
        // create test keys
        KeyPair user1TestKey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);

        // Create a request
        SimpleRequestMessage req = new SimpleRequestMessage(user1TestKey.getPublic(), user1Name, "foo123");
        //req.setIssuerDN(CertTools.getIssuerDN(tempCaInfo.getCertificateChain().get(0)));
        req.setRequestDN( user1DN);
        
        // Will need to set the User's password to match that in the request
        endEntityManagementSession.setPassword(admin, user1Name, "foo123");
        
        // Set the User to use the temp CA.
        EndEntityInformation eeiForUser1 = endEntityAccessSession.findUser(admin, user1Name );
        eeiForUser1.setCAId( tempCAID);
        
        // Issue new cert. As EE is allowed renewals, this will work.
        SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(admin, eeiForUser1, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        assertNotNull("Failed to create cert", resp);
        assertEquals("Cert response was not successful", resp.getStatus(), ResponseStatus.SUCCESS);
        assertTrue("User#1 cert should have been issued by temp CA", ((X509Certificate)resp.getCertificate()).getIssuerDN().getName().contains("CN=TempScepTestCA"));
        

        // Setup a SCEP renewal using this newly issued cert from a different CA.
        
        // Generate test key for User1
        KeyPair user1Key4 = null;
        try {
            user1Key4 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
       
        // Create a SCEP renewal message. Use cert issued by different CA
        final byte[] scepReqInBytes = genScepRequest( CMSSignedGenerator.DIGEST_SHA256, user1DN, user1Key4, 
                BouncyCastleProvider.PROVIDER_NAME,  PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC, user1TestKey, (X509Certificate) resp.getCertificate());

        // Send message with GET
        byte[] scepRespInBytes = sendScep(false, scepReqInBytes, HttpServletResponse.SC_OK);
        // Get the User's forth certificate
        X509Certificate user1Cert4 = getUserCertFromScepResponse( scepRespInBytes, testCACert, user1TestKey);
        assertNotNull("User#1 certificate should have been issued.", user1Cert4);
        
        assertTrue("User#1 cert should contain '"+user1Name+"'.",user1Cert4.getSubjectDN().getName().contains(user1Name));
        assertTrue("User#1 cert issued by wrong CA",user1Cert4.getIssuerDN().getName().contains("CN="+TestScepCAName));
       
    }


    @Override
    protected String getResourceScep() {
        return resourceScep;
    }

    @Override
    protected String getTransactionId() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected X509Certificate getCaCertificate() {
        return testCACert;
    }

    
    private byte[] genScepRequest( String digestoid, String userDN, KeyPair kpCSR, String signatureProvider, 
                                    ASN1ObjectIdentifier wrappingAlg, ASN1ObjectIdentifier encryptionAlg, KeyPair kpSigner, 
                                    X509Certificate certSigner) throws Exception {

        ScepRequestGenerator gen = new ScepRequestGenerator();
        gen.setKeys(kpCSR, signatureProvider);
        gen.setDigestOid(digestoid);
        byte[] msgBytes = null;
        // Create a transactionId
        byte[] randBytes = new byte[16];
        this.rand.nextBytes(randBytes);
        byte[] digest = CertTools.generateMD5Fingerprint(randBytes);
        transId = new String(Base64.encode(digest));
        
        // Sender certificate could be self-generated or provided (for the case of renewals)
        X509Certificate senderCertificate = null;
        KeyPair kpUseToSign = null;
        if ( certSigner == null) {
          senderCertificate = CertTools.genSelfCert("CN=SenderCertificate", 24 * 60 * 60 * 1000, null,
                kpCSR.getPrivate(), kpCSR.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false);
          kpUseToSign = kpCSR;
        } else {
            senderCertificate=certSigner;
            kpUseToSign = kpSigner;
        }
        
        // CA Cert should exist
        assertNotNull( testCACert);
        
         msgBytes = gen.generateCertReq(userDN, "foo123", transId, testCACert, senderCertificate, kpUseToSign.getPrivate(), wrappingAlg, encryptionAlg);
         assertNotNull(msgBytes);
 
         senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertTrue(nonceBytes.length == 16);
        return msgBytes;
    }
    
    
    protected X509Certificate getUserCertFromScepResponse(byte[] retMsg,X509Certificate caCertToUse, KeyPair key)   throws Exception {

        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);
        
        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = iter.next();
        
        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();
        
        // --Fail info
        Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
        // No failInfo on this success message
        assertNull(attr);

        // --Message type
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType));
        assertNotNull(attr);

        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1String str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        String messageType = str.getString();
        assertEquals("3", messageType);

        // --Success status
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        assertEquals(ResponseStatus.SUCCESS.getStringValue(), str.getString());
        // First we extract the encrypted data from the CMS enveloped data
        // contained
        // within the CMS signed data
        final CMSProcessable sp = s.getSignedContent();
        final byte[] content = (byte[]) sp.getContent();
        final CMSEnvelopedData ed = new CMSEnvelopedData(content);
        final RecipientInformationStore recipients = ed.getRecipientInfos();
        @SuppressWarnings("rawtypes")
        Store certstore;

        Collection<RecipientInformation> c = recipients.getRecipients();
        assertEquals(c.size(), 1);
        Iterator<RecipientInformation> riIterator = c.iterator();
        byte[] decBytes = null;
        RecipientInformation recipient = riIterator.next();
        AlgorithmIdentifier wrapAlg = recipient.getKeyEncryptionAlgorithm();
        // Was it the expected key wrapping algo from the server?
        log.debug("Key encryption algorithm from the server is: " + wrapAlg.getAlgorithm().getId());

        JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(key.getPrivate());
        rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
        // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM, 
        // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known 
        // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
        rec.setMustProduceEncodableUnwrappedKey(true);            
        decBytes = recipient.getContent(rec);
        String encAlg = ed.getContentEncryptionAlgorithm().getAlgorithm().getId();
        // Was it the expected encryption algo from the server?
        log.debug("Encryption algorithm from the server is: " + encAlg);

        // This is yet another CMS signed data
        CMSSignedData sd = new CMSSignedData(decBytes);
        // Get certificates from the signed data
        certstore = sd.getCertificates();

        // We got a reply with a requested certificate
        @SuppressWarnings("unchecked")
        final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
        // EJBCA returns the issued cert and the CA cert (cisco vpn
        // client requires that the ca cert is included)
        //                if (noca) {
        //                    assertEquals(certs.size(), 1);
        //                } else {
        //                    assertEquals(certs.size(), 2);
        //                }

        final Iterator<X509CertificateHolder> it = certs.iterator();
        // Issued certificate must be first
        boolean verified = false;
        boolean gotcacert = false;
        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        while (it.hasNext()) {
            X509Certificate retcert = jcaX509CertificateConverter.getCertificate(it.next());
            log.info("Got cert with DN: " + retcert.getSubjectDN().getName());

            return retcert;

            //                    // check the returned certificate
            //                    String subjectdn = CertTools.stringToBCDNString(retcert.getSubjectDN().getName());
            //                    if (CertTools.stringToBCDNString(userDN).equals(subjectdn)) {
            //                        // issued certificate
            //                        assertEquals(CertTools.stringToBCDNString(userDN), subjectdn);
            //                        assertEquals(CertTools.getSubjectDN(caCertToUse), CertTools.getIssuerDN(retcert));
            //                        retcert.verify(caCertToUse.getPublicKey());
            //                        assertTrue(checkKeys(key.getPrivate(), retcert.getPublicKey()));
            //
            //                        verified = true;
            //                    } else {
            //                        // ca certificate
            //                        assertEquals(CertTools.getSubjectDN(caCertToUse), CertTools.getSubjectDN(retcert));
            //                        gotcacert = true;
            //                    }
        }
        //                assertTrue(verified);
        //                if (noca) {
        //                    assertFalse(gotcacert);
        //                } else {
        //                    assertTrue(gotcacert);
        //                }

        return null;
    }

    
    protected String getFailedScepResponse(byte[] retMsg)  throws Exception {

        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);

        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = iter.next();

        // Get authenticated attributes
        AttributeTable tab = signerInfo.getSignedAttributes();

        // --Get PKI status
        Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        ASN1Set values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        
        ASN1String str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        // Expecting a FAILURE
        assertEquals(ResponseStatus.FAILURE.getStringValue(), str.getString());

        // --Fail info
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
        // Expect a fail info
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = ASN1PrintableString.getInstance((values.getObjectAt(0)));
        
        return str.getString();

    }

    

}
