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

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Random;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.util.NonEjbTestTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test the combined function for editing and requesting a keystore/certificate
 * in a single transaction.
 * 
 * Note that the rollback tests requires a transactional database, if using
 * MySQL this means InnoDB and not MyISAM.
 * 
 */
public class CertificateRequestSessionTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CertificateRequestSessionTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateRequestSessionTest"));
    private final Random random = new Random();

    private static final CertificateRequestSessionRemote certificateRequestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateRequestSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    
    private static final String EE_PROFILE_NAME = "TEST_AUTOGEN_USERNAME";
    private static final String PASSWORD = "foo123";
    private static final String CN_IGNORED = "CN=Ignored";
    private static final String NAME_SN_O = ",Name=removed,SN=removed,O=removed,C=SE";
    private static final String CERT_TOOLS_SUBJDN = "CertTools.getSubjectDN: ";

    
    @Before
    public void setup() throws Exception {
        super.setUp();
    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /**
     * Verify that a soft token can be generated in a single transaction.
     */
    @Test
    public void testSoftTokenRequestRollback() throws Exception {
        // First try a successful request and validate the returned KeyStore
        String username = "softTokenRequestTest-" + random.nextInt();
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_JKS, null);
        userdata.setPassword(PASSWORD);
        byte[] encodedKeyStore = certificateRequestSession.processSoftTokenReq(admin, userdata, "1024",
                AlgorithmConstants.KEYALGORITHM_RSA, true);
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encodedKeyStore)) {
            // Convert encoded KeyStore to the proper return type
            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
            keyStore.load(byteArrayInputStream, userdata.getPassword().toCharArray());
            assertNotNull(keyStore);
            Enumeration<String> aliases = keyStore.aliases();
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (CertTools.isSelfSigned(cert)) {
                // Ignore the CA cert and get another one
                alias = aliases.nextElement();
                cert = keyStore.getCertificate(alias);
            }
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
                    CertTools.getSubjectDN(cert), userdata.getDN());
            keyStore.getKey(alias, PASSWORD.toCharArray());
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
        }
        // Try again with a user that does not exist and use values that we will
        // break certificate generation
        // If the transaction really is rolled back successfully there will be
        // no trace of the user in the database
        // We can do this by relying on the Unique Subject DN constraint
        String username2 = "softTokenRequestTest-" + random.nextInt();
        userdata.setUsername(username2); // Still the same Subject DN
        userdata.setPassword(PASSWORD);
        assertFalse(username2 + " already exists.", endEntityManagementSession.existsUser(username2));
        try {
            certificateRequestSession.processSoftTokenReq(admin, userdata, "1024", AlgorithmConstants.KEYALGORITHM_RSA, true);
            fail("Certificate creation did not fail as expected.");
        } catch (Exception e) {
            log.debug("Got an exception as expected: " + e.getMessage());
        } 
        assertFalse("Failed keystore generation request never rolled back created user '" + username2 + "'.", endEntityManagementSession.existsUser(username2));
    }

    /**
     * Verify that a soft token can be generated in a single transaction.
     */
    @Test
    public void testCertificateRequestRollback() throws Exception {
        // First try a successful request and validate the returned KeyStore
        final String username = "certificateRequestTest-user1";
        final  String username2 = "certificateRequestTest-user2";
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, null);
        userdata.setPassword(PASSWORD);
        String pkcs10 = new String(Base64.encode(NonEjbTestTools.generatePKCS10Req(CN_IGNORED, PASSWORD)));
        byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
        try {
            Certificate cert = CertTools.getCertfromByteArray(encodedCertificate, Certificate.class);
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
                    CertTools.getSubjectDN(cert), userdata.getDN());
            // Try again with a user that does not exist and use values that we will
            // break certificate generation
            // If the transaction really is rolled back successfully there will be
            // no trace of the user in the database
            // We can do this by relying on the Unique Public Key constraint
           
            userdata.setUsername(username2); // Still the same Subject DN
            userdata.setPassword(PASSWORD);
            try {
                certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
                fail("Certificate creation did not fail as expected.");
            } catch (Exception e) {
                log.debug("Got an exception as expected: " + e.getMessage());
            }
            assertFalse("Failed certificate generation request never rolled back user created '" + username2 + "'.",
                    endEntityManagementSession.existsUser(username2));
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
            //If the above test failed.
            if(endEntityManagementSession.existsUser(username2)) {
                endEntityManagementSession.deleteUser(admin, username2);
            }
        }
    }

    /**
     * Test what happens if we supply empty DN fields. Created in response to ECA-1767.
     */
    @Test
    public void testEmptyFields() throws Exception {
        // First try a successful request and validate the returned KeyStore
        String username = "certificateRequestTest-" + random.nextInt();
    	final String suppliedDn = "CN=" + username + ",Name=removed,SN=removed,GIVENNAME= ,GIVENNAME=,SURNAME= ,SURNAME=,O=removed,C=SE";
    	final String expectedDn = "CN=" + username + NAME_SN_O;
        EndEntityInformation userdata = new EndEntityInformation(username, suppliedDn, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, null);
        userdata.setPassword(PASSWORD);
        String pkcs10 = new String(Base64.encode(NonEjbTestTools.generatePKCS10Req(CN_IGNORED, PASSWORD)));
        byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
        try {
            Certificate cert = CertTools.getCertfromByteArray(encodedCertificate, Certificate.class);
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " expectedDn: " + expectedDn, expectedDn,
                    CertTools.getSubjectDN(cert));
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
        }
    }

    /**
     * Test if username is set to auto generated in EEP certificate should be
     * issued properly.
     * 
     * @throws Exception
     */
    @Test
    public void testAutoGenerateUserName() throws Exception {
        
        EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.DNSERIALNUMBER);
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.NAME);
        profile.setAutoGeneratedUsername(true);
        // Profile will be removed in finally clause
        endEntityProfileSession.addEndEntityProfile(admin, EE_PROFILE_NAME, profile);
        int profileId = endEntityProfileSession.getEndEntityProfileId(EE_PROFILE_NAME);
        
        final String uniqueId = UUID.randomUUID().toString();
        
        final String suppliedDn = "CN=Test" + uniqueId + NAME_SN_O;
        final String expectedDn = "CN=Test" + uniqueId + NAME_SN_O;

        EndEntityInformation userdata = new EndEntityInformation(null, suppliedDn, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), profileId,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, null);

        userdata.setPassword(PASSWORD);

        String pkcs10 = new String(Base64.encode(NonEjbTestTools.generatePKCS10Req(CN_IGNORED, PASSWORD)));
        byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, CertificateConstants.CERT_RES_TYPE_CERTIFICATE);

        try {
            final Certificate cert = CertTools.getCertfromByteArray(encodedCertificate, Certificate.class);
            assertEquals(CERT_TOOLS_SUBJDN + CertTools.getSubjectDN(cert) + " expectedDn: " + expectedDn, expectedDn,
                    CertTools.getSubjectDN(cert));
        } finally {
            endEntityProfileSession.removeEndEntityProfile(admin, EE_PROFILE_NAME);
        }
    }

}
