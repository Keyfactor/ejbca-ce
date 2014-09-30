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
import java.util.Enumeration;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.SecConst;
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
 * @version $Id$
 */
public class CertificateRequestSessionTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CertificateRequestSessionTest.class);
    private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateRequestSessionTest"));
    private final Random random = new Random();

    private CertificateRequestSessionRemote certificateRequestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateRequestSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    @Before
    public void setup() throws Exception {
        super.setUp();
    }

    /**
     * Verify that a soft token can be generated in a single transaction.
     */
    @Test
    public void testSoftTokenRequestRollback() throws Exception {
        // First try a successful request and validate the returned KeyStore
        String username = "softTokenRequestTest-" + random.nextInt();
        String password = "foo123";
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_JKS, 0, null);
        userdata.setPassword(password);
        byte[] encodedKeyStore = certificateRequestSession.processSoftTokenReq(admin, userdata, null, "1024",
                AlgorithmConstants.KEYALGORITHM_RSA, true);
        try {
            // Convert encoded KeyStore to the proper return type
            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
            keyStore.load(new ByteArrayInputStream(encodedKeyStore), userdata.getPassword().toCharArray());
            assertNotNull(keyStore);
            Enumeration<String> aliases = keyStore.aliases();
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (CertTools.isSelfSigned(cert)) {
                // Ignore the CA cert and get another one
                alias = aliases.nextElement();
                cert = keyStore.getCertificate(alias);
            }
            assertEquals("CertTools.getSubjectDN: " + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
                    CertTools.getSubjectDN(cert), userdata.getDN());
            keyStore.getKey(alias, password.toCharArray());
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
        userdata.setPassword(password);
        assertFalse(username2 + " already exists.", endEntityManagementSession.existsUser(username2));
        try {
            certificateRequestSession.processSoftTokenReq(admin, userdata, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA, true);
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
        final String password = "foo123";
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        userdata.setPassword(password);
        String pkcs10 = new String(Base64.encode(NonEjbTestTools.generatePKCS10Req("CN=Ignored", password)));
        byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, null,
                CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
        try {
            Certificate cert = CertTools.getCertfromByteArray(encodedCertificate);
            assertEquals("CertTools.getSubjectDN: " + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
                    CertTools.getSubjectDN(cert), userdata.getDN());
            // Try again with a user that does not exist and use values that we will
            // break certificate generation
            // If the transaction really is rolled back successfully there will be
            // no trace of the user in the database
            // We can do this by relying on the Unique Public Key constraint
           
            userdata.setUsername(username2); // Still the same Subject DN
            userdata.setPassword(password);
            try {
                certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, null,
                        CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
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
        String password = "foo123";
    	final String suppliedDn = "CN=" + username + ",Name=removed,SN=removed,GIVENNAME= ,GIVENNAME=,SURNAME= ,SURNAME=,O=removed,C=SE";
    	final String expectedDn = "CN=" + username + ",Name=removed,SN=removed,O=removed,C=SE";
        EndEntityInformation userdata = new EndEntityInformation(username, suppliedDn, getTestCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        userdata.setPassword(password);
        String pkcs10 = new String(Base64.encode(NonEjbTestTools.generatePKCS10Req("CN=Ignored", password)));
        byte[] encodedCertificate = certificateRequestSession.processCertReq(admin, userdata, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, null,
                CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
        try {
            Certificate cert = CertTools.getCertfromByteArray(encodedCertificate);
            assertEquals("CertTools.getSubjectDN: " + CertTools.getSubjectDN(cert) + " expectedDn: " + expectedDn, expectedDn,
                    CertTools.getSubjectDN(cert));
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
        }
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
}
