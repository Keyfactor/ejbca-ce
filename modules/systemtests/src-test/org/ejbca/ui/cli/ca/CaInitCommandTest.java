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

package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.Certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaInitCommandTest
 * 
 * @version $Id$
 */
public class CaInitCommandTest {

    private static final String CA_NAME = "CaInitCommandTest";
    private static final String CA_DN = "CN=CLI Test CA "+CA_NAME+"ca2,O=EJBCA,C=SE";
    private static final String CERTIFICATE_PROFILE_NAME = "certificateProfile"+CA_NAME;
    private static final String[] HAPPY_PATH_ARGS = {  CA_NAME, CA_DN, "soft", "foo123", "2048", "RSA", "365", "null", "SHA256WithRSA" };
    private static final String[] X509_TYPE_ARGS = { CA_NAME, CA_DN, "soft", "foo123", "2048", "RSA", "365", "null", "SHA1WithRSA", "-type",
            "x509" };
    private static final String[] X509_ARGS_NON_DEFULTPWD = { CA_NAME, CA_DN, "soft", "bar123", "2048", "RSA", "365", "1.1.1.1",
            "SHA1WithRSA" };
    private static final String[] ROOT_CA_ARGS = {  CA_NAME, CA_DN, "soft", "foo123", "2048", "RSA", "365", "null", "SHA256WithRSA",
            "-certprofile", "ROOTCA" };
    private static final String[] CUSTOM_PROFILE_ARGS = {  CA_NAME, CA_DN, "soft", "foo123", "2048", "RSA", "365", "null", "SHA256WithRSA",
            "-certprofile", CERTIFICATE_PROFILE_NAME };
    private static final String[] ECC_CA_ARGS = {  CA_NAME, CA_DN, "soft", "foo123", "secp256r1", "ECDSA", "365", "null", "SHA256withECDSA" };
    private static final String[] ECC_CA_EXPLICIT_ARGS = {  CA_NAME, CA_DN, "soft", "foo123", "secp256r1", "ECDSA", "365", "null",
            "SHA256withECDSA", "-explicitecc" };


    private CaInitCommand caInitCommand;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaInitCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caInitCommand = new CaInitCommand();
        CaTestCase.removeTestCA(CA_NAME);
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(CA_NAME);
        // Make sure CA certificates are wiped from the DB
        internalCertStoreSession.removeCertificatesBySubject(CA_DN);
    }

    /** Test trivial happy path for execute, i.e, create an ordinary CA. */
    @Test
    public void testExecuteHappyPath() throws Exception {
        caInitCommand.execute(HAPPY_PATH_ARGS);
        assertNotNull("Happy path CA was not created.", caSession.getCAInfo(admin, CA_NAME));
    }

    @Test
    public void testWithX509Type() throws Exception {
        caInitCommand.execute(X509_TYPE_ARGS);
        assertNotNull("X509 typed CA was not created.", caSession.getCAInfo(admin, CA_NAME));
    }

    @Test
    public void testWithX509TypeNonDefaultPwd() throws Exception {
        caInitCommand.execute(X509_ARGS_NON_DEFULTPWD);
        assertNotNull("X509 typed CA with non default CA token pwd was not created.", caSession.getCAInfo(admin, CA_NAME));
    }

    @Test
    public void testExecuteWithRootCACertificateProfile() throws Exception {
        caInitCommand.execute(ROOT_CA_ARGS);
        assertNotNull("CA was not created using ROOTCA certificate profile.", caSession.getCAInfo(admin, CA_NAME));
    }

    @Test
    public void testExecuteWithCustomCertificateProfile() throws CertificateProfileExistsException,
            AuthorizationDeniedException, CADoesntExistsException {
        if (certificateProfileSessionRemote.getCertificateProfile(CERTIFICATE_PROFILE_NAME) == null) {
            CertificateProfile certificateProfile = new CertificateProfile();
            certificateProfileSessionRemote.addCertificateProfile(admin, CERTIFICATE_PROFILE_NAME, certificateProfile);
        }
        try {
            CertificateProfile apa = certificateProfileSessionRemote.getCertificateProfile(CERTIFICATE_PROFILE_NAME);
            assertNotNull(apa);
            caInitCommand.execute(CUSTOM_PROFILE_ARGS);

            // Following line should throw an exception.
            boolean caught = false;
            try {
                caSession.getCAInfo(admin, CA_NAME);
            } catch (CADoesntExistsException e) {
                caught = true;
            }
            Assert.assertTrue("CA was created using created using non ROOTCA or SUBCA certificate profile.", caught);

        } finally {
            certificateProfileSessionRemote.removeCertificateProfile(admin, CERTIFICATE_PROFILE_NAME);
        }
    }

    /** Test happy path for creating an ECDSA CA. */
    @Test
    public void testEccCA() throws Exception {
        caInitCommand.execute(ECC_CA_ARGS);
        CAInfo cainfo = caSession.getCAInfo(admin, CA_NAME);
        assertNotNull("ECC CA was not created.", cainfo);
        Certificate cert = cainfo.getCertificateChain().iterator().next();
        assertEquals("EC", cert.getPublicKey().getAlgorithm());
    }

    /** Test happy path for creating an ECDSA CA with explicit ECC parameters. Requires some special handling. */
    @Test
    public void testEccCAExplicitEccParams() throws Exception {
        try {
            caInitCommand.execute(ECC_CA_EXPLICIT_ARGS);
            // In versions of EJBCA before 6.4.0 / 6.2.11, this did not work, because Java always deserializes
            // certificates using the Sun provider even if they where created with BC originally. This was fixed
            // by making the certificate object transient and sending an encoded certificate instead.
            CAInfo cainfo = caSession.getCAInfo(admin, CA_NAME);
            assertNotNull("ECC CA was not created.", cainfo);
            Certificate cert = cainfo.getCertificateChain().iterator().next();
            assertEquals("EC", cert.getPublicKey().getAlgorithm());
        } finally {
            // Normal remove routines do not work when it is not serializeable, we have to make some qualified guesses
            // and remove it manually
            caSession.removeCA(admin, CA_DN.hashCode());
            Integer id = cryptoTokenManagementSession.getIdFromName(CA_NAME);
            cryptoTokenManagementSession.deleteCryptoToken(admin, id);
        }
    }

   
    /**
     * Create a root CA, then create a sub CA signed by that root.
     */
    @Test
    public void testCreateSubCa() throws AuthorizationDeniedException {
        final String rootCaName = "rootca";
        final String subCaName = "subca";
        final String[] ROOT_CA_ARGS = { rootCaName, "CN=rootca", "soft", "foo123", "2048", "RSA", "365", "null", "SHA1WithRSA" };
      
        try {
            assertEquals(CommandResult.SUCCESS, caInitCommand.execute(ROOT_CA_ARGS));
            CAInfo rootCaInfo = caSession.getCAInfo(admin, rootCaName);
            int rootCaId = rootCaInfo.getCAId();
            try {
                final String[] SUB_CA_ARGS = { subCaName, "CN=subca", "soft", "foo123", "2048", "RSA", "365", "null", "SHA1WithRSA", "--signedby",
                        Integer.toString(rootCaId) };
                assertEquals(CommandResult.SUCCESS, caInitCommand.execute(SUB_CA_ARGS));
                CAInfo subCaInfo = caSession.getCAInfo(admin, subCaName);
                int subCaId = subCaInfo.getCAId();
                try {
                    assertEquals("SubCA was not signed by Root CA", rootCaId, subCaInfo.getSignedBy());
                } finally {
                    caSession.removeCA(admin, subCaId);
                    cryptoTokenManagementSession.deleteCryptoToken(admin, subCaInfo.getCAToken().getCryptoTokenId());
                }
            } finally {
                caSession.removeCA(admin, rootCaId);
                cryptoTokenManagementSession.deleteCryptoToken(admin, rootCaInfo.getCAToken().getCryptoTokenId());
            }
        } catch (CADoesntExistsException e) {
            throw new RuntimeException("Root CA wasn't created, can't continue.", e);
        }

    }
}
