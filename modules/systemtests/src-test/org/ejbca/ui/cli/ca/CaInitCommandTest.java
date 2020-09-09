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

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * System test class for CaInitCommandTest, tests rudimentary behavior of the "ca init" CLI command
 * 
 */
public class CaInitCommandTest {

    private static final String CA_NAME = "CaInitCommandTest";
    private static final String CA_DN = "CN=CLI Test CA "+CA_NAME+",O=EJBCA,C=SE";
    private static final String CA_NAME_2 = "CaInitCommandTest2";
    private static final String CA_DN_2 = "CN=CLI Test CA "+CA_NAME_2+",O=EJBCA,C=SE";
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
    private CaImportCACertCommand caImportCaCertCommand;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaInitCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caInitCommand = new CaInitCommand();
        caImportCaCertCommand = new CaImportCACertCommand();
        CaTestCase.removeTestCA(CA_NAME);
        CaTestCase.removeTestCA(CA_NAME_2);
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(CA_NAME);
        CaTestCase.removeTestCA(CA_NAME_2);
        // Make sure CA certificates are wiped from the DB
        internalCertStoreSession.removeCertificatesBySubject(CA_DN);
        internalCertStoreSession.removeCertificatesBySubject(CA_DN_2);
    }

    /** Test with some missing token arguments to see that we check this input and give errors. */
    @Test
    public void testExecuteInvalidTokenArgs() throws Exception {
        // Arguments missing both --tokenType and --tokenName
        final String[] NO_TOKEN_TYPE = {  "--caname", CA_NAME, "--dn", CA_DN, "--keyspec", "secp256r1", "--keytype", "ECDSA", "-v", "365", "--policy", "null", "-s", "SHA256withECDSA" };
        CommandResult result = caInitCommand.execute(NO_TOKEN_TYPE);
        assertEquals("Result should be failure for NO_TOKEN_TYPE", CommandResult.CLI_FAILURE.getReturnCode(), result.getReturnCode());

        // Arguments with PKCS#11 --tokenType, but missing --tokenprop
        final String[] NO_TOKEN_PROP_WITH_TyPE = {  "--caname", CA_NAME, "--dn", CA_DN, "--tokenType", "org.cesecore.keys.token.PKCS11CryptoToken", "--keyspec", "secp256r1", "--keytype", "ECDSA", "-v", "365", "--policy", "null", "-s", "SHA256withECDSA" };
        result = caInitCommand.execute(NO_TOKEN_PROP_WITH_TyPE);
        assertEquals("Result should be failure for NO_TOKEN_PROP_WITH_TyPE", CommandResult.CLI_FAILURE.getReturnCode(), result.getReturnCode());

        // Arguments with --tokenName, but missing --tokenprop
        final String[] NO_TOKEN_PROP_WITH_NAME = {  "--caname", CA_NAME, "--dn", CA_DN, "--tokenName", "My Token", "--keyspec", "secp256r1", "--keytype", "ECDSA", "-v", "365", "--policy", "null", "-s", "SHA256withECDSA" };
        result = caInitCommand.execute(NO_TOKEN_PROP_WITH_NAME);
        assertEquals("Result should be failure for NO_TOKEN_PROP_WITH_NAME", CommandResult.CLI_FAILURE.getReturnCode(), result.getReturnCode());

        // Arguments with Soft --tokenType, but including --tokenprop
        final String[] SOFT_WITH_TOKEN_PROP = {  "--caname", CA_NAME, "--dn", CA_DN, "--tokenType", "soft", "--tokenprop", "my.properties", "--keyspec", "secp256r1", "--keytype", "ECDSA", "-v", "365", "--policy", "null", "-s", "SHA256withECDSA" };
        result = caInitCommand.execute(SOFT_WITH_TOKEN_PROP);
        assertEquals("Result should be failure for SOFT_WITH_TOKEN_PROP", CommandResult.CLI_FAILURE.getReturnCode(), result.getReturnCode());

    }

    /** Test trivial happy path for execute, i.e, create an ordinary CA, both creating a new crypto token, and re-using an existing crypto token. */
    @Test
    public void testExecuteHappyPath() throws Exception {
        // 1. Create new crypto token
        // Create a new CA, also creating a new crypto token. The crypto token will get the same name as the CA
        CommandResult result = caInitCommand.execute(HAPPY_PATH_ARGS);
        assertNotNull("Happy path CA was not created.", caSession.getCAInfo(admin, CA_NAME));
        assertEquals("Result should be success", CommandResult.SUCCESS.getReturnCode(), result.getReturnCode());
        
        // 2. Use existing crypto token
        // Test creating CA from an existing crypto token, i.e. not creating a new crypto token, re-use the crypto token created above
        // First create the token.properties file that we need for the command
        File f = File.createTempFile("cainit", "test");
        try {
            try (FileWriter fw = new FileWriter(f)) {
                // Create a configuration file
                fw.write("certSignKey signKey\n");
                fw.write("crlSignKey signKey\n");
                fw.write("encryptKey defaultKey\n");
            }
        } finally {
            f.deleteOnExit();
        }        
        final String[] HAPPY_PATH_WITH_TOKENNAME = {  "--caname", CA_NAME_2, "--dn", CA_DN_2, "--tokenName", CA_NAME, "--tokenprop", f.getAbsolutePath(), "--keyspec", "2048", "--keytype", "RSA", "-v", "30", "--policy", "null", "-s", "SHA256withRSA" };
        result = caInitCommand.execute(HAPPY_PATH_WITH_TOKENNAME);
        assertNotNull("Happy path CA 2 was not created.", caSession.getCAInfo(admin, CA_NAME_2));
        assertEquals("Result should be success", CommandResult.SUCCESS.getReturnCode(), result.getReturnCode());
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
            assertNull("CA was created using created using non ROOTCA or SUBCA certificate profile.", caSession.getCAInfo(admin, CA_NAME));

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
        CAInfo cainfo = null;
        try {
            caInitCommand.execute(ECC_CA_EXPLICIT_ARGS);
            // In versions of EJBCA before 6.4.0 / 6.2.11, this did not work, because Java always deserializes
            // certificates using the Sun provider even if they where created with BC originally. This was fixed
            // by making the certificate object transient and sending an encoded certificate instead.
            cainfo = caSession.getCAInfo(admin, CA_NAME);
            assertNotNull("ECC CA was not created.", cainfo);
            Certificate cert = cainfo.getCertificateChain().iterator().next();
            assertEquals("EC", cert.getPublicKey().getAlgorithm());
        } finally {
            CaTestUtils.removeCa(admin, cainfo);
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
        assertEquals(CommandResult.SUCCESS, caInitCommand.execute(ROOT_CA_ARGS));
        CAInfo rootCaInfo = caSession.getCAInfo(admin, rootCaName);
        int rootCaId = rootCaInfo.getCAId();
        try {
            final String[] SUB_CA_ARGS = { subCaName, "CN=subca", "soft", "foo123", "2048", "RSA", "365", "null", "SHA1WithRSA", "--signedby",
                    Integer.toString(rootCaId) };
            assertEquals(CommandResult.SUCCESS, caInitCommand.execute(SUB_CA_ARGS));
            CAInfo subCaInfo = caSession.getCAInfo(admin, subCaName);
            try {
                assertEquals("SubCA was not signed by Root CA", rootCaId, subCaInfo.getSignedBy());
            } finally {
                CaTestUtils.removeCa(admin, subCaInfo);
            }
        } finally {
            CaTestUtils.removeCa(admin, rootCaInfo);
        }
        

    }
    
    private static final String[] IMPORT_SIGNED_BY_EXTERNAL_ARGS = { CA_NAME, "cert.pem" };
    private static final String[] SIGNED_BY_EXTERNAL_ARGS = { CA_NAME, CA_DN, "soft", "foo123", "2048", "RSA", "365", "null", "SHA256WithRSA",
            "--signedby", "External", "-externalcachain", "chain.pem" };
    
    /** Test happy path for creating a CA signed by an external CA. */
    @Test
    public void testCASignedByExternal() throws Exception {
        // Create a handmade External CA
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        X509Certificate externalCACert = CertTools.genSelfCert("CN=External CA", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        final String fp1 = CertTools.getFingerprintAsString(externalCACert);
        String fp2 = null;
        File temp = File.createTempFile("chain", ".pem");
        File csr = new File(CA_NAME + "_csr.der");
        File certfile = new File(CA_NAME + "_cert.der");
        try {
            ArrayList<Certificate> mylist = new ArrayList<Certificate>();
            mylist.add(externalCACert);
            FileOutputStream fos = new FileOutputStream(temp);
            fos.write(CertTools.getPemFromCertificateChain(mylist));
            fos.close();
            SIGNED_BY_EXTERNAL_ARGS[SIGNED_BY_EXTERNAL_ARGS.length - 1] = temp.getAbsolutePath();
            assertEquals(CommandResult.SUCCESS, caInitCommand.execute(SIGNED_BY_EXTERNAL_ARGS));
            CAInfo cainfo = caSession.getCAInfo(admin, CA_NAME);
            assertNotNull("CA signed by external CA was not created.", cainfo);
            assertEquals("Creating a CA signed by an external CA should initially create it in status 'waiting for certificate response'",
                    CAConstants.CA_WAITING_CERTIFICATE_RESPONSE, cainfo.getStatus());

            // Read the generated CSR, requires knowledge of what filename it creates
            byte[] bytes = FileTools.readFiletoBuffer(CA_NAME + "_csr.der");
            PKCS10RequestMessage msg = new PKCS10RequestMessage(bytes);
            // Create a new certificate with the subjectDN and publicKey from the request
            Date firstDate = new Date();
            Date lastDate = new Date();
            lastDate.setTime(lastDate.getTime() + (365 * (24 * 60 * 60 * 1000)));
            byte[] serno = new byte[8];
            // This is a test, so randomness does not have to be secure (CSPRNG)
            Random random = new Random();
            random.nextBytes(serno);
            final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(msg.getRequestPublicKey().getEncoded());
            X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(
                    CertTools.stringToBcX500Name(externalCACert.getSubjectDN().toString()), new java.math.BigInteger(serno).abs(), firstDate,
                    lastDate, CertTools.stringToBcX500Name(msg.getRequestDN()), pkinfo);
            BasicConstraints bc = new BasicConstraints(true);
            certbuilder.addExtension(Extension.basicConstraints, true, bc);
            X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
            certbuilder.addExtension(Extension.keyUsage, true, ku);
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keys.getPrivate()), 20480);
            final X509CertificateHolder certHolder = certbuilder.build(signer);
            final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
            fp2 = CertTools.getFingerprintAsString(cert);
            // Now we have issued a certificate, import it
            mylist = new ArrayList<Certificate>();
            mylist.add(cert);
            fos = new FileOutputStream(certfile);
            fos.write(CertTools.getPemFromCertificateChain(mylist));
            fos.close();
            IMPORT_SIGNED_BY_EXTERNAL_ARGS[IMPORT_SIGNED_BY_EXTERNAL_ARGS.length - 1] = certfile.getAbsolutePath();
            assertEquals(CommandResult.SUCCESS, caImportCaCertCommand.execute(IMPORT_SIGNED_BY_EXTERNAL_ARGS));
            cainfo = caSession.getCAInfo(admin, CA_NAME);
            assertNotNull("CA signed by external CA does not exist.", cainfo);
            assertEquals("importing a certificate to a CA signed by an external CA should result in status 'active'", CAConstants.CA_ACTIVE,
                    cainfo.getStatus());
        } finally {
            temp.deleteOnExit();
            csr.deleteOnExit();
            certfile.deleteOnExit();
            // Clean up imported certificates from database
            internalCertStoreSession.removeCertificate(fp1);
            internalCertStoreSession.removeCertificate(fp2);
        }
    }
}
