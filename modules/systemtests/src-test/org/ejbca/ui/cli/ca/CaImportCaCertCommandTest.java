/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
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
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CaImportCaCertCommandTest {

    private static final String CA_NAME = "CaImportCaCertCommandTest";
    private static final String CA_DN = "CN=CLI Test CA " + CA_NAME + "ca2,O=EJBCA,C=SE";

    private static final String[] SIGNED_BY_EXTERNAL_ARGS = { CA_NAME, CA_DN, "soft", "foo123", "2048", "RSA", "365", "null", "SHA256WithRSA",
            "--signedby", "External", "-externalcachain", "chain.pem" };
    private static final String[] IMPORT_SIGNED_BY_EXTERNAL_ARGS = { CA_NAME, "cert.pem" };

    private CaInitCommand caInitCommand;
    private CaImportCACertCommand caImportCaCertCommand;

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaImportCaCertCommandTest"));

    private X509Certificate cert;
    private X509Certificate externalCACert;
    private File temp;
    private File csr = new File(CA_NAME + "_csr.der");

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setUp() throws Exception {
        temp = File.createTempFile("chain", ".pem");

        caInitCommand = new CaInitCommand();

        caImportCaCertCommand = new CaImportCACertCommand();
        CaTestCase.removeTestCA(CA_NAME);

        // Create a handmade External CA
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        X509Certificate externalCACert = CertTools.genSelfCert("CN=External CA", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);

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
        Random random = new Random();
        random.setSeed(firstDate.getTime());
        random.nextBytes(serno);
        final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(msg.getRequestPublicKey().getEncoded());
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCACert.getSubjectDN().toString()),
                new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(msg.getRequestDN()), pkinfo);
        BasicConstraints bc = new BasicConstraints(true);
        certbuilder.addExtension(Extension.basicConstraints, true, bc);
        X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        certbuilder.addExtension(Extension.keyUsage, true, ku);
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(
                BouncyCastleProvider.PROVIDER_NAME).build(keys.getPrivate()), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);

    }

    @After
    public void tearDown() throws Exception {
        temp.deleteOnExit();
        csr.deleteOnExit();
        // Clean up imported certificates from database
        internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(externalCACert));
        internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(cert));
        CaTestCase.removeTestCA(CA_NAME);
        // Make sure CA certificates are wiped from the DB
        internalCertStoreSession.removeCertificatesBySubject(CA_DN);
    }

    /** Test happy path for importing a CA certificate, as PEM */
    @Test
    public void testImportCaCertPem() throws Exception {
        File certfile = new File(CA_NAME + "_cert.pem");
        try {
            // Now we have issued a certificate, import it
            FileOutputStream fos = new FileOutputStream(certfile);
            fos.write(CertTools.getPemFromCertificateChain(Arrays.asList((Certificate) cert)));
            fos.close();
            IMPORT_SIGNED_BY_EXTERNAL_ARGS[IMPORT_SIGNED_BY_EXTERNAL_ARGS.length - 1] = certfile.getAbsolutePath();
            assertEquals(CommandResult.SUCCESS, caImportCaCertCommand.execute(IMPORT_SIGNED_BY_EXTERNAL_ARGS));
            CAInfo cainfo = caSession.getCAInfo(admin, CA_NAME);
            assertNotNull("CA signed by external CA does not exist.", cainfo);
            assertEquals("importing a certificate to a CA signed by an external CA should result in status 'active'", CAConstants.CA_ACTIVE,
                    cainfo.getStatus());
        } finally {
            certfile.deleteOnExit();

        }

    }
    
    /** Test happy path for importing a binary CA certificate*/
    @Test
    public void testImportCaCertBinary() throws Exception {
        File certfile = new File(CA_NAME + "_cert.der");
        try {
            // Now we have issued a certificate, import it
            FileOutputStream fos = new FileOutputStream(certfile);
            fos.write(cert.getEncoded());
            fos.close();
            IMPORT_SIGNED_BY_EXTERNAL_ARGS[IMPORT_SIGNED_BY_EXTERNAL_ARGS.length - 1] = certfile.getAbsolutePath();
            assertEquals(CommandResult.SUCCESS, caImportCaCertCommand.execute(IMPORT_SIGNED_BY_EXTERNAL_ARGS));
            CAInfo cainfo = caSession.getCAInfo(admin, CA_NAME);
            assertNotNull("CA signed by external CA does not exist.", cainfo);
            assertEquals("importing a certificate to a CA signed by an external CA should result in status 'active'", CAConstants.CA_ACTIVE,
                    cainfo.getStatus());
        } finally {
            certfile.deleteOnExit();

        }

    }

}
