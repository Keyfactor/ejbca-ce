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

package org.ejbca.core.protocol.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.unidfnr.UnidfnrProxySessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.protocol.ocsp.extension.unid.FnrFromUnidExtension;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * 
 * Tests http pages of ocsp lookup server. This test requires the following setup:  
 * 
 *  1- The unidfnr extension must be deployed (UnidDS datasource configured in application server is required).
 *  2- The lookup service (ocsp lookup) must be active. 
 *  3- There must be a database for the unid-fnr mapping with the mapping 123456789, 654321 (it can be created using the create-table-unid-mysql.sql 
 *     script which can be found under modules/unidfnr/resources/scripts/). 
 *  4- You must have a CA that has issued certificates with serialNumber in the DN matching the unid
 *     123456789 (Default ManagementCA can be used). 
 *  5- You also need a keystore issued by the CA for TLS communication located under LOOKUP_KSTRUST_PATH, 
 *     and its keystore cert (in pem format) must be configured in the ocsp lookup extension.
 *  6- You also need a keystore as above but not configured as trusted in the lookup extension located under LOOKUP_KSNOTRUST_PATH. 
 *  7- The CA-certificate issuing the two keystores should be configured in ejbca.properties (default ManagementCA could be used).
 * 
 * Simply create two new users with batch generation and PKCS12 keystores in ejbca and issue their keystores. The SSL certificate used for JBoss must
 * be issued by the same CA that creates lookup-kstrust.p12.
 * 
 * The database table for the UnidFnrMapping should look like (MySQL): 
    CREATE TABLE UnidFnrMapping (
    unid VARCHAR(250) NOT NULL DEFAULT '',
    fnr  VARCHAR(250) NOT NULL DEFAULT '',
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    PRIMARY KEY (unid);
 *
 *
 * 
 * @version $Id$
 *
 */
public class ProtocolLookupServerHttpTest extends CaTestCase {
    private static Logger log = Logger.getLogger(ProtocolLookupServerHttpTest.class);

    // Set the proper trust/notrust keystore parameters here
    private static final String LOOKUP_KSTRUST_PATH = "";
    private static final String LOOKUP_KSNOTRUST_PATH = "";
    private static final String KEYSTORE_PASS_PHRASE = "foo123";
    private static final String TRUSTSTORE_PASS_PHRASE = "foo123";
    private static final String USER_PASS_PHRASE = "foo123";
    private static final String TEST_USER_NAME = "unidtest";
    private static final String TEST_USER_EMAIL = TEST_USER_NAME+"@anatom.se";
    private static final String TRUSTED_CA_NAME = "ManagementCA"; // Default ManagementCA is used for this test (to keep things simple).
    private static final String SAMPLE_UNID = "123456789";
    private static final String SAMPLE_FNR = "654321";
    private static final String TEST_USER_SUBJECTDN_GOOD_SERIAL = "C=SE,O=AnaTom,surname=Jansson,serialNumber="+SAMPLE_UNID+",CN=UNIDTest";
    private static final String TEST_USER_SUBJECTDN_BAD_SERIAL = "C=SE,O=AnaTom,surname=Jansson,serialNumber=123456,CN=UNIDTest";
    private static final String TEST_USER_SUBJECTDN_NO_SERIAL = "C=SE,O=AnaTom,surname=Jansson,CN=UNIDTest";

    
    private String httpReqPath;
    private String resourceOcsp;

    private int caid = getTestCAId(TRUSTED_CA_NAME);
    private static AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ProtocolLookupServerHttpTest"));
    private static X509Certificate cacert = null;
    private static X509Certificate ocspTestCert = null;
    private static KeyPair keys = null;

    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private RevocationSessionRemote revocationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RevocationSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private static UnidfnrProxySessionRemote unidfnrProxySessionBean = EjbRemoteHelper.INSTANCE.getRemoteSession(UnidfnrProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
        unidfnrProxySessionBean.removeUnidFnrDataIfPresent(SAMPLE_UNID);
        unidfnrProxySessionBean.stroreUnidFnrData(SAMPLE_UNID, SAMPLE_FNR);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        httpReqPath = "https://127.0.0.1:8443/ejbca";
        resourceOcsp = "publicweb/status/ocsp";
        cacert = (X509Certificate) getTestCACertUsingItsName(TRUSTED_CA_NAME);
        keys = KeyTools.genKeys("512", "RSA");
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }
        
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /**
     * Tests ocsp message with good status and a valid unid
     * 
     * @throws Exception error
     */
    @Test
    public void test01OcspGoodWithFnr() throws Exception {
        // Make user that we know...
        boolean userExists = false;
        try {
            endEntityManagementSession.addUser(admin, TEST_USER_NAME, USER_PASS_PHRASE, TEST_USER_SUBJECTDN_GOOD_SERIAL, null,
                    TEST_USER_EMAIL, false, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                    SecConst.TOKEN_SOFT_PEM, caid);
            log.debug("created user: unidtest, foo123, C=SE, O=AnaTom,surname=Jansson,serialNumber="+SAMPLE_UNID+", CN=UNIDTest");
        } catch (EndEntityExistsException e) {
            userExists = true;
        }
        if (userExists) {
            log.debug("User unidtest already exists.");
            EndEntityInformation userData = new EndEntityInformation(TEST_USER_NAME, TEST_USER_SUBJECTDN_GOOD_SERIAL,
                    caid, null, TEST_USER_EMAIL, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, null);
            userData.setPassword(USER_PASS_PHRASE);
            endEntityManagementSession.changeUser(admin, userData, false);
            log.debug("Reset status to NEW");
        }
        // Generate certificate for the new user

        // user that we know exists...
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, TEST_USER_NAME, USER_PASS_PHRASE, new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create certificate", ocspTestCert);

        // And an OCSP request
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(SAMPLE_UNID.getBytes()));
        ocspReqBuilder.setRequestExtensions(new Extensions(extensions));
        
        OCSPReq ocspReq = ocspReqBuilder.build();

        // Send the request and receive a BasicResponse
        BasicOCSPResp basicOCSPResp = sendOCSPPost(ocspReq.getEncoded(), true);
        
        assertEquals(SAMPLE_FNR, getFnrGood(basicOCSPResp));
        SingleResp[] singleResps = basicOCSPResp.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /**
     * Tests ocsp message with bad status and a valid unid
     * 
     * @throws Exception error
     */
    @Test
    public void test02OcspBadWithFnr() throws Exception {
        // Change user to a Unid that is OK
        EndEntityInformation userData = new EndEntityInformation(TEST_USER_NAME, TEST_USER_SUBJECTDN_GOOD_SERIAL,
                caid, null, TEST_USER_EMAIL, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, null);
        userData.setPassword(USER_PASS_PHRASE);
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, userData, false);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, TEST_USER_NAME, USER_PASS_PHRASE, new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create certificate", ocspTestCert);
        
        // Revoke the certificate immediately!
        revocationSession.revokeCertificate(admin, ocspTestCert, null, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);

        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(SAMPLE_UNID.getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        // When a certificate is revoked the FNR must not be returned
        getFnrNotGood(brep);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        int reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
    }

    /**
     * Tests ocsp message with good status and invalid unid
     * 
     * @throws Exception error
     */
    @Test
    public void test03OcspGoodWithNoFnr() throws Exception {
        // Change uses to a Unid that we don't have mapping for
        EndEntityInformation userData = new EndEntityInformation(TEST_USER_NAME, TEST_USER_SUBJECTDN_BAD_SERIAL,
                caid, null, TEST_USER_EMAIL, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, null);
        userData.setPassword(USER_PASS_PHRASE);
        endEntityManagementSession.changeUser(admin, userData, false);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, TEST_USER_NAME, USER_PASS_PHRASE, new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create certificate", ocspTestCert);

        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString("12345678".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        getFnrNotGood(brep);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /**
     * Tests ocsp message with good status but no serialNumber in the DN
     * 
     * @throws Exception error
     */
    @Test
    public void test04OcspGoodNoSerialNo() throws Exception {
        // Change uses to not have any serialNumber
        EndEntityInformation userData = new EndEntityInformation(TEST_USER_NAME, TEST_USER_SUBJECTDN_NO_SERIAL,
                caid, null, TEST_USER_EMAIL, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, null);
        userData.setPassword(USER_PASS_PHRASE);
        endEntityManagementSession.changeUser(admin, userData, false);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, TEST_USER_NAME, USER_PASS_PHRASE, new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create certificate", ocspTestCert);

        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(SAMPLE_UNID.getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        getFnrNotGood(brep);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /**
     * Test a lookup message from an untrusted requester, should not work
     * @throws Exception
     */
    @Test
    public void test05HttpsNotAuthorized() throws Exception {
        // Change uses to a Unid that is OK
        EndEntityInformation userData = new EndEntityInformation(TEST_USER_NAME, TEST_USER_SUBJECTDN_GOOD_SERIAL,
                caid, null, TEST_USER_EMAIL, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, null);
        userData.setPassword(USER_PASS_PHRASE);
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, userData, false);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, TEST_USER_NAME, USER_PASS_PHRASE, new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create certificate", ocspTestCert);

        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(SAMPLE_UNID.getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), false);
        getFnrNotGood(brep);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /**
     * Test a lookup request with regular http, should not work
     * 
     * @throws Exception
     */
    @Test
    public void test06HttpNotAuthorized() throws Exception {
        // Change to use plain http, we should be able to get a OCSP response, but the FNR mapping
        // will not be returned because it requires https with client authentication
        httpReqPath = "http://127.0.0.1:8080/ejbca";
        // Change uses to a Unid that is OK
        EndEntityInformation userData = new EndEntityInformation(TEST_USER_NAME, "C=SE,O=AnaTom,surname=Jansson,serialNumber="+SAMPLE_UNID+",CN=UNIDTest",
                caid, null, TEST_USER_EMAIL, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, null);
        userData.setPassword(USER_PASS_PHRASE);
        endEntityManagementSession.changeUser(admin, userData, false);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, TEST_USER_NAME, USER_PASS_PHRASE, new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create certificate", ocspTestCert);

        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(SAMPLE_UNID.getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        getFnrNotGood(brep);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    //
    // Private helper methods
    //
    private BasicOCSPResp sendOCSPPost(byte[] ocspPackage, boolean trust) throws IOException, OCSPException, GeneralSecurityException,
            OperatorCreationException {
        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection) getUrlConnection(url, trust);
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream outputStream = con.getOutputStream();
        outputStream.write(ocspPackage);
        outputStream.close();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/ocsp-response", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and OCSP requests are small
        try (InputStream inputStream = con.getInputStream()) {
            int b = inputStream.read();
            while (b != -1) {
                baos.write(b);
                b = inputStream.read();
            }
            baos.flush();
        }
        byte[] respBytes = baos.toByteArray();
        OCSPResp response = new OCSPResp(respBytes);
        assertEquals("Response status not zero.", 0, response.getStatus());
        
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509CertificateHolder[] chain = brep.getCerts();
        boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(chain[0]));
        assertTrue("Response failed to verify.", verify);
        return brep;
    }

    private String getFnrGood(BasicOCSPResp basicOCSPResp) throws IOException {
        byte[] fnrrep = basicOCSPResp.getExtension(FnrFromUnidExtension.FnrFromUnidOid).getExtnValue().getEncoded();
        if (fnrrep == null) {
            return null;
        }
        assertNotNull(fnrrep);
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(fnrrep));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        FnrFromUnidExtension fnrobj = FnrFromUnidExtension.getInstance(aIn.readObject());
        return fnrobj.getFnr();
    }

    private void getFnrNotGood(BasicOCSPResp basicOCSPResp) throws IOException {
        final Extension unidExtension = basicOCSPResp.getExtension(FnrFromUnidExtension.FnrFromUnidOid);
        assertNull(unidExtension);
    }
    
    
    private SSLSocketFactory getSSLFactory(boolean trust) throws GeneralSecurityException, IOException {
        log.trace(">getSSLFactory()");

        final File trustp12 = trust ? new File(LOOKUP_KSTRUST_PATH) : new File(LOOKUP_KSNOTRUST_PATH);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");

        try (final FileInputStream fileInputStream = new FileInputStream(trustp12)) {
            keystore.load(fileInputStream, KEYSTORE_PASS_PHRASE.toCharArray());
        }

        keyManagerFactory.init(keystore, KEYSTORE_PASS_PHRASE.toCharArray());

        // Now make a truststore to verify the server
        KeyStore trustks = KeyStore.getInstance("jks");
        trustks.load(null, TRUSTSTORE_PASS_PHRASE.toCharArray());

        // add trusted CA cert
        List<String> aliases = Collections.list(keystore.aliases());
        Certificate[] certs = null;

        for (final String alias : aliases) {
            if (alias.equals(TRUSTED_CA_NAME)) {
                continue;
            }
            certs = KeyTools.getCertChain(keystore, alias);
        }
        
        trustks.setCertificateEntry("trusted", certs[certs.length - 1]);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(trustks);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        log.trace("<getSSLFactory()");
        return ctx.getSocketFactory();

    }

    /**
     * 
     * @param url
     * @param trust should be set to false when we want to use an un-trusted keystore
     * @return URLConnection
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private URLConnection getUrlConnection(URL url, boolean trust) throws IOException, GeneralSecurityException {
        log.trace(">getUrlConnection( URL url )");
        log.debug(" - url=" + url);
        URLConnection orgcon = url.openConnection();
        log.debug(orgcon.getClass());
        if (orgcon instanceof HttpsURLConnection) {
            HttpsURLConnection con = (HttpsURLConnection) orgcon;
            con.setHostnameVerifier(new SimpleVerifier());
            con.setSSLSocketFactory(getSSLFactory(trust));
        } else {
            log.debug("getUrlConnection(): Ingen HttpsUrlConnection!");
        }
        log.trace("<getUrlConnection() --> " + orgcon);
        return orgcon;
    }
    
    class SimpleVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }
}
