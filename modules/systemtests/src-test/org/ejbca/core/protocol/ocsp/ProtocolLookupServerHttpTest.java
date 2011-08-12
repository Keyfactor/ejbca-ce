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

package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
import java.util.Enumeration;
import java.util.Hashtable;

import javax.ejb.EJBException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests http pages of ocsp lookup server. This test requires a lot of setup. - The lookup service must be active - There must be a database for the
 * unid-fnr mapping with the mapping 123456789, 654321 - You must have a CA that has issued certificates with serialNumber in the DN matching the unid
 * 123456789 - You also need a keystore issued by the CA for TLS communication, the keystore cert must be configured in the lookup extension as
 * trusted - /lookup-kstrust.p12 (password lookup) - You also need a keystore as above but not configured as trusted in the lookup extension -
 * /lookup-ksnotrust.p12 (password lookup) - The CA-certificate issuing the two keystores should be configured in ejbca.properties
 * 
 * Simply create two new users with batch generation and PKCS12 keystores in ejbca and issue their keystores. The SSL certificate used for JBoss must
 * be issued by the same CA that creates lookup-kstrust.p12.
 * 
 * The database table for the UnidFnrMapping should look like (MySQL): CREATE TABLE UnidFnrMapping( unid varchar(250) NOT NULL DEFAULT '', fnr
 * varchar(250) NOT NULL DEFAULT '', PRIMARY KEY (unid) );
 * 
 **/
public class ProtocolLookupServerHttpTest extends CaTestCase {
    private static Logger log = Logger.getLogger(ProtocolLookupServerHttpTest.class);

    private String httpReqPath;
    private String resourceOcsp;

    private int caid = getTestCAId();
    private static AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    private static X509Certificate cacert = null;
    private static X509Certificate ocspTestCert = null;
    private static KeyPair keys = null;

    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private RevocationSessionRemote revocationSession = InterfaceCache.getRevocationSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();

    @BeforeClass
    public static void beforeClass() {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        httpReqPath = "https://127.0.0.1:8443/ejbca";
        resourceOcsp = "publicweb/status/ocsp";
        cacert = (X509Certificate) getTestCACert();
        keys = KeyTools.genKeys("512", "RSA");
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
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
            userAdminSession.addUser(admin, "unidtest", "foo123", "C=SE,O=AnaTom,surname=Jansson,serialNumber=123456789,CN=UNIDTest", null,
                    "unidtest@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER,
                    SecConst.TOKEN_SOFT_PEM, 0, caid);
            log.debug("created user: unidtest, foo123, C=SE, O=AnaTom,surname=Jansson,serialNumber=123456789, CN=UNIDTest");
        } catch (EJBException e) {
            if (e.getCause() instanceof PersistenceException) {
                userExists = true;
            }
        }
        if (userExists) {
            log.debug("User unidtest already exists.");
            userAdminSession.changeUser(admin, "unidtest", "foo123", "C=SE,O=AnaTom,surname=Jansson,serialNumber=123456789,CN=UNIDTest", null,
                    "unidtest@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER,
                    SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, caid);
            log.debug("Reset status to NEW");
        }
        // Generate certificate for the new user

        // user that we know exists...
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, "unidtest", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", ocspTestCert);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("123456789")));
        exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        assertEquals(getFnr(brep), "654321");
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
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
        revocationSession.revokeCertificate(admin, ocspTestCert, null, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("123456789")));
        exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        // When a certificate is revoked the FNR must not be returned
        assertEquals(getFnr(brep), null);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
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
        userAdminSession.changeUser(admin, "unidtest", "foo123", "C=SE,O=AnaTom,surname=Jansson,serialNumber=12345678,CN=UNIDTest", null,
                "unidtest@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, caid);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, "unidtest", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", ocspTestCert);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("123456789")));
        exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        assertEquals(getFnr(brep), null);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /**
     * Tests ocsp message with good status but no serialNnumber in the DN
     * 
     * @throws Exception error
     */
    @Test
    public void test04OcspGoodNoSerialNo() throws Exception {
        // Change uses to not have any serialNumber
        userAdminSession.changeUser(admin, "unidtest", "foo123", "C=SE,O=AnaTom,surname=Jansson,CN=UNIDTest", null, "unidtest@anatom.se", false,
                SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0,
                UserDataConstants.STATUS_NEW, caid);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, "unidtest", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", ocspTestCert);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("123456789")));
        exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        assertEquals(getFnr(brep), null);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /**
     * test a lookup message from an untrusted requestor, should not work
     * 
     * @throws Exception
     */
    @Test
    public void test05HttpsNotAuthorized() throws Exception {
        // Change uses to a Unid that is OK
        userAdminSession.changeUser(admin, "unidtest", "foo123", "C=SE,O=AnaTom,surname=Jansson,serialNumber=123456789,CN=UNIDTest", null,
                "unidtest@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, caid);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, "unidtest", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", ocspTestCert);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("123456789")));
        exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), false);
        assertEquals(getFnr(brep), null);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /**
     * test a lookup request with regular http, should not work
     * 
     * @throws Exception
     */
    @Test
    public void test06HttpNotAuthorized() throws Exception {
        // Change to use plain http, we should be able to get a OCSP response, but the FNR mapping
        // will not be returned bacuse it requires https with client authentication
        httpReqPath = "http://127.0.0.1:8080/ejbca";
        // Change uses to a Unid that is OK
        userAdminSession.changeUser(admin, "unidtest", "foo123", "C=SE,O=AnaTom,surname=Jansson,serialNumber=123456789,CN=UNIDTest", null,
                "unidtest@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, caid);
        log.debug("Reset status to NEW");
        // Generate certificate for the new/changed user
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, "unidtest", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", ocspTestCert);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString(new FnrFromUnidExtension("123456789")));
        exts.put(FnrFromUnidExtension.FnrFromUnidOid, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a BasicResponse
        BasicOCSPResp brep = sendOCSPPost(req.getEncoded(), true);
        assertEquals(getFnr(brep), null);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    //
    // Private helper methods
    //

    private BasicOCSPResp sendOCSPPost(byte[] ocspPackage, boolean trust) throws IOException, OCSPException, GeneralSecurityException {
        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        // HttpURLConnection con = (HttpURLConnection)url.openConnection();
        HttpURLConnection con = (HttpURLConnection) getUrlConnection(url, trust);
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(ocspPackage);
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/ocsp-response", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and OCSP requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(respBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509Certificate[] chain = brep.getCerts("BC");
        boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
        assertTrue("Response failed to verify.", verify);
        return brep;
    }

    private String getFnr(BasicOCSPResp brep) throws IOException {
        byte[] fnrrep = brep.getExtensionValue(FnrFromUnidExtension.FnrFromUnidOid.getId());
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

    private SSLSocketFactory getSSLFactory(boolean trust) throws GeneralSecurityException, IOException {
        log.trace(">getSSLFactory()");

        String trustp12 = "/lookup-kstrust.p12";
        if (!trust) {
            trustp12 = "/lookup-ksnotrust.p12";
        }
        char[] passphrase = "lookup".toCharArray();

        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");

        // Put the key and certs in the user keystore
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(trustp12), passphrase);
        kmf.init(ks, passphrase);

        // Now make a truststore to verify the server
        KeyStore trustks = KeyStore.getInstance("jks");
        trustks.load(null, "foo123".toCharArray());
        // add trusted CA cert
        Enumeration<String> en = ks.aliases();
        String alias = en.nextElement();
        Certificate[] certs = KeyTools.getCertChain(ks, alias);
        trustks.setCertificateEntry("trusted", certs[certs.length - 1]);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustks);

        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

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
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

}
