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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/** 
 * Test requiring signed OCSP requests.
 * 
 * @version $Id$
 **/
public class ProtocolOcspSignedHttpTest extends CaTestCase {
    private static Logger log = Logger.getLogger(ProtocolOcspSignedHttpTest.class);
    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private static final String END_ENTITY_NAME = "ocsptest";
    
    protected static byte[] unknowncacertBytes = Base64.decode(("MIICLDCCAZWgAwIBAgIIbzEhUVZYO3gwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE" +
            "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDcw" +
            "OTEyNDc1OFoXDTA0MDgxNTEyNTc1OFowLzEPMA0GA1UEAxMGVGVzdENBMQ8wDQYD" +
            "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB" +
            "hwKBgQDZlACHRwJnQKlgpMqlZQmxvCrJPpPFyhxvjDHlryhp/AQ6GCm+IkGUVlwL" +
            "sCnjgZH5BXDNaVXpkmME8334HFsxVlXqmZ2GqyP6kptMjbWZ2SRLBRKjAcI7EJIN" +
            "FPDIep9ZHXw1JDjFGoJ4TLFd99w9rQ3cB6zixORoyCZMw+iebwIBEaNTMFEwDwYD" +
            "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUY3v0dqhUJI6ldKV3RKb0Xg9XklEwHwYD" +
            "VR0jBBgwFoAUY3v0dqhUJI6ldKV3RKb0Xg9XklEwDQYJKoZIhvcNAQEFBQADgYEA" +
            "i1P53jnSPLkyqm7i3nLNi+hG7rMgF+kRi6ZLKhzIPyKcAWV8iZCI8xl/GurbZ8zd" +
            "nTiIOfQIP9eD/nhIIo7n4JOaTUeqgyafPsEgKdTiZfSdXjvy6rj5GiZ3DaGZ9SNK" +
            "FgrCpX5kBKVbbQLO6TjJKCjX29CfoJ2TbP1QQ6UbBAY=").getBytes());

    private int caid = getTestCAId();
    private static AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ProtocolOcspSignedHttpTest"));
    private static X509Certificate cacert = null;
    private static X509Certificate ocspTestCert = null;
    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private OcspJunitHelper helper = null;
 
    private int internalKeyBindingId;
    
    private String originalSigRequiredValue;
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        final String remoteHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        final String remotePort = SystemTestsConfiguration.getRemotePortHttp("8080");
        helper = new OcspJunitHelper("http://"+remoteHost+":"+remotePort+"/ejbca", "publicweb/status/ocsp"); 
        cacert = (X509Certificate) getTestCACert();
        originalSigRequiredValue =  configurationSessionRemote.getConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED);
    	configurationSessionRemote.setConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED, "true");
    	internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(admin, caSession.getCAInfo(admin, getTestCAId()).getCAToken().getCryptoTokenId(),
    	        OcspKeyBinding.IMPLEMENTATION_ALIAS, ProtocolOcspSignedHttpTest.class.getSimpleName(), "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
    	ocspResponseGeneratorTestSession.reloadOcspSigningCache();
    	internalCertificateStoreSession.reloadCaCertificateCache();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        configurationSessionRemote.setConfigurationValue(OcspConfiguration.SIGNATUREREQUIRED, originalSigRequiredValue);
        for (Certificate certificate : certificateStoreSession.findCertificatesByUsername(END_ENTITY_NAME)) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
        internalKeyBindingMgmtSession.deleteInternalKeyBinding(admin, internalKeyBindingId);
    }

    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    /** Tests ocsp message
     * @throws Exception error
     */
    @Test
    public void test01OcspGood() throws Exception {
        log.trace(">test01OcspGood()");

        // find a CA (TestCA?) create a user and generate his cert
        // send OCSP req to server and get good response
        // change status of cert to bad status
        // send OCSP req and get bad status
        // (send crap message and get good error)

        // Make user that we know...
        boolean userExists = endEntityManagementSession.existsUser(END_ENTITY_NAME);
        if (!userExists) {
            endEntityManagementSession.addUser(admin, END_ENTITY_NAME, "foo123", "C=SE,O=AnaTom,CN=OCSPTest", null, "ocsptest@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                    SecConst.TOKEN_SOFT_PEM, 0, caid);
            log.debug("created user: ocsptest, foo123, C=SE, O=AnaTom, CN=OCSPTest");
        } else {
            log.debug("User ocsptest already exists.");
            EndEntityInformation userData = new EndEntityInformation(END_ENTITY_NAME, "C=SE,O=AnaTom,CN=OCSPTest",
                    caid, null, "ocsptest@anatom.se", EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, 0,
                    null);
            userData.setPassword("foo123");
            endEntityManagementSession.changeUser(admin, userData, false);
            log.debug("Reset status to NEW");
        }
        try {
            // Generate certificate for the new user
            KeyPair keys = KeyTools.genKeys("512", "RSA");

            // user that we know exists...
            ocspTestCert = (X509Certificate) signSession.createCertificate(admin, "ocsptest", "foo123", new PublicKeyWrapper(keys.getPublic()));
            assertNotNull("Failed to create a certificate", ocspTestCert);

            // And an OCSP request
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
            Extension[] extensions = new Extension[1];
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
            gen.setRequestExtensions(new Extensions(extensions));      
            X509CertificateHolder chain[] = new JcaX509CertificateHolder[2];
            chain[0] = new JcaX509CertificateHolder(ocspTestCert);
            chain[1] = new JcaX509CertificateHolder(cacert);
            gen.setRequestorName(chain[0].getSubject());
            OCSPReq req = gen.build(
                    new BufferingContentSigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
                            keys.getPrivate()), 20480), chain);
            // Send the request and receive a singleResponse
            SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", OCSPResponseStatus.SUCCESSFUL, 200);
            assertEquals("Number of of SingResps should be 1.", 1, singleResps.length);
            SingleResp singleResp = singleResps[0];

            CertificateID certId = singleResp.getCertID();
            assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
            Object status = singleResp.getCertStatus();
            assertEquals("Status is not null (good)", null, status);

            // Try with an unsigned request, we should get a status code 5 back from the server (signature required)
            req = gen.build();
            // Send the request and receive a singleResponse, this response should have error code SIGNATURE_REQUIRED
            singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", OCSPResponseStatus.SIG_REQUIRED, 200);
            assertNull(singleResps);

            // sign with a keystore where the CA-certificate is not known
            KeyStore store = KeyStore.getInstance("PKCS12", "BC");
            ByteArrayInputStream fis = new ByteArrayInputStream(ks3);
            store.load(fis, "foo123".toCharArray());
            Certificate[] certs = KeyTools.getCertChain(store, "privateKey");
            chain[0] = new JcaX509CertificateHolder((X509Certificate)certs[0]);
            chain[1] = new JcaX509CertificateHolder((X509Certificate)certs[1]);
            PrivateKey pk = (PrivateKey)store.getKey("privateKey", "foo123".toCharArray());
            req = gen.build(new BufferingContentSigner(new JcaContentSignerBuilder("SHA1withRSA").build(pk), 20480), chain);
            // Send the request and receive a singleResponse, this response should have error code UNAUTHORIZED (6)
            singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", OCSPResponseStatus.UNAUTHORIZED, 200);
            assertNull(singleResps);
        } finally {
            endEntityManagementSession.deleteUser(roleMgmgToken, END_ENTITY_NAME);
        }
        log.trace("<test01OcspGood()");
    }


    private static byte[] ks3 = Base64.decode(("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCAyYwgDCABgkqhkiG9w0BBwGggCSABIID"
            + "DjCCAwowggMGBgsqhkiG9w0BDAoBAqCCAqkwggKlMCcGCiqGSIb3DQEMAQMwGQQU"
            + "/h0pQXq7ZVjYWlDvzEwwmiJ8O8oCAWQEggJ4MZ12+kTVGd1w7SP4ZWlq0bCc4MsJ"
            + "O0FFSX3xeVp8Bx16io1WkEFOW3xfqjuxKOL6YN9atoOZdfhlOMhmbhglm2PJSzIg"
            + "JSDHvWk2xKels5vh4hY1iXWOh48077Us4wP4Qt94iKglCq4xwxYcSCW8BJwbu93F"
            + "uxE1twnWXbH192nMhaeIAy0v4COdduQamJEtHRmIJ4GZwIhH+lNHj/ARdIfNw0Dm"
            + "uPspuSu7rh6rQ8SrRsjg63EoxfSH4Lz6zIJKF0OjNX07T8TetFgznCdGCrqOZ1fK"
            + "5oRzXIA9hi6UICiuLSm4EoHzEpifCObpiApwNj3Kmp2uyz2uipU0UKhf/WqvmU96"
            + "yJj6j1JjZB6p+9sgecPFj1UMWhEFTwxMEwR7iZDvjkKDNWMit+0cQyeS7U0Lxn3u"
            + "m2g5e6C/1akwHZsioLC5OpFq/BkPtnbtuy4Kr5Kwb2y7vSiKpjFr7sKInjdAsgCi"
            + "8kyUV8MyaIfZdtREjwqBe0imfP+IPVqAsl1wGW95YXsLlK+4P1bspAgeHdDq7Q91"
            + "bJJQAS5OTD38i1NY6MRtt/fWsShVBLjf2FzNpw6siHHl2N7BDNyO3ALtgfp50e0Z"
            + "Dsw5WArgKLiXfwZIrIKbYA73RFc10ReDqnJSF+NXgBo1/i4WhZLHC1Osl5UoKt9q"
            + "UoXIUmYhAwdAT5ZKVw6A8yp4e270yZTXNsDz8u/onEwNc1iM0v0RnPQhNE5sKEZH"
            + "QrMxttiwbKe3YshCjbruz/27XnNA51t2p1M6eC1HRab4xSHAyH5NTxGJ8yKhOfiT"
            + "aBKqdTH3P7QzlcoCUDVDDe7aLMaZEf+a2Te63cZTuUVpkysxSjAjBgkqhkiG9w0B"
            + "CRQxFh4UAHAAcgBpAHYAYQB0AGUASwBlAHkwIwYJKoZIhvcNAQkVMRYEFCfeHSg6"
            + "EdeP5A1IC8ydjyrjyFSdAAQBAAQBAAQBAAQBAASCCBoAMIAGCSqGSIb3DQEHBqCA"
            + "MIACAQAwgAYJKoZIhvcNAQcBMCcGCiqGSIb3DQEMAQYwGQQURNy47tUcttscSleo"
            + "8gY6ZAPFOl0CAWSggASCB8jdZ+wffUP1B25Ys48OFBMg/itT0EBS6J+dYVofZ84c"
            + "x41q9U+CRMZJwVNZbkqfRZ+F3tLORSwuIcwyioa2/JUpv8uJCjQ2tru5+HtqCrzR"
            + "Huh7TfdiMqvjkKpnXi69DPPjQdCSPwYMy1ahZrP5KgEZg4S92xpU2unF1kKQ30Pq"
            + "PTEBueDlFC39rojp51Wsnqb1QzjPo53YvJQ8ztCoG0yk+0omELyPbc/qMKe5/g5h"
            + "Lx7Q+2D0PC/ZHtoDkCRfMDKwgwALFsSj2uWNJsCplspmc7YgIzSr/GqqeSXHp4Ue"
            + "dwVJAswrhpkXZTlp1rtl/lCSFl9akwjY1fI144zfpYKpLqfoHL1uI1c3OumrFzHd"
            + "ZldZYgsM/h3qjgu8qcXqI0sKVXsffcftCaVs+Bxmdu9vpY15rlx1e0an/O05nMKU"
            + "MBU2XpGkmWxuy0tOKs3QtGzHUJR5+RdEPURctRyZocEjJgTvaIMq1dy/FIaBhi+d"
            + "IeAbFmjBu7cv9C9v/jMuUjLroycmo7QW9jGgyTOQ68J+6w2/PtqiqIo3Ry9WC0SQ"
            + "8+fVNOGLr5O2YPpw17sDQa/+2gjozngvL0OHiABwQ3EbXAQLF046VYkTi5R+8iGV"
            + "3jlTvvStIKY06E/s/ih86bzwJWAQENCazXErN69JO+K3IUiwxac+1AOO5WyR9qyv"
            + "6m/yHdIdbOVE21M2RARbI8UiDpRihCzk4duPfj/x2bZyFqLclIMhbTd2UOQQvr+W"
            + "4etpMJRtyFGhdLmNgYAhYrbUgmdL1kRkzPzOs77PqleMpfkii7HPk3HlVkM7NIqd"
            + "dN0WQaQwGJuh5f1ynhyqtsaw6Gu/X56H7hpziAh0eSDQ5roRE7yy98h2Mcwb2wtY"
            + "PqVFTmoKuRWR2H5tT6gCaAM3xiSC7RLa5SF1hYQGaqunqBaNPYyUIg/r03dfwF9r"
            + "AkOhh6Mq7Z2ktzadWTxPl8OtIZFVeyqIOtSKBHhJyGDGiz3+SSnTnSX81NaTSJYZ"
            + "7YTiXkXvSYNpjpPckIKfjpBw0T4pOva3a6s1z5p94Dkl4kz/zOmgveGd3dal6wUV"
            + "n3TR+2cyv51WcnvB9RIp58SJOc+CvCvYTvkEdvE2QtRw3wt4ngGJ5pxmC+7+8fCf"
            + "hRDzw9LBNz/ry88y/0Bidpbhwr8gEkmHuaLp43WGQQsQ+cWYJ8AeLZMvKplbCWqy"
            + "iuks0MnKeaC5dcB+3BL55OvcTfGkMtz0oYBkcGBTbbR8BKJZgkIAx7Q+/rCaqv6H"
            + "HN/cH5p8iz5k+R3MkmR3gi6ktelQ2zx1pbPz3IqR67cTX3IyTX56F2aY54ueY17m"
            + "7hFwSy4aMen27EO06DXn/b6vPKj73ClE2B/IPHO/H2e8r04JWMltFWuStV0If5x0"
            + "5ZImXx068Xw34eqSWvoMzr97xDxUwdlFgrKrkMKNoTDhA4afrZ/lwHdUbNzh6cht"
            + "jHW/IfIaMo3NldN/ihO851D399FMsWZW7YA7//RrWzBDiLvh+RfwkMOfEpbujy0G"
            + "73rO/Feed2MoVXvmuKBRpTNyFuBVvFDwIzBT4m/RaVf5m1pvprSk3lo43aumdN9f"
            + "NDETktVZ/CYaKlYK8rLcNBKJicM5+maiQSTa06XZXDMY84Q0xtCqJ/aUH4sa/z8j"
            + "KukVUSyUZDJk/O82B3NA4+CoP3Xyc9LAUKucUvoOmGt2JCw6goB/vqeZEg9Tli0Q"
            + "+aRer720QdVRkPVXKSshL2FoXHWUMaBF8r//zT6HbjTNQEdxbRcBNvkUXUHzITfl"
            + "YjQcEn+FGrF8+HVdXCKzSXSgu7mSouYyJmZh42spUFCa4j60Ks1fhQb2H1p72nJD"
            + "n1mC5sZkU68ITVu1juVl/L2WJPmWfasb1Ihnm9caJ/mEE/i1iKp7qaY9DPTw5hw4"
            + "3QplYWFv47UA/sOmnWwupRuPk7ISdimuUnih8OYR75rJ0z6OYexvj/2svx9/O5Mw"
            + "654jFF2hAq69jt7GJo6VZaeCRCAxEU7N97l3EjqaKJVrpIPQ+3yLmqHit/CWxImB"
            + "iIl3sW7MDEHgPdQy3QiZmAYNLQ0Te0ygcIHwtPyzhFoFmjbQwib2vxDqWaMQpUM1"
            + "/W96R/vbCjA7tfKYchImwAPCyRM5Je2FHewErG413kZct5tJ1JqkcjPsP7Q8kmgw"
            + "Ec5QNq1/PZOzL1ZLr6ryfA4gLBXa6bJmf43TUkdFYTvIYbvH2jp4wpAtA152YgPI"
            + "FL19/Tv0B3Bmb1qaK+FKiiQmYfVOm/J86i/L3b8Z3jj8dRWEBztaI/KazZ/ZVcs/"
            + "50bF9jH7y5+2uZxByjkM/kM/Ov9zIHbYdxLw2KHnHsGKTCooSSWvPupQLBGgkd6P"
            + "M9mgE6MntS+lk9ucpP5j1LXo5zlZaLSwrvSzE3/bbWJKsJuomhRbKeZ+qSYOWvPl"
            + "/1RqREyZHbSDKzVk39oxH9EI9EWKlCbrz5EHWiSv0+9HPczxbO3q+YfqcY8plPYX"
            + "BvgxHUeDR+LxaAEcVEX6wd2Pky8pVwxQydU4cEgohrgZnKhxxLAvCp5sb9kgqCrh"
            + "luvBsHpmiUSCi/r0PNXDgApvTrVS/Yv0jTpX9u9IWMmNMrnskdcP7tpEdkw8/dpf"
            + "RFLLgqwmNEhCggfbyT0JIUxf2rldKwd6N1wZozaBg1uKjNmAhJc1RxsABAEABAEA"
            + "BAEABAEABAEABAEABAEABAEABAEABAEABAEAAAAAAAAAMDwwITAJBgUrDgMCGgUA"
            + "BBSS2GOUxqv3IT+aesPrMPNn9RQ//gQUYhjCLPh/h2ULjh+1L2s3f5JIZf0CAWQA"
            + "AA==").getBytes());

}
