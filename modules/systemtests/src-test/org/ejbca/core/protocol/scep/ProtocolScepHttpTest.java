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

package org.ejbca.core.protocol.scep;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Random;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.util.Streams;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.junit.util.CryptoTokenRule;
import org.cesecore.junit.util.CryptoTokenTestRunner;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.Configuration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import com.gargoylesoftware.htmlunit.SubmitMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 * Tests http pages of scep
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(CryptoTokenTestRunner.class)
public class ProtocolScepHttpTest {
    private static final Logger log = Logger.getLogger(ProtocolScepHttpTest.class);

    private static final String scepAlias = "ProtocolHttpTestScepAlias";
    private static final String resourceScep = "publicweb/apply/scep/" + scepAlias + "/pkiclient.exe";

    private static final byte[] openscep = Base64.decode(("MIIGqwYJKoZIhvcNAQcCoIIGnDCCBpgCAQExDjAMBggqhkiG9w0CBQUAMIICuwYJ"
            + "KoZIhvcNAQcBoIICrASCAqgwggKkBgkqhkiG9w0BBwOgggKVMIICkQIBADGB1TCB" + "0gIBADA7MC8xDzANBgNVBAMTBlRlc3RDQTEPMA0GA1UEChMGQW5hVG9tMQswCQYD"
            + "VQQGEwJTRQIIbzEhUVZYO3gwDQYJKoZIhvcNAQEBBQAEgYCksIoSXYsCQPot2DDW" + "dexdFqLj1Fuz3xSpu/rLozXKxEY0n0W0JXRR9OxxuyqNw9cLZhiyWkNsJGbP/rEz"
            + "yrXe9NXuLK5U8+qqE8OhnY9BhCxjeUJSLni6oCSi7YzwOqdg2KmifJrQQI/jZIiC" + "tSISAtE6qi6DKQwLCkQLmokLrjCCAbIGCSqGSIb3DQEHATARBgUrDgMCBwQILYvZ"
            + "rBWuC02AggGQW9o5MB/7LN4o9G4ZD1l2mHzS+g+Y/dT2qD/qIaQi1Mamv2oKx9eO" + "uFtaGkBBGWZlIKg4mm/DFtvXqW8Y5ijAiQVHHPuRKNyIV6WVuFjNjhNlM+DWLJR+"
            + "rpHEhvB6XeDo/pd+TyOKFcxedMPTD7U+j46yd46vKdmoKAiIF21R888uVSz3GDts" + "NlqgvZ7VlaI++Tj7aPdOI7JTdQXZk2FWF7Ql0LBIPwk9keffptF5if5Y+aHqB0a2"
            + "uQj1aE8Em15VG8p8MmLJOX0OA1aeqfxR0wk343r44UebliY2DE8cEnym/fmya30/" + "7WYzJ7erWofO2ukg1yc93wUpyIKxt2RGIy5geqQCjCYSSGgaNFafEV2pnOVSx+7N"
            + "9z/ICNQfDBD6b83MO7yPHC1cXcdREKHHeqaKyQLiVRk9+R/3D4vEZt682GRaUKOY" + "PQXK1Be2nyZoo4gZs62nZVAliJ+chFkEUog9k9OsIvZRG7X+VEjVYBqxlE1S3ikt"
            + "igFXiuLC/LDCi3IgVwQjfNx1/mhxsO7GSaCCAfswggH3MIIBYKADAgEDAiA4OEUy" + "REVFNDcwNjhCQjM3RjE5QkE2NDdCRjAyRkQwRjANBgkqhkiG9w0BAQQFADAyMQsw"
            + "CQYDVQQGEwJTZTERMA8GA1UEChMIUHJpbWVLZXkxEDAOBgNVBAMTB1RvbWFzIEcw" + "HhcNMDMwNjAxMDgzNDQyWhcNMDMwNzAxMDgzNDQyWjAyMQswCQYDVQQGEwJTZTER"
            + "MA8GA1UEChMIUHJpbWVLZXkxEDAOBgNVBAMTB1RvbWFzIEcwgZ8wDQYJKoZIhvcN" + "AQEBBQADgY0AMIGJAoGBAOu47fpIQfzfSnEBTG2WJpKZz1891YLNulc7XgMk8hl3"
            + "nVC4m34SaR7eXR3nCsorYEpPPmL3affaPFsBnNBQNoZLxKmQ1RKiDyu8dj90AKCP" + "CFlIM2aJbKMiQad+dt45qse6k0yTrY3Yx0hMH76tRkDif4DjM5JUvdf4d/zlYcCz"
            + "AgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAGNoWI02kXNEA5sPHb3KEY8QZoYM5Kha1" + "JA7HLmlXKy6geeJmk329CUnvF0Cr7zxbMkFRdUDUtR8omDDnGlBSOCkV6LLYH939"
            + "Z8iysfaxigZkxUqUYGLtYHhsEjVgcpfKZVxTz0E2ocR2P+IuU04Duel/gU4My6Qv" + "LDpwo1CQC10xggHDMIIBvwIBATBWMDIxCzAJBgNVBAYTAlNlMREwDwYDVQQKEwhQ"
            + "cmltZUtleTEQMA4GA1UEAxMHVG9tYXMgRwIgODhFMkRFRTQ3MDY4QkIzN0YxOUJB" + "NjQ3QkYwMkZEMEYwDAYIKoZIhvcNAgUFAKCBwTASBgpghkgBhvhFAQkCMQQTAjE5"
            + "MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTAzMDYw" + "MTA4MzQ0MlowHwYJKoZIhvcNAQkEMRIEEBqGJFo7n4B8sFBCi54PckIwIAYKYIZI"
            + "AYb4RQEJBTESBBA77Owxh2rbflhXsDYw3xsLMDAGCmCGSAGG+EUBCQcxIhMgODhF" + "MkRFRTQ3MDY4QkIzN0YxOUJBNjQ3QkYwMkZEMEYwDQYJKoZIhvcNAQEBBQAEgYB4"
            + "BPcw4NPIt4nMOFKSGg5oM1nGDPGFN7eorZV+/2uWiQfdtK4B4lzCTuNxWRT853dW" + "dRDzXBCGEArlG8ef+vDD/HP9SX3MQ0NJWym48VI9bTpP/mJlUKSsfgDYHohvUlVI"
            + "E5QFC6ILVLUmuWPGchUEAb8t30DDnmeXs8QxdqHfbQ==").getBytes());

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ProtocolScepHttpTest"));
    private static X509CA x509ca;
    private static X509Certificate cacert;
    private static KeyPair key1;
    private static KeyPair key2;
    private static final String userName1 = "sceptest1";
    private static final String userName2 = "sceptest2";
    private static final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
    private static final String userDN2 = "C=SE,O=PrimeKey,CN=" + userName2;
    private static String senderNonce = null;
    private static String transId = null;

    private Random rand = new Random();
    private String httpReqPath;
    private ScepConfiguration scepConfiguration;

    private final ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);

    @ClassRule
    public static CryptoTokenRule cryptoTokenRule = new CryptoTokenRule();
    
    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        // Pre-generate key for all requests to speed things up a bit
        try {
            key1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            key2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        x509ca = cryptoTokenRule.createX509Ca();
        cacert = (X509Certificate) x509ca.getCACertificate();
    }

    @Before
    public void setUp() throws Exception {
        final String httpHost = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        final String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        httpReqPath = "http://"+httpHost+":" + httpPort + "/ejbca";
             
        scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(Configuration.ScepConfigID);
        scepConfiguration.addAlias(scepAlias);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);

    }

    @After
    public void tearDown() throws Exception {
        // remove user
        try {
        	endEntityManagementSession.deleteUser(admin, userName1);
        	log.debug("deleted user: " + userName1);
        } catch (Exception e) {
        	// NOPMD: ignore
        }
        try {
        	endEntityManagementSession.deleteUser(admin, userName2);
        	log.debug("deleted user: " + userName2);
        } catch (Exception e) {
        	// NOPMD: ignore
        }        
        
        scepConfiguration.removeAlias(scepAlias);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
    }

    @AfterClass
    public static void afterClass() {
        cryptoTokenRule.cleanUp();
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Test
    public void test01Access() throws Exception {
        // Hit scep
        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        
        // Gives a 400: Bad Request
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceScep));
        WebResponse resp = con.getResponse(settings);
        assertEquals("Response code", 400, resp.getStatusCode());
    }

    @Test
    public void test02AccessTest() throws Exception {
        
        ScepConfiguration scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(Configuration.ScepConfigID);
        boolean remove = false;
        if(!scepConfig.aliasExists("scep")) {
            scepConfig.addAlias("scep");
            globalConfigSession.saveConfiguration(admin, scepConfig, Configuration.ScepConfigID);
            remove = true;
        }
        
        String resourceName = "/ejbca/publicweb/apply/scep/pkiclient.exe?operation=GetCACert&message=" + x509ca.getName();
        String httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        String httpBaseUrl = "http://" + httpHost + ":" + httpPort;
        
        
        String url = httpBaseUrl + resourceName;
        final HttpURLConnection con;
        URL u = new URL(url);
        con = (HttpURLConnection)u.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        
        int ret = con.getResponseCode();
        log.debug("HTTP response code: "+ret);
        if ( ret == 200 ) {
            log.debug(Streams.asString(con.getInputStream())); 
        }
        con.disconnect();
        
        if(remove) {
            scepConfig.removeAlias("scep");
            globalConfigSession.saveConfiguration(admin, scepConfig, Configuration.ScepConfigID);
        }
        assertEquals("HTTP GET is not supported. (This test expects " + httpBaseUrl+resourceName + " to exist)", 200, ret);
        
    }

    /**
     * Tests that the right configuration alias is extracted from the SCEP URL. 
     * 
     * A SCEP request for a non-existing alias is sent. Expected an error message caused by the absence of the expected SCEP alias 
     * 
     * @throws Exception
     */
    @Test
    public void test02Access() throws Exception {
        log.trace(">test02Access()");
        
        ScepConfiguration scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(Configuration.ScepConfigID);
        
        sendScepAliasRequest(scepConfig, "alias123", "alias123", "SCEP alias 'alias123' does not exist"); // "alias123" in the request causes Ejbca to use "alias123" as SCEP alias
        sendScepAliasRequest(scepConfig, "123", "123", "SCEP alias '123' does not exist"); // "123" in the request causes Ejbca to use "123" as SCEP alias
        sendScepAliasRequest(scepConfig, "", "scep", "SCEP alias 'scep' does not exist"); // No alias in the request causes Ejbca to use "scep" (the default alias) as SCEP alias
        sendScepAliasRequest(scepConfig, null, "scep", "SCEP alias 'scep' does not exist"); // No alias in the request causes Ejbca to use "scep" (the default alias) as SCEP alias
        sendScepAliasRequest(scepConfig, "alias??&!!foo", null, "Wrong URL. No alias found"); // Specifying alias with non-alphanumeric characters causes the request to fail. 

        log.trace("<test02Access()");
    }
    

    /**
     * Tests a random old scep message from OpenScep
     * 
     * @throws Exception error
     */
    @Test
    public void test03OpenScep() throws Exception {
        log.debug(">test02OpenScep()");
        // send message to server and see what happens
        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceScep), SubmitMethod.GET);
        ArrayList<NameValuePair> l = new ArrayList<NameValuePair>();
        l.add(new NameValuePair("operation", "PKIOperation"));
        l.add(new NameValuePair("message", new String(Base64.encode(openscep))));
        settings.setRequestParameters(l);
        WebResponse resp = con.getResponse(settings);
        // TODO: since our request most certainly uses the wrong CA cert to
        // encrypt the
        // request, it will fail. If we get something back, we came a little bit
        // at least :)
        // We should get a NOT_FOUND error back.
        assertEquals("Response code", 404, resp.getStatusCode());
        log.debug("<test02OpenScep()");
    }

    @Test
    public void test04ScepRequestOKSHA1() throws Exception {
        log.debug(">test03ScepRequestOKSHA1()");
        // find a CA create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
        
        // Make user that we know...
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA1, userDN1);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, false);
        
        log.debug("<test03ScepRequestOKSHA1()");
    }

    @Test
    public void test05ScepRequestOKMD5() throws Exception {
        log.debug(">test04ScepRequestOKMD5()");
        // find a CA create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
        
        // Make user that we know...
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_MD5, userDN1);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_MD5, false);
        
        log.debug("<test04ScepRequestOKMD5()");
    }

    @Test
    public void test06ScepRequestPostOK() throws Exception {
        log.debug(">test05ScepRequestPostOK()");
        // find a CA, create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
        
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA1, userDN1);
        // Send message with GET
        byte[] retMsg = sendScep(true, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, false);
        
        log.debug(">test05ScepRequestPostOK()");
    }

    @Test
    public void test07ScepRequestPostOKNoCA() throws Exception {
        log.debug(">test06ScepRequestPostOKNoCA()");
        // find a CA, create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
        
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA1, userDN1);
        // Send message with GET
        byte[] retMsg = sendScep(true, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, true);
        
        log.debug(">test06ScepRequestPostOKNoCA()");
    }

    @Test
    public void test08ScepGetCACert() throws Exception {
        log.debug(">test07ScepGetCACert()");
        {
            String reqUrl = httpReqPath + '/' + resourceScep + "?operation=GetCACert&message=" + URLEncoder.encode(x509ca.getName(), "UTF-8");
            URL url = new URL(reqUrl);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Response code is not 200 (OK)", 200, con.getResponseCode());
            // Some appserver (Weblogic) responds with
            // "application/x-x509-ca-cert; charset=UTF-8"
            assertTrue(con.getContentType().startsWith("application/x-x509-ca-cert"));
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
            X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(respBytes);
            // Check that we got the right cert back
            assertEquals(cacert.getSubjectDN().getName(), cert.getSubjectDN().getName());
        }
        
        // 
        // Test the same message but without message component, it should use a default CA
        {
            // Try with a non extisting CA first, should respond with a 404
            updatePropertyOnServer("scep.defaultca", "NonExistingCAForSCEPTest");
            String reqUrl = httpReqPath + '/' + resourceScep + "?operation=GetCACert";
            URL url = new URL(reqUrl);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Response code is not 404 (not found)", 404, con.getResponseCode());
            // Try with the good CA            
            updatePropertyOnServer("scep.defaultca", x509ca.getName());
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Response code is not 200 (OK)", 200, con.getResponseCode());
            // Some appserver (Weblogic) responds with
            // "application/x-x509-ca-cert; charset=UTF-8"
            assertTrue(con.getContentType().startsWith("application/x-x509-ca-cert"));
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
            X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(respBytes);
            // Check that we got the right cert back
            assertEquals(cacert.getSubjectDN().getName(), cert.getSubjectDN().getName());
        }
        log.debug(">test07ScepGetCACert()");
    }

    @Test
    public void test09ScepGetCrl() throws Exception {
        
        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
        publishingCrlSession.forceCRL(admin, x509ca.getCAId());
        byte[] msgBytes = genScepRequest(true, CMSSignedGenerator.DIGEST_SHA1, userDN1);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, true, CMSSignedGenerator.DIGEST_SHA1, false);
        
    }

    @Test
    public void test10ScepGetCACaps() throws Exception {
        log.debug(">test09ScepGetCACaps()");
        String reqUrl = httpReqPath + '/' + resourceScep + "?operation=GetCACaps&message=" + URLEncoder.encode(x509ca.getName(), "UTF-8");
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with "text/plain; charset=UTF-8"
        assertTrue(con.getContentType().startsWith("text/plain"));
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
        assertEquals(new String(respBytes), "POSTPKIOperation\nSHA-1");
        log.debug(">test09ScepGetCACaps()");
    }

    @Test
    public void test11EnforcementOfUniquePublicKeys() throws Exception {
        log.debug(">test10EnforcementOfUniquePublicKeys()");
        
        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
        
        // create new user for new DN.
        createScepUser(userName2, userDN2);

        final byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA1, userDN2);
        // Send message with GET
        final byte[] retMsg = sendScep(true, msgBytes, HttpServletResponse.SC_BAD_REQUEST);
    
        String returnMessageString = new String(retMsg);      
        String localizedMessage = InternalResourcesStub.getInstance().getLocalizedMessage("createcert.key_exists_for_another_user", userName2);
        if("createcert.key_exists_for_another_user".equals(localizedMessage)) {
            String currentDirectory = System.getProperty("user.dir");
            throw new Error("Test can't continue, can't find language resource files. Current directory is " + currentDirectory);
        }
        assertTrue(returnMessageString.indexOf(localizedMessage) >= 0);
        
        log.debug("<test10EnforcementOfUniquePublicKeys()");
    }

    @Test
    public void test12EnforcementOfUniqueDN() throws Exception {
        
        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration, Configuration.ScepConfigID);
        
        createScepUser(userName2, userDN2);
        // new user will have a DN of a certificate already issued for another
        // user.
        changeScepUser(userName2, userDN1);

        final byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA1, userDN2, key2);
        // Send message with GET
        final byte[] retMsg = sendScep(true, msgBytes, HttpServletResponse.SC_BAD_REQUEST);
        String returnMessageString = new String(retMsg);      
        String localizedMessage = InternalResourcesStub.getInstance().getLocalizedMessage(
                "createcert.subjectdn_exists_for_another_user", userName2, "'" + userName1 + "'");
        
        if("createcert.subjectdn_exists_for_another_user".equals(localizedMessage)) {
            String currentDirectory = System.getProperty("user.dir");
            throw new Error("Test can't continue, can't find language resource files. Current directory is " + currentDirectory);
        }
        assertTrue(returnMessageString.indexOf(localizedMessage) >= 0);
    }

    
    //
    // Private helper methods
    //
    /**
     * Sends a SCEP request with the alias requestAlias in the URL and expects a SCEP error message 
     * that can inform us about the alias extracted from the URL.
     */
    private void sendScepAliasRequest(ScepConfiguration scepConfig, String requestAlias, String extractedAlias, String expectedErrMsg) throws Exception {
        
        if(extractedAlias != null) {
            if(scepConfig.aliasExists(extractedAlias)) {
                scepConfig.renameAlias(extractedAlias, "backUpAlias" + extractedAlias + "ForAliasTesting001122334455");
                globalConfigSession.saveConfiguration(admin, scepConfig, Configuration.ScepConfigID);
            }
        }
        
        try {
            String resource = "publicweb/apply/scep/" + (requestAlias != null ? requestAlias + "/" : "") + "pkiclient.exe";
            String urlString = httpReqPath + '/' + resource + "?operation=PKIOperation";
            log.info("http URL: " + urlString);
            
            String reqUrl = urlString + "&message=" + URLEncoder.encode("Test Scep message", "UTF-8");
            URL url = new URL(reqUrl);
            final HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Unexpected HTTP response code.", HttpServletResponse.SC_BAD_REQUEST, con.getResponseCode()); // OK response (will use alias "alias123")
            
            InputStream err = con.getErrorStream();
            byte[] errB = new byte[1024];
            err.read(errB);
            err.close();
            String response = new String(errB);
            assertTrue("Response does not contain the correct error message", StringUtils.contains(response, expectedErrMsg));
        } finally {
            if(extractedAlias != null) {
                if(scepConfig.aliasExists("backUpAlias" + extractedAlias + "ForAliasTesting001122334455")) {
                    scepConfig.renameAlias("backUpAlias" + extractedAlias + "ForAliasTesting001122334455", extractedAlias);
                    globalConfigSession.saveConfiguration(admin, scepConfig, Configuration.ScepConfigID);
                }
            }
        }
    }
    
    private EndEntityInformation getEndEntityInformation(String userName, String userDN) {
        final EndEntityInformation data = new EndEntityInformation(userName, userDN, x509ca.getCAId(), null, "sceptest@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        data.setPassword("foo123");
        data.setStatus(EndEntityConstants.STATUS_NEW);
        return data;
    }

    private void createScepUser(String userName, String userDN) throws EndEntityExistsException, CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException {
        if(!endEntityManagementSession.existsUser(userName)) {
            endEntityManagementSession.addUser(admin, getEndEntityInformation(userName, userDN), false);
        } else {
            changeScepUser(userName, userDN);
        }
    }

    private void changeScepUser(String userName, String userDN) throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException  {
        endEntityManagementSession.changeUser(admin, getEndEntityInformation(userName, userDN), false);
        log.debug("changing user: " + userName + ", foo123, " + userDN);
    }

    private byte[] genScepRequest(boolean makeCrlReq, String digestoid, String userDN) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, InvalidAlgorithmParameterException, CertStoreException, IOException, CMSException,
            IllegalStateException, OperatorCreationException, CertificateException {
        return genScepRequest(makeCrlReq, digestoid, userDN, key1);
    }

    private byte[] genScepRequest(boolean makeCrlReq, String digestoid, String userDN, KeyPair key) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidAlgorithmParameterException, CertStoreException,
            IOException, CMSException, IllegalStateException, OperatorCreationException, CertificateException {
        ScepRequestGenerator gen = new ScepRequestGenerator();
        gen.setKeys(key);
        gen.setDigestOid(digestoid);
        byte[] msgBytes = null;
        // Create a transactionId
        byte[] randBytes = new byte[16];
        this.rand.nextBytes(randBytes);
        byte[] digest = CertTools.generateMD5Fingerprint(randBytes);
        transId = new String(Base64.encode(digest));

        if (makeCrlReq) {
            msgBytes = gen.generateCrlReq(userDN, transId, cacert);
        } else {
            msgBytes = gen.generateCertReq(userDN, "foo123", transId, cacert);
        }
        assertNotNull(msgBytes);
        senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertTrue(nonceBytes.length == 16);
        return msgBytes;
    }

    private void checkScepResponse(byte[] retMsg, String userDN, String _senderNonce, String _transId, boolean crlRep, String digestOid, boolean noca)
            throws CMSException, NoSuchProviderException, NoSuchAlgorithmException, CertStoreException, InvalidKeyException, CertificateException,
            SignatureException, CRLException {
        //
        // Parse response message
        //
        CMSSignedData s = new CMSSignedData(retMsg);
        // The signer, i.e. the CA, check it's the right CA
        SignerInformationStore signers = s.getSignerInfos();
        @SuppressWarnings("unchecked")
        Collection<SignerInformation> col = signers.getSigners();
        assertTrue(col.size() > 0);
        Iterator<SignerInformation> iter = col.iterator();
        SignerInformation signerInfo = iter.next();
        // Check that the message is signed with the correct digest alg
        assertEquals(signerInfo.getDigestAlgOID(), digestOid);
        SignerId sinfo = signerInfo.getSID();
        // Check that the signer is the expected CA
        assertEquals(CertTools.stringToBCDNString(cacert.getIssuerDN().getName()), CertTools.stringToBCDNString(sinfo.getIssuer().toString()));
        // Verify the signature
        boolean ret = signerInfo.verify(cacert.getPublicKey(), "BC");
        assertTrue(ret);
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
        ASN1String str = DERPrintableString.getInstance((values.getObjectAt(0)));
        String messageType = str.getString();
        assertEquals("3", messageType);
        // --Success status
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = DERPrintableString.getInstance((values.getObjectAt(0)));
        assertEquals(ResponseStatus.SUCCESS.getStringValue(), str.getString());
        // --SenderNonce
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_senderNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        ASN1OctetString octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // SenderNonce is something the server came up with, but it should be 16
        // chars
        assertTrue(octstr.getOctets().length == 16);
        // --Recipient Nonce
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_recipientNonce));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
        // recipient nonce should be the same as we sent away as sender nonce
        assertEquals(_senderNonce, new String(Base64.encode(octstr.getOctets())));
        // --Transaction ID
        attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_transId));
        assertNotNull(attr);
        values = attr.getAttrValues();
        assertEquals(values.size(), 1);
        str = DERPrintableString.getInstance((values.getObjectAt(0)));
        // transid should be the same as the one we sent
        assertEquals(_transId, str.getString());

        //
        // Check different message types
        //
        if (messageType.equals("3")) {
            // First we extract the encrypted data from the CMS enveloped data
            // contained
            // within the CMS signed data
            final CMSProcessable sp = s.getSignedContent();
            final byte[] content = (byte[]) sp.getContent();
            final CMSEnvelopedData ed = new CMSEnvelopedData(content);
            final RecipientInformationStore recipients = ed.getRecipientInfos();
            CertStore certstore;
            {
                @SuppressWarnings("unchecked")
                Collection<RecipientInformation> c = recipients.getRecipients();
                assertEquals(c.size(), 1);
                Iterator<RecipientInformation> it = c.iterator();
                byte[] decBytes = null;
                RecipientInformation recipient = it.next();
                decBytes = recipient.getContent(key1.getPrivate(), "BC");
                // This is yet another CMS signed data
                CMSSignedData sd = new CMSSignedData(decBytes);
                // Get certificates from the signed data
                certstore = sd.getCertificatesAndCRLs("Collection", "BC");
            }
            if (crlRep) {
                // We got a reply with a requested CRL
                @SuppressWarnings("unchecked")
                final Collection<X509CRL> crls = (Collection<X509CRL>) certstore.getCRLs(null);
                assertEquals(crls.size(), 1);
                final Iterator<X509CRL> it = crls.iterator();
                // CRL is first (and only)
                final X509CRL retCrl = it.next();
                log.info("Got CRL with DN: " + retCrl.getIssuerDN().getName());

                // check the returned CRL
                assertEquals(cacert.getSubjectDN().getName(), retCrl.getIssuerDN().getName());
                retCrl.verify(cacert.getPublicKey());
            } else {
                // We got a reply with a requested certificate
                @SuppressWarnings("unchecked")
                final Collection<X509Certificate> certs = (Collection<X509Certificate>) certstore.getCertificates(null);
                // EJBCA returns the issued cert and the CA cert (cisco vpn
                // client requires that the ca cert is included)
                if (noca) {
                    assertEquals(certs.size(), 1);
                } else {
                    assertEquals(certs.size(), 2);
                }
                final Iterator<X509Certificate> it = certs.iterator();
                // Issued certificate must be first
                boolean verified = false;
                boolean gotcacert = false;
                while (it.hasNext()) {
                    X509Certificate retcert = it.next();
                    log.info("Got cert with DN: " + retcert.getSubjectDN().getName());

                    // check the returned certificate
                    String subjectdn = CertTools.stringToBCDNString(retcert.getSubjectDN().getName());
                    if (CertTools.stringToBCDNString(userDN).equals(subjectdn)) {
                        // issued certificate
                        assertEquals(CertTools.stringToBCDNString(userDN), subjectdn);
                        assertEquals(cacert.getSubjectDN().getName(), retcert.getIssuerDN().getName());
                        retcert.verify(cacert.getPublicKey());
                        assertTrue(checkKeys(key1.getPrivate(), retcert.getPublicKey()));
                        verified = true;
                    } else {
                        // ca certificate
                        assertEquals(cacert.getSubjectDN().getName(), retcert.getSubjectDN().getName());
                        gotcacert = true;
                    }
                }
                assertTrue(verified);
                if (noca) {
                    assertFalse(gotcacert);
                } else {
                    assertTrue(gotcacert);
                }
            }
        }

    }

    /**
     * checks that a public and private key matches by signing and verifying a message
     */
    private boolean checkKeys(PrivateKey priv, PublicKey pub) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        Signature signer = Signature.getInstance("SHA1WithRSA");
        signer.initSign(priv);
        signer.update("PrimeKey".getBytes());
        byte[] signature = signer.sign();

        Signature signer2 = Signature.getInstance("SHA1WithRSA");
        signer2.initVerify(pub);
        signer2.update("PrimeKey".getBytes());
        return signer2.verify(signature);
    }

    private byte[] sendScep(boolean post, byte[] scepPackage) throws IOException {
        return sendScep(post, scepPackage, HttpServletResponse.SC_OK);
    }

    private byte[] sendScep(boolean post, byte[] scepPackage, int responseCode) throws IOException {
        // POST the SCEP request
        // we are going to do a POST
        String urlString = httpReqPath + '/' + resourceScep + "?operation=PKIOperation";
        log.debug("UrlString =" + urlString);
        final HttpURLConnection con;
        if (post) {
            URL url = new URL(urlString);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.connect();
            // POST it
            OutputStream os = con.getOutputStream();
            os.write(scepPackage);
            os.close();
        } else {
            String reqUrl = urlString + "&message=" + URLEncoder.encode(new String(Base64.encode(scepPackage)), "UTF-8");
            URL url = new URL(reqUrl);
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
        }

        assertEquals("Response code", responseCode, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/x-pki-message; charset=UTF-8"
        if (responseCode == HttpServletResponse.SC_OK) {
            assertTrue(con.getContentType().startsWith("application/x-pki-message"));
        } else {
            assertTrue(con.getContentType().startsWith("text/html"));
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        final InputStream in;
        if (responseCode == HttpServletResponse.SC_OK) {
            in = con.getInputStream();
        } else {
            in = con.getErrorStream();
        }
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
        return respBytes;
    }

    private void updatePropertyOnServer(String property, String value) {
        final String msg = "Setting property on server: " + property + "=" + value;
        log.debug(msg);
        boolean ret = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST).updateProperty(property, value);
        if (!ret) {
            throw new IllegalStateException("Failed operation: "+msg);
        }
    }

    static class InternalResourcesStub extends InternalEjbcaResources {

        private static final long serialVersionUID = 1L;
        private static final Logger log = Logger.getLogger(InternalResourcesStub.class);

        private InternalResourcesStub() {

            setupResources();

        }

        private void setupResources() {
            String primaryLanguage = PREFEREDINTERNALRESOURCES.toLowerCase();
            String secondaryLanguage = SECONDARYINTERNALRESOURCES.toLowerCase();

            InputStream primaryStream = null;
            InputStream secondaryStream = null;

            primaryLanguage = "en";
            secondaryLanguage = "se";
            try {
                primaryStream = new FileInputStream("src/intresources/intresources." + primaryLanguage + ".properties");
                secondaryStream = new FileInputStream("src/intresources/intresources." + secondaryLanguage + ".properties");

                try {
                    primaryEjbcaResource.load(primaryStream);
                    secondaryEjbcaResource.load(secondaryStream);
                } catch (IOException e) {
                    log.error("Error reading internal resourcefile", e);
                }

            } catch (FileNotFoundException e) {
                log.error("Localization files not found", e);

            } finally {
                try {
                    if (primaryStream != null) {
                        primaryStream.close();
                    }
                    if (secondaryStream != null) {
                        secondaryStream.close();
                    }
                } catch (IOException e) {
                    log.error("Error closing internal resources language streams: ", e);
                }
            }

        }

        public static synchronized InternalEjbcaResources getInstance() {
            if (instance == null) {
                instance = new InternalResourcesStub();
            }
            return instance;
        }

    }
}
