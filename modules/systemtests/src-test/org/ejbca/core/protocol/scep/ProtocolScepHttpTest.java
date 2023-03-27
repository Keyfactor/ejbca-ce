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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.util.Streams;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.WebTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.CryptoTokenRunner;
import org.cesecore.junit.util.PKCS12TestRunner;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Tests http pages of scep
 * 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)
public class ProtocolScepHttpTest extends ScepTestBase {

    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
       return Arrays.asList(new PKCS12TestRunner());
    }
    
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
    private static KeyPair key1;
    private static KeyPair key2;

    private static final String userName1 = "sceptest1";
    private static final String userName2 = "sceptest2";
    private static final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
    private static final String userDN2 = "C=SE,O=PrimeKey,CN=" + userName2;

    private String senderNonce = null;
    private String transId = null;

    private Random rand = new Random();
    private ScepConfiguration scepConfiguration;
    private X509CAInfo x509ca;
    private X509Certificate cacert;


    private final ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EndEntityAccessSessionRemote endEntityAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
   
    
    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @Rule
    public TestName testName = new TestName();

    private CryptoTokenRunner cryptoTokenRunner;

    public ProtocolScepHttpTest(CryptoTokenRunner cryptoTokenRunner) throws Exception {
        super();
        this.cryptoTokenRunner = cryptoTokenRunner;
       
    }

    @Before
    public void setUp() throws Exception {
        assumeTrue("Test with runner " + cryptoTokenRunner.getSimpleName() + " cannot run on this platform.", cryptoTokenRunner.canRun());
        // Pre-generate key for all requests to speed things up a bit
        try {
            key1 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            key2 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        
        x509ca = cryptoTokenRunner.createX509Ca("CN="+testName.getMethodName(), testName.getMethodName()); 
        cacert = (X509Certificate) x509ca.getCertificateChain().get(0);
                     
        scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        scepConfiguration.addAlias(scepAlias);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);

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
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        cryptoTokenRunner.cleanUp();
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    @Override
    protected String getResourceScep() {
        return resourceScep;
    }

    @Test
    public void test01Access() throws Exception {        
        // Gives a 400: Bad Request
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + '/' + resourceScep);
        assertEquals("Response code", 400, resp.getStatusLine().getStatusCode());
    }

    @Test
    public void test02AccessTest() throws Exception {
        
        ScepConfiguration scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        boolean remove = false;
        if(!scepConfig.aliasExists("scep")) {
            scepConfig.addAlias("scep");
            globalConfigSession.saveConfiguration(admin, scepConfig);
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
            globalConfigSession.saveConfiguration(admin, scepConfig);
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
        
        ScepConfiguration scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        
        sendScepAliasRequest(scepConfig, "alias123", "alias123", "SCEP alias 'alias123' does not exist"); // "alias123" in the request causes Ejbca to use "alias123" as SCEP alias
        sendScepAliasRequest(scepConfig, "123", "123", "SCEP alias '123' does not exist"); // "123" in the request causes Ejbca to use "123" as SCEP alias
        sendScepAliasRequest(scepConfig, "", "scep", "SCEP alias 'scep' does not exist"); // No alias in the request causes Ejbca to use "scep" (the default alias) as SCEP alias
        sendScepAliasRequest(scepConfig, null, "scep", "SCEP alias 'scep' does not exist"); // No alias in the request causes Ejbca to use "scep" (the default alias) as SCEP alias
        sendScepAliasRequest(scepConfig, "alias??&!!foo", null, "Wrong URL. No alias found"); // Specifying alias with non-alphanumeric characters causes the request to fail. 
    }
    

    /**
     * Tests a random old scep message from OpenScep
     * 
     * @throws Exception error
     */
    @Test
    public void test03OpenScep() throws Exception {
        // send message to server and see what happens
        String encodedMessage = URLEncoder.encode(new String(Base64.encode(openscep), "UTF-8"), "UTF-8");
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + '/' + resourceScep + "?operation=PKIOperation&message=" + encodedMessage);
        // TODO: since our request most certainly uses the wrong CA cert to
        // encrypt the
        // request, it will fail. If we get something back, we came a little bit
        // at least :)
        // We should get a NOT_FOUND error back.
        assertEquals("Response code", 404, resp.getStatusLine().getStatusCode());
    }

    @Test
    public void test04ScepRequestOKSHA1() throws Exception {
        // find a CA create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, true);
        scepConfiguration.setAllowLegacyDigestAlgorithm(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        // Make user that we know...
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA1, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, false, SMIMECapability.dES_CBC, key1);
    }
    
    @Test
    public void test04ScepRequestSHA1NoLegacyDigestAlgAllowed() throws Exception {
        // find a CA create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        // Make user that we know...
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA1, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        //With legacy digest algorithm not allowed, response should default to SHA256
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA256, false, SMIMECapability.dES_CBC, key1);
    }

    @Test
    public void test04ScepRequestOKSHA256() throws Exception {
        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);        
        // Make user that we know...
        createScepUser(userName1, userDN1);
        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA256, false, SMIMECapability.dES_CBC, key1);
    }

    @Test
    public void test04ScepRequestOKSHA256DES3() throws Exception {
        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);        
        // Make user that we know...
        createScepUser(userName1, userDN1);
        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, userDN1, SMIMECapability.dES_EDE3_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        // When the request is encrypted with 3DES, the response should be as well.
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA256, false, SMIMECapability.dES_EDE3_CBC, key1);
    }

    @Test
    public void test04ScepRequestOKSHA512() throws Exception {
        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);        
        // Make user that we know...
        createScepUser(userName1, userDN1);
        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA512, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA512, false, SMIMECapability.dES_CBC, key1);
    }

    @Test
    public void test05ScepRequestOKMD5() throws Exception {
        // find a CA create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, true);
        scepConfiguration.setAllowLegacyDigestAlgorithm(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        // Make user that we know...
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_MD5, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_MD5, false, SMIMECapability.dES_CBC, key1);
        
    }

    @Test
    public void test06ScepRequestPostOK() throws Exception {
        // find a CA, create a user and send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, userDN1, SMIMECapability.dES_CBC);
        // Send message with POST
        byte[] retMsg = sendScep(true, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA256, false, SMIMECapability.dES_CBC, key1);
        
        // Send a message that is larger than LimitLengthASN1Reader.MAX_REQUEST_SIZE with POST
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // add the real message first, so it will parse OK if the message would be received and give a SC_OK unless there is a limit in place
        baos.write(msgBytes);
        baos.write(new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE + 1]);
        sendScep(true, baos.toByteArray(), HttpServletResponse.SC_BAD_REQUEST);
        
    }

    @Test
    public void test07ScepRequestPostOKNoCA() throws Exception {
        // find a CA, create a user and
        // send SCEP req to server and get good response with cert

        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        createScepUser(userName1, userDN1);

        byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(true, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA256, true, SMIMECapability.dES_CBC, key1);
        
    }

    @Test
    public void test08ScepGetCACert() throws Exception {
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
            X509Certificate cert = CertTools.getCertfromByteArray(respBytes, X509Certificate.class);
            // Check that we got the right cert back
            assertEquals(cacert.getSubjectDN().getName(), cert.getSubjectDN().getName());
        }

        // 
        // Test the same message but without message component, it should use a default CA, if one is set
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
            X509Certificate cert = CertTools.getCertfromByteArray(respBytes, X509Certificate.class);
            // Check that we got the right cert back
            assertEquals(cacert.getSubjectDN().getName(), cert.getSubjectDN().getName());

            // Try with no default CA last, should respond with a 404
            updatePropertyOnServer("scep.defaultca", "");
            reqUrl = httpReqPath + '/' + resourceScep + "?operation=GetCACert";
            url = new URL(reqUrl);
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Response code is not 404 (not found)", 404, con.getResponseCode());
            
            // Now set the CA as default CA in the alias instead, it should pick up that, if we are in RA mode
            scepConfiguration.setRADefaultCA(scepAlias, x509ca.getName());
            scepConfiguration.setRAMode(scepAlias, false);
            globalConfigSession.saveConfiguration(admin, scepConfiguration);
            assertFalse("We should be in CA mode in this part of the test", scepConfiguration.getRAMode(scepAlias));
            url = new URL(reqUrl);
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Response code is not 404 (not found)", 404, con.getResponseCode());
            scepConfiguration.setRAMode(scepAlias, true);
            globalConfigSession.saveConfiguration(admin, scepConfiguration);
            assertTrue("We should be in RA mode now", scepConfiguration.getRAMode(scepAlias));
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Response code is not 200 (OK)", 200, con.getResponseCode());
            assertTrue(con.getContentType().startsWith("application/x-x509-ca-cert"));
            baos = new ByteArrayOutputStream();
            // This works for small requests, and SCEP requests are small enough
            in = con.getInputStream();
            b = in.read();
            while (b != -1) {
                baos.write(b);
                b = in.read();
            }
            baos.flush();
            in.close();
            respBytes = baos.toByteArray();
            assertNotNull("Response can not be null.", respBytes);
            assertTrue(respBytes.length > 0);
            cert = CertTools.getCertfromByteArray(respBytes, X509Certificate.class);
            // Check that we got the right cert back
            assertEquals(cacert.getSubjectDN().getName(), cert.getSubjectDN().getName());

        }
        
        //
        // Also test getCACertChain
        {
            String reqUrl = httpReqPath + '/' + resourceScep + "?operation=GetCACertChain&message=" + URLEncoder.encode(x509ca.getName(), "UTF-8");
            URL url = new URL(reqUrl);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.getDoOutput();
            con.connect();
            assertEquals("Response code is not 200 (OK)", 200, con.getResponseCode());
            // Some appserver (Weblogic) responds with
            // "application/x-x509-ca-cert; charset=UTF-8"
            assertTrue(con.getContentType().startsWith("application/x-x509-ca-ra-cert-chain"));
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
            // This is a PKCS#7, ignore trying to parse if for now. EJBCAINTER-120 suggests removing it
        }
        
    }

    @Test
    public void test09ScepGetCrlSHA1() throws Exception {
        scepConfiguration.setIncludeCA(scepAlias, false);
        scepConfiguration.setAllowLegacyDigestAlgorithm(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        publishingCrlSession.forceCRL(admin, x509ca.getCAId());
        byte[] msgBytes = genScepRequest(true, CMSSignedGenerator.DIGEST_SHA1, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, true, CMSSignedGenerator.DIGEST_SHA1, false, SMIMECapability.dES_CBC, key1);
    }
    
    @Test
    public void test09ScepGetCrlSHA1NoLegacyDigestAlgorithmAllowed() throws Exception {
        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        publishingCrlSession.forceCRL(admin, x509ca.getCAId());
        byte[] msgBytes = genScepRequest(true, CMSSignedGenerator.DIGEST_SHA1, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        //With legacy digest algorithm not allowed, response should default to SHA256
        checkScepResponse(retMsg, userDN1, senderNonce, transId, true, CMSSignedGenerator.DIGEST_SHA256, false, SMIMECapability.dES_CBC, key1);
    }

    @Test
    public void test09ScepGetCrlSHA256() throws Exception {
        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        publishingCrlSession.forceCRL(admin, x509ca.getCAId());
        byte[] msgBytes = genScepRequest(true, CMSSignedGenerator.DIGEST_SHA256, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, userDN1, senderNonce, transId, true, CMSSignedGenerator.DIGEST_SHA256, false, SMIMECapability.dES_CBC, key1);
    }

    @Test
    public void test10ScepGetCACaps() throws Exception {
        checkCACaps(x509ca.getName(), "POSTPKIOperation\nRenewal\nSHA-512\nSHA-256\nSHA-1\nDES3");
        sendGetCACapsRequest("NonExistent", 404);
    }

    @Test
    public void test11EnforcementOfUniquePublicKeys() throws Exception {        
        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        //Create the initial user
        createScepUser(userName1, userDN1);
        final byte[] msgBytesUser1 = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, userDN1, SMIMECapability.dES_CBC);
        // Send message with GET
        sendScep(true, msgBytesUser1, HttpServletResponse.SC_OK);
        
        // create new which is going to reuse the same key. 
        createScepUser(userName2, userDN2);
        
        final byte[] msgBytesUser2 = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, userDN2, SMIMECapability.dES_CBC);
        // Send message with GET
        final byte[] retMsgUser2 = sendScep(true, msgBytesUser2, HttpServletResponse.SC_BAD_REQUEST);

        String returnMessageString = new String(retMsgUser2);      
        String localizedMessage = InternalResourcesStub.getInstance().getLocalizedMessage("createcert.key_exists_for_another_user", userName2);
        if("createcert.key_exists_for_another_user".equals(localizedMessage)) {
            String currentDirectory = System.getProperty("user.dir");
            throw new IllegalStateException("Test can't continue, can't find language resource files. Current directory is " + currentDirectory);
        }
        assertTrue(returnMessageString+": should contain: "+localizedMessage, returnMessageString.indexOf(localizedMessage) >= 0);
     }

    @Test
    public void testEnforcementOfUniqueDN() throws Exception {
        
        scepConfiguration.setIncludeCA(scepAlias, false);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        final String first = "testEnforcementOfUniqueDN_user1";
        final String second = "testEnforcementOfUniqueDN_user2";
        final String firstUserDn = "CN="+first;
        final String secondUserDn = "CN="+second;
        
        try {
            createScepUser(first, firstUserDn);
            final byte[] firstMessage = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, firstUserDn, key1, BouncyCastleProvider.PROVIDER_NAME,
                    SMIMECapability.dES_CBC);
            sendScep(true, firstMessage, HttpServletResponse.SC_OK);
            createScepUser(second, secondUserDn);
            changeScepUser(second, firstUserDn, x509ca.getCAId());

            final byte[] secondMessage = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, secondUserDn, key2, BouncyCastleProvider.PROVIDER_NAME,
                    SMIMECapability.dES_CBC);
            // Send message with GET
            final byte[] retMsg = sendScep(true, secondMessage, HttpServletResponse.SC_BAD_REQUEST);
            String returnMessageString = new String(retMsg);
            String localizedMessage = InternalResourcesStub.getInstance().getLocalizedMessage("createcert.subjectdn_exists_for_another_user", second,
                    "'" + first + "'");

            if ("createcert.subjectdn_exists_for_another_user".equals(localizedMessage)) {
                String currentDirectory = System.getProperty("user.dir");
                throw new IllegalStateException("Test can't continue, can't find language resource files. Current directory is " + currentDirectory);
            }
            assertTrue(returnMessageString + ": should contain: " + localizedMessage, returnMessageString.indexOf(localizedMessage) >= 0);
        } finally {
            // remove user
            try {
                endEntityManagementSession.deleteUser(admin, first);
            } catch (Exception e) {
                // NOPMD: ignore
            }
            try {
                endEntityManagementSession.deleteUser(admin, second);
            } catch (Exception e) {
                // NOPMD: ignore
            }
            internalCertificateStoreSession.removeCertificatesBySubject(firstUserDn);
            internalCertificateStoreSession.removeCertificatesBySubject(secondUserDn);
        }
    }
    
   
    
    /**
     * Regression test as part of ECA-10620, where it was found that enrolling a key over SCEP to the wrong CA led to that EE changing status.
     */
    @Test
    public void testInvalidRequestDoesNotChangeStatus() throws Exception {
        final String username = "testInvalidRequestDoesNotChangeStatus";
        final String subjectDn = "CN=" + username;
        scepConfiguration.setIncludeCA(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        final String differentCaName = "testInvalidRequestDoesNotChangeStatus_ca";
        final String differentCaSubjectDn = "CN=" + differentCaName;

        X509CAInfo differentCa = cryptoTokenRunner.createX509Ca(differentCaSubjectDn, differentCaName);

        // Create a user from a different CA than the one called from genScepRequest below
        createScepUser(username, subjectDn, differentCa.getCAId());
        try {
            byte[] msgBytes = genScepRequest(false, CMSSignedGenerator.DIGEST_SHA256, subjectDn, SMIMECapability.dES_CBC);
            // Send message with GET, we're expecting a 400 back since the CA's were mismatched.
            byte[] retMsg = sendScep(false, msgBytes, HttpServletResponse.SC_BAD_REQUEST);
            assertNotNull("Response message was null", retMsg);
            // Verify that the end entity's status hasn't changed
            assertEquals("End Entity status changed in spite of request failing.", EndEntityConstants.STATUS_NEW,
                    endEntityAccessSessionRemote.findUser(admin, username).getStatus());
        } finally {
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            endEntityManagementSession.deleteUser(admin, username);
            //CA's are cleaned by the crypto token rule
        }
    }

    @Test
    public void testDashesAndUnderscoresInAlias() throws Exception {
        final String aliasName = "it-has_underscores_and-dashes";
        final String scepUrl = createScepUrl(aliasName);

        ScepConfiguration scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);

        if(!scepConfig.aliasExists(aliasName)) {
            scepConfig.addAlias(aliasName);
            globalConfigSession.saveConfiguration(admin, scepConfig);
        }

        HttpResponse response = WebTestUtils.sendGetRequest(scepUrl);
        assertEquals("Wrong response code is returned", 200, response.getStatusLine().getStatusCode());

        if(scepConfig.aliasExists(aliasName)) {
            scepConfig.removeAlias(aliasName);
            globalConfigSession.saveConfiguration(admin, scepConfig);
        }
    }

    private String createScepUrl(final String aliasName) {
        String resourceName = "/ejbca/publicweb/apply/scep/" + aliasName + "/pkiclient.exe?operation=GetCACert&message=" + x509ca.getName();

        String httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        String httpBaseUrl = "http://" + httpHost + ":" + httpPort;

        return httpBaseUrl + resourceName;
    }

    /**
     * Sends a SCEP request with the alias requestAlias in the URL and expects a SCEP error message 
     * that can inform us about the alias extracted from the URL.
     */
    private void sendScepAliasRequest(ScepConfiguration scepConfig, String requestAlias, String extractedAlias, String expectedErrMsg) throws Exception {
        
        if(extractedAlias != null) {
            if(scepConfig.aliasExists(extractedAlias)) {
                scepConfig.renameAlias(extractedAlias, "backUpAlias" + extractedAlias + "ForAliasTesting001122334455");
                globalConfigSession.saveConfiguration(admin, scepConfig);
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
                    globalConfigSession.saveConfiguration(admin, scepConfig);
                }
            }
        }
    }
    
    private void createScepUser(String userName, String userDN)
            throws EndEntityExistsException, CADoesntExistsException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, EjbcaException, IllegalNameException, CertificateSerialNumberException, NoSuchEndEntityException {
        createScepUser(userName, userDN, x509ca.getCAId());
    }
    

    private byte[] genScepRequest(boolean makeCrlReq, String digestoid, String userDN, ASN1ObjectIdentifier encryptionAlg) throws IOException, CMSException,
            IllegalStateException, OperatorCreationException, CertificateException {
        return genScepRequest(makeCrlReq, digestoid, userDN, key1, BouncyCastleProvider.PROVIDER_NAME, encryptionAlg);
    }

    private byte[] genScepRequest(boolean makeCrlReq, String digestoid, String userDN, KeyPair keyPair, String signatureProvider, ASN1ObjectIdentifier encryptionAlg) throws
            IOException, CMSException, OperatorCreationException, CertificateException {
        ScepRequestGenerator gen = new ScepRequestGenerator();
        gen.setKeys(keyPair, signatureProvider);
        gen.setDigestOid(digestoid);
        byte[] msgBytes = null;
        // Create a transactionId
        byte[] randBytes = new byte[16];
        this.rand.nextBytes(randBytes);
        byte[] digest = CertTools.generateMD5Fingerprint(randBytes);
        transId = new String(Base64.encode(digest));
        final X509Certificate senderCertificate = CertTools.genSelfCert("CN=SenderCertificate", 24 * 60 * 60 * 1000, null,
                keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false);
        if (makeCrlReq) {
            msgBytes = gen.generateCrlReq(userDN, transId, cacert, senderCertificate, keyPair.getPrivate(), encryptionAlg);
        } else {
            msgBytes = gen.generateCertReq(userDN, "foo123", transId, cacert, senderCertificate, keyPair.getPrivate(), encryptionAlg);
        }
        assertNotNull(msgBytes);
        senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertTrue(nonceBytes.length == 16);
        return msgBytes;
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

    @Override
    protected String getTransactionId() {
        return transId;
    }

    @Override
    protected X509Certificate getCaCertificate() {
        return cacert;
    }
    
   

}
