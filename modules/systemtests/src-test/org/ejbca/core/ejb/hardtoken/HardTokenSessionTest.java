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

package org.ejbca.core.ejb.hardtoken;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.Configuration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Tests the hard token related entity beans.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HardTokenSessionTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(HardTokenSessionTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("HardTokenTest"));

    private static int orgEncryptCAId;

    static byte[] testcert = Base64.decode(("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw" + "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB" + "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
            + "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe" + "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
            + "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM" + "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
            + "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS" + "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
            + "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+" + "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());

    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private HardTokenSessionRemote hardTokenSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);


    @BeforeClass
    public static void beforeClass() {       
        CryptoProviderTools.installBCProvider();
        
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();

    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Test
    public void test01AddHardToken() throws Exception {
        log.trace(">test01AddHardToken()");

        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID);
        orgEncryptCAId = gc.getHardTokenEncryptCA();
        gc.setHardTokenEncryptCA(0);
        globalConfigurationSession.saveConfiguration(internalAdmin, gc, Configuration.GlobalConfigID);

        SwedishEIDHardToken token = new SwedishEIDHardToken("1234", "1234", "123456", "123456", 1);

        ArrayList<Certificate> certs = new ArrayList<Certificate>();

        certs.add(CertTools.getCertfromByteArray(testcert));

        hardTokenSessionRemote.addHardToken(internalAdmin, "1234", "TESTUSER", "CN=TEST", SecConst.TOKEN_SWEDISHEID, token, certs, null);

        TurkishEIDHardToken token2 = new TurkishEIDHardToken("1234", "123456", 1);

        hardTokenSessionRemote.addHardToken(internalAdmin, "2345", "TESTUSER", "CN=TEST", SecConst.TOKEN_TURKISHEID, token2, certs, null);

        log.trace("<test01AddHardToken()");
    }

    @Test
    public void test02EditHardToken() throws Exception {
        log.trace(">test02EditHardToken()");

        boolean ret = false;

        HardTokenInformation token = hardTokenSessionRemote.getHardToken(internalAdmin, "1234", true);

        SwedishEIDHardToken swe = (SwedishEIDHardToken) token.getHardToken();

        assertTrue("Retrieving HardToken failed", swe.getInitialAuthEncPIN().equals("1234"));

        swe.setInitialAuthEncPIN("5678");

        hardTokenSessionRemote.changeHardToken(internalAdmin, "1234", SecConst.TOKEN_SWEDISHEID, token.getHardToken());
        ret = true;

        assertTrue("Editing HardToken failed", ret);
        log.trace("<test02EditHardToken()");
    }

    @Test
    public void test03FindHardTokenByCertificate() throws Exception {
        log.trace(">test03FindHardTokenByCertificate()");

        Certificate cert = CertTools.getCertfromByteArray(testcert);
        // Store the dummy cert for test.
        if (certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) == null) {
            certificateStoreSession.storeCertificate(internalAdmin, cert, "DUMMYUSER",
                    CertTools.getFingerprintAsString(cert), CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    null, new Date().getTime());
        }
        String tokensn = hardTokenSessionRemote.findHardTokenByCertificateSNIssuerDN(CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert));

        assertTrue("Couldn't find right hardtokensn", tokensn.equals("1234"));

        log.trace("<test03FindHardTokenByCertificate()");
    }

    @Test
    public void test04EncryptHardToken() throws Exception {
        log.trace(">test04EncryptHardToken()");

        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID);
        gc.setHardTokenEncryptCA(getTestCAId());
        globalConfigurationSession.saveConfiguration(internalAdmin, gc, Configuration.GlobalConfigID);
        boolean ret = false;

        // Make sure the old data can be read
        HardTokenInformation token = hardTokenSessionRemote.getHardToken(internalAdmin, "1234", true);

        SwedishEIDHardToken swe = (SwedishEIDHardToken) token.getHardToken();

        assertTrue("Retrieving HardToken failed : " + swe.getInitialAuthEncPIN(), swe.getInitialAuthEncPIN().equals("5678"));

        swe.setInitialAuthEncPIN("5678");

        // Store the new data as encrypted
        hardTokenSessionRemote.changeHardToken(internalAdmin, "1234", SecConst.TOKEN_SWEDISHEID, token.getHardToken());
        ret = true;

        assertTrue("Saving encrypted HardToken failed", ret);

        // Make sure the encrypted data can be read
        token = hardTokenSessionRemote.getHardToken(internalAdmin, "1234", true);

        swe = (SwedishEIDHardToken) token.getHardToken();

        assertTrue("Retrieving encrypted HardToken failed", swe.getInitialAuthEncPIN().equals("5678"));

        log.trace("<test04EncryptHardToken()");
    }

    @Test
    public void test05removeHardTokens() throws AuthorizationDeniedException {
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID);
        gc.setHardTokenEncryptCA(orgEncryptCAId);
        globalConfigurationSession.saveConfiguration(internalAdmin, gc, Configuration.GlobalConfigID);
    
        try {
            hardTokenSessionRemote.removeHardToken(internalAdmin, "1234");
            hardTokenSessionRemote.removeHardToken(internalAdmin, "2345");
        } catch (HardTokenDoesntExistsException e) {
            e.printStackTrace();        
        }
        
        assertFalse("Removing hard token with tokensn 1234 failed.", hardTokenSessionRemote.existsHardToken("1234"));
        assertFalse("Removing hard token with tokensn 2345 failed.", hardTokenSessionRemote.existsHardToken("2345"));
    }
    
    @Test
    public void testSQLInjection() throws Exception {
    /* Vulnerability type : SQL Injection
    First, hardtokenissuer table in the database should not be empty in order to exploit the vulnerability
    The PoC is : We inject a test that will always return the records in the table.*/
        try {
            SwedishEIDHardToken token = new SwedishEIDHardToken("1234", "1234", "123456", "123456", 1);
            ArrayList<Certificate> certs = new ArrayList<Certificate>();
            certs.add(CertTools.getCertfromByteArray(testcert));
            hardTokenSessionRemote.addHardToken(internalAdmin, "12344321", "TESTUSERSQL", "CN=TESTSQL", SecConst.TOKEN_SWEDISHEID, token, certs, null);
            // One search that must return result
            Collection<String> tokens = hardTokenSessionRemote.matchHardTokenByTokenSerialNumber("12344321");
            assertEquals("Search query should have returned one result, the database does not contain any records like 12344321.", 1, tokens.size());
            // Another search that should return the same
            tokens = hardTokenSessionRemote.matchHardTokenByTokenSerialNumber("12344"); // Like query should work on partial serno
            assertEquals("Search query should have returned one result, the database does not contain any records like 12344.", 1, tokens.size());
            // One search that should not return anything
            tokens = hardTokenSessionRemote.matchHardTokenByTokenSerialNumber("SQL12345678");
            assertEquals("Search query should have returned no results, the database contains a hard token with serno like SQL12345678.", 0, tokens.size());
            // Now try the SQL injection, should return nothing
            tokens = hardTokenSessionRemote.matchHardTokenByTokenSerialNumber("x' or (1=1) or tokenSN LIKE 'x");
            assertEquals("Search query should have returned no results, vulnerable to sql injection?", 0, tokens.size());
        } finally {
            try {
                hardTokenSessionRemote.removeHardToken(internalAdmin, "12344321");
            } catch (HardTokenDoesntExistsException e) {} // NOPMD            
        }

    }
    

}
