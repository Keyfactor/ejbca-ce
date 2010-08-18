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

package org.ejbca.core.ejb.hardtoken;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the hard token related entity beans.
 *
 * @version $Id$
 */
public class HardTokenTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(HardTokenTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    
    private static int orgEncryptCAId;

    static byte[] testcert = Base64.decode(("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw"
            + "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
            + "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
            + "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe"
            + "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
            + "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM"
            + "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
            + "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS"
            + "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
            + "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+"
            + "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());


    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private HardTokenSessionRemote hardTokenSessionRemote = InterfaceCache.getHardTokenSession();
    private RaAdminSessionRemote raAdminSession = InterfaceCache.getRAAdminSession();
    
    /**
     * Creates a new TestHardToken object.
     *
     * @param name name
     */
    public HardTokenTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
        assertTrue("Could not create TestCA.", createTestCA());
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * adds a token to the database
     *
     * @throws Exception error
     */

    public void test01AddHardToken() throws Exception {
        log.trace(">test01AddHardToken()");
      
        GlobalConfiguration gc = raAdminSession.getCachedGlobalConfiguration(admin);
        orgEncryptCAId = gc.getHardTokenEncryptCA();
        gc.setHardTokenEncryptCA(0);
        raAdminSession.saveGlobalConfiguration(admin, gc);
        

        SwedishEIDHardToken token = new SwedishEIDHardToken("1234", "1234", "123456", "123456", 1);

        ArrayList<Certificate> certs = new ArrayList<Certificate>();

        certs.add(CertTools.getCertfromByteArray(testcert));

        hardTokenSessionRemote.addHardToken(admin, "1234", "TESTUSER", "CN=TEST", SecConst.TOKEN_SWEDISHEID, token, certs, null);

        TurkishEIDHardToken token2 = new TurkishEIDHardToken("1234",  "123456", 1);

        hardTokenSessionRemote.addHardToken(admin, "2345", "TESTUSER", "CN=TEST", SecConst.TOKEN_TURKISHEID, token2, certs, null);

        log.trace("<test01AddHardToken()");
    }


    /**
     * edits token
     *
     * @throws Exception error
     */
    
    public void test02EditHardToken() throws Exception {
        log.trace(">test02EditHardToken()");

        boolean ret = false;

        HardTokenData token = hardTokenSessionRemote.getHardToken(admin, "1234", true);

        SwedishEIDHardToken swe = (SwedishEIDHardToken) token.getHardToken();

        assertTrue("Retrieving HardToken failed", swe.getInitialAuthEncPIN().equals("1234"));

        swe.setInitialAuthEncPIN("5678");

        hardTokenSessionRemote.changeHardToken(admin, "1234", SecConst.TOKEN_SWEDISHEID, token.getHardToken());
        ret = true;

        assertTrue("Editing HardToken failed", ret);
        log.trace("<test02EditHardToken()");
    }  

    /**
     * Test that tries to find a hardtokensn from is certificate
     *
     * @throws Exception error
     */
    
    public void test03FindHardTokenByCertificate() throws Exception {
        log.trace(">test03FindHardTokenByCertificate()");

        Certificate cert = CertTools.getCertfromByteArray(testcert);
        // Store the dummy cert for test.  
        if(certificateStoreSession.findCertificateByFingerprint(admin, CertTools.getFingerprintAsString(cert)) == null){
        	certificateStoreSession.storeCertificate(admin,cert,"DUMMYUSER", CertTools.getFingerprintAsString(cert),SecConst.CERT_ACTIVE,SecConst.CERTTYPE_ENDENTITY, SecConst.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
        }
        String tokensn = hardTokenSessionRemote.findHardTokenByCertificateSNIssuerDN(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert));        

        assertTrue("Couldn't find right hardtokensn", tokensn.equals("1234"));

        log.trace("<test03FindHardTokenByCertificate()");
    }
    
    /**
     * edits token
     *
     * @throws Exception error
     */
    
    public void test04EncryptHardToken() throws Exception {
        log.trace(">test04EncryptHardToken()");

        GlobalConfiguration gc = raAdminSession.getCachedGlobalConfiguration(admin);
        gc.setHardTokenEncryptCA(getTestCAId());
        raAdminSession.saveGlobalConfiguration(admin, gc);
        boolean ret = false;

        // Make sure the old data can be read
        HardTokenData token = hardTokenSessionRemote.getHardToken(admin, "1234", true);

        SwedishEIDHardToken swe = (SwedishEIDHardToken) token.getHardToken();

        assertTrue("Retrieving HardToken failed : " + swe.getInitialAuthEncPIN(), swe.getInitialAuthEncPIN().equals("5678"));

        swe.setInitialAuthEncPIN("5678");

        // Store the new data as encrypted
        hardTokenSessionRemote.changeHardToken(admin, "1234", SecConst.TOKEN_SWEDISHEID, token.getHardToken());
        ret = true;                

        assertTrue("Saving encrypted HardToken failed", ret);

        // Make sure the encrypted data can be read
        token = hardTokenSessionRemote.getHardToken(admin, "1234",true);

        swe = (SwedishEIDHardToken) token.getHardToken();

        assertTrue("Retrieving encrypted HardToken failed", swe.getInitialAuthEncPIN().equals("5678"));

        log.trace("<test04EncryptHardToken()");
    }
    
    /**
     * removes all profiles
     *
     * @throws Exception error
     */
   
    public void test05removeHardTokens() throws Exception {
        log.trace(">test05removeHardTokens()");
        GlobalConfiguration gc = raAdminSession.getCachedGlobalConfiguration(admin);
        gc.setHardTokenEncryptCA(orgEncryptCAId);
        raAdminSession.saveGlobalConfiguration(admin, gc);
        boolean ret = false;
        try {
            hardTokenSessionRemote.removeHardToken(admin, "1234");
            hardTokenSessionRemote.removeHardToken(admin, "2345");

            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing Hard Token failed", ret);

        log.trace("<test05removeHardTokens()");
    }
   
	public void test99RemoveTestCA() throws Exception {
		removeTestCA();
	}
}
