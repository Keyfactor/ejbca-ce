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

package se.anatom.ejbca.hardtoken;

import java.util.ArrayList;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.hardtoken.hardtokentypes.SwedishEIDHardToken;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;

/**
 * Tests the hard token related entity beans.
 *
 * @version $Id: TestHardToken.java,v 1.1 2004-06-10 16:17:44 sbailliez Exp $
 */
public class TestHardToken extends TestCase {
    private static Logger log = Logger.getLogger(TestHardToken.class);
    private IHardTokenSessionRemote cacheAdmin;


    private static IHardTokenSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

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


    /**
     * Creates a new TestHardToken object.
     *
     * @param name name
     */
    public TestHardToken(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");
        CertTools.installBCProvider();
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("HardTokenSession");
                cacheHome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IHardTokenSessionHome.class);

            }

            cacheAdmin = cacheHome.create();
        }


        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");

        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");

        return ctx;
    }


    /**
     * adds a token to the database
     *
     * @throws Exception error
     */
    public void test01AddHardToken() throws Exception {
        log.debug(">test01AddHardToken()");
        boolean ret = false;
        try {
            SwedishEIDHardToken token = new SwedishEIDHardToken("1234", "1234", "123456", "123456", 1);

            ArrayList certs = new ArrayList();

            certs.add(CertTools.getCertfromByteArray(testcert));

            cacheAdmin.addHardToken(admin, "1234", "TESTUSER", "CN=TEST", SecConst.TOKEN_SWEDISHEID, token, certs, null);

            ret = true;
        } catch (HardTokenExistsException pee) {
        }

        assertTrue("Creating End Entity Profile failed", ret);
        log.debug("<test01AddHardToken()");
    }


    /**
     * edits token
     *
     * @throws Exception error
     */
    public void test02EditHardToken() throws Exception {
        log.debug(">test02EditHardToken()");

        boolean ret = false;

        HardTokenData token = cacheAdmin.getHardToken(admin, "1234");

        SwedishEIDHardToken swe = (SwedishEIDHardToken) token.getHardToken();

        assertTrue("Retrieving HardToken failed", swe.getInitialAuthEncPIN().equals("1234"));

        swe.setInitialAuthEncPIN("5678");

        cacheAdmin.changeHardToken(admin, "1234", SecConst.TOKEN_SWEDISHEID, token.getHardToken());
        ret = true;

        assertTrue("Editing HardToken failed", ret);


        log.debug("<test02EditHardToken()");
    }


    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test03removeHardTokens() throws Exception {
        log.debug(">test03removeHardTokens()");
        boolean ret = false;
        try {
            cacheAdmin.removeHardToken(admin, "1234");

            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing Certificate Profile failed", ret);

        log.debug("<test03removeHardTokens()");
    }


}
