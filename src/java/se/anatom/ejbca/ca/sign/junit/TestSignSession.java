package se.anatom.ejbca.ca.sign.junit;

import java.util.Random;
import java.util.*;
import java.lang.Integer;
import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.Provider;
import java.security.Security;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import javax.ejb.DuplicateKeyException;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ca.sign.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests signing session.
 *
 * @version $Id: TestSignSession.java,v 1.1.1.1 2001-11-15 14:58:15 anatom Exp $
 */
public class TestSignSession extends TestCase {

    static Category cat = Category.getInstance( TestSignSession.class.getName() );
    private static Context ctx;
    private static ISignSessionHome home;
    private static ISignSession remote;

    public TestSignSession(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("RSASignSession");
        home = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
        remote = home.create();
        cat.debug("<setUp()");
    }
    protected void tearDown() throws Exception {
    }
    private Context getInitialContext() throws NamingException {
        System.out.println(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        System.out.println("<getInitialContext");
        return ctx;
    }
    /**
     * Generates a RSA key pair.
     *
     * @return KeyPair the generated key pair
     * @exception Exception if en error occurs...
     */
    private static KeyPair genKeys()
    throws Exception
    {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(512);
        System.out.println("Generating keys, please wait...");
        KeyPair rsaKeys = keygen.generateKeyPair();

        System.out.println("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" + ((RSAPrivateKey)rsaKeys.getPrivate()).getPrivateExponent().bitLength());

        return rsaKeys;

    } // getKeys

    public void test01CreateNewUser() throws Exception {
        cat.debug(">test01CreateNewUser()");
        // Make user that we know...
        Object obj1 = ctx.lookup("UserData");
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1, UserDataHome.class);
        try {
            UserData createdata = userhome.create("foo", "foo123", "C=SE, O=AnaTom, CN=foo");
            assertNotNull("Failed to create user foo", createdata);
            createdata.setType(SecConst.USER_ENDUSER);
            createdata.setSubjectEmail("foo@anatom.se");
            System.out.println("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (DuplicateKeyException dke) {
            System.out.println("user foo already exists.");
            UserDataPK pk = new UserDataPK();
            pk.username = "foo";
            UserData data = userhome.findByPrimaryKey(pk);
            data.setStatus(UserData.STATUS_NEW);
            System.out.println("Reset status to NEW");
        }
        cat.debug("<test01CreateNewUser()");
    }
    public void test02SignSession() throws Exception {
        cat.debug(">test02SignSession()");
        KeyPair keys = genKeys();
        // user that we know exists...
        X509Certificate cert = (X509Certificate)remote.createCertificate("foo", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", cert);
        System.out.println("Cert="+cert.toString());
        //FileOutputStream fos = new FileOutputStream("testcert.crt");
        //fos.write(cert.getEncoded());
        //fos.close();
       cat.debug("<test02SignSession()");
    }

}

