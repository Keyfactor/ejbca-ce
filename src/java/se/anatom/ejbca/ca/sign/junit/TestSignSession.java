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

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.*;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests signing session.
 *
 * @version $Id: TestSignSession.java,v 1.6 2002-03-24 10:47:23 anatom Exp $
 */
public class TestSignSession extends TestCase {

    static byte[] keytoolp10 = Base64.decode(
    ("MIIBbDCB1gIBADAtMQ0wCwYDVQQDEwRUZXN0MQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
    +"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDY+ATE4ZB0oKfmXStu8J+do0GhTag6rOGtoydI"
    +"eNX9DdytlsmXDyONKl8746478/3HXdx9rA0RevUizKSataMpDsb3TjprRjzBTvYPZSIfzko6s8g6"
    +"AZLO07xCFOoDmyRzb9k/KEZsMls0ujx79CQ9p5K4rg2ksjmDeW7DaPMphQIDAQABoAAwDQYJKoZI"
    +"hvcNAQEFBQADgYEAyJVobqn6wGRoEsdHxjoqPXw8fLrQyBGEwXccnVpI4kv9iIZ45Xres0LrOwtS"
    +"kFLbpn0guEzhxPBbL6mhhmDDE4hbbHJp1Kh6gZ4Bmbb5FrwpvUyrSjTIwwRC7GAT00A1kOjl9jCC"
    +"XCfJkJH2QleCy7eKANq+DDTXzpEOvL/UqN0=").getBytes());

    static byte[] oldbcp10 = Base64.decode(
    ("MIIBbDCB1gIBADAtMQswCQYDVQQGEwJTRTEPMA0GA1UEChMGQW5hVG9tMQ0wCwYDVQQDEwRUZXN0"
    +"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzN9nDdwmq23/RLGisvR3CRO9JSem2QZ7JC7nr"
    +"NlbxQBLVqlkypT/lxMMur+lTX1S+jBaqXjtirhZTVaV5C/+HObWZ5vrj30lmsCdgzFybSzVxBz0l"
    +"XC0UEDbgBml/hO70cSDdmyw3YE9g5eH3wdYs2FCTzexRF3kNAVHNUa8svwIDAQABoAAwDQYJKoZI"
    +"hvcNAQEFBQADgYEAm6uRSyEmyCcs652Ttg2npm6JZPFT2qwSl4dviyIKJbn6j+meCzvn2TMP10d8"
    +"7Ak5sv5NJew1XGkM4mGpF9cfcVshxLVlW+cgq0749fWbyS8KlgQP/ANh3DkLl8k5E+3Wnbi0JjCV"
    +"Xe1s44+K2solX8jOtryoR4TMJ6p9HpsuO68=").getBytes());

    static byte[] iep10 = Base64.decode(
    ("MIICnTCCAgYCAQAwGzEZMBcGA1UEAxMQNkFFSzM0N2Z3OHZXRTQyNDCBnzANBgkq"
    +"hkiG9w0BAQEFAAOBjQAwgYkCgYEAukW70HN9bt5x2AiSZm7y8GXQuyp1jN2OIvqU"
    +"sr0dzLIOFt1H8GPJkL80wx3tLDj3xJfWJdww3TqExsxMSP+qScoYKIOeNBb/2OMW"
    +"p/k3DThCOewPebmt+M08AClq5WofXTG+YxyJgXWbMTNfXKIUyR0Ju4Spmg6Y4eJm"
    +"GXTG7ZUCAwEAAaCCAUAwGgYKKwYBBAGCNw0CAzEMFgo1LjAuMjE5NS4yMCAGCisG"
    +"AQQBgjcCAQ4xEjAQMA4GA1UdDwEB/wQEAwIE8DCB/wYKKwYBBAGCNw0CAjGB8DCB"
    +"7QIBAR5cAE0AaQBjAHIAbwBzAG8AZgB0ACAARQBuAGgAYQBuAGMAZQBkACAAQwBy"
    +"AHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAgAHYAMQAu"
    +"ADADgYkAjuYPzZPpbLgCWYnXoNeX2gS6nuI4osrWHlQQKcS67VJclhELlnT3hBb9"
    +"Blr7I0BsJ/lguZvZFTZnC1bMeNULRg17bhExTg+nUovzPcJhMvG7G3DR17PrJ7V+"
    +"egHAsQV4dQC2hOGGhOnv88JhP9Pwpso3t2tqJROa5ZNRRSJSkw8AAAAAAAAAADAN"
    +"BgkqhkiG9w0BAQQFAAOBgQCL5k4bJt265j63qB/9GoQb1XFOPSar1BDFi+veCPA2"
    +"GJ/vRXt77Vcr4inx9M51iy87FNcGGsmyesBoDg73p06UxpIDhkL/WpPwZAfQhWGe"
    +"o/gWydmP/hl3uEfE0E4WG02UXtNwn3ziIiJM2pBCGQQIN2rFggyD+aTxwAwOU7Z2"
    +"fw==").getBytes());

    static Category cat = Category.getInstance( TestSignSession.class.getName() );
    private static Context ctx;
    private static ISignSessionHome home;
    private static ISignSession remote;
    private static UserDataHome userhome;
    private static KeyPair keys;

    public TestSignSession(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        // Install BouncyCastle provider
        Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        int result = Security.addProvider(BCJce);

        ctx = getInitialContext();
        Object obj = ctx.lookup("RSASignSession");
        home = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
        remote = home.create();

        Object obj1 = ctx.lookup("UserData");
        userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1, UserDataHome.class);

        cat.debug("<setUp()");
    }
    protected void tearDown() throws Exception {
    }
    private Context getInitialContext() throws NamingException {
        cat.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        cat.debug("<getInitialContext");
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
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(512);
        cat.debug("Generating keys, please wait...");
        KeyPair rsaKeys = keygen.generateKeyPair();

        cat.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" + ((RSAPrivateKey)rsaKeys.getPrivate()).getPrivateExponent().bitLength());

        return rsaKeys;

    } // getKeys

    public void test01CreateNewUser() throws Exception {
        cat.debug(">test01CreateNewUser()");
        // Make user that we know...
        boolean userExists = false;
        try {
            UserData createdata = userhome.create("foo", "foo123", "C=SE, O=AnaTom, CN=foo");
            assertNotNull("Failed to create user foo", createdata);
            createdata.setType(SecConst.USER_ENDUSER);
            createdata.setSubjectEmail("foo@anatom.se");
            cat.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                userExists = true;
            }
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            cat.debug("user foo already exists.");
            UserDataPK pk = new UserDataPK();
            pk.username = "foo";
            UserData data = userhome.findByPrimaryKey(pk);
            data.setStatus(UserData.STATUS_NEW);
            cat.debug("Reset status to NEW");
        }
        cat.debug("<test01CreateNewUser()");
    }
    public void test02SignSession() throws Exception {
        cat.debug(">test02SignSession()");
        keys = genKeys();
        // user that we know exists...
        X509Certificate cert = (X509Certificate)remote.createCertificate("foo", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", cert);
        cat.debug("Cert="+cert.toString());
        //FileOutputStream fos = new FileOutputStream("testcert.crt");
        //fos.write(cert.getEncoded());
        //fos.close();
        cat.debug("<test02SignSession()");
    }

    public void test03TestBCPKCS10() throws Exception {
        cat.debug(">test03TestBCPKCS10()");
        UserDataPK pk = new UserDataPK();
        pk.username = "foo";
        UserData data = userhome.findByPrimaryKey(pk);
        data.setStatus(UserData.STATUS_NEW);
        cat.debug("Reset status of 'foo' to NEW");

        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(
            "SHA1WithRSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"), keys.getPublic(), null, keys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream ();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DERInputStream dIn = new DERInputStream(bIn);
        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest((DERConstructedSequence)dIn.readObject());
        boolean verify = req2.verify();
        cat.debug("Verify returned " + verify);
        if (verify == false) {
            cat.debug("Aborting!");
            return;
        }
        cat.debug("CertificationRequest generated succefully.");
        byte[] bcp10 = bOut.toByteArray();
        X509Certificate cert = (X509Certificate)remote.createCertificate("foo", "foo123", bcp10);
        assertNotNull("Failed to create certificate", cert);
        cat.debug("Cert="+cert.toString());
        cat.debug("<test03TestBCPKCS10()");
    }
    public void test04TestKeytoolPKCS10() throws Exception {
        cat.debug(">test04TestKeytoolPKCS10()");
        UserDataPK pk = new UserDataPK();
        pk.username = "foo";
        UserData data = userhome.findByPrimaryKey(pk);
        data.setStatus(UserData.STATUS_NEW);
        cat.debug("Reset status of 'foo' to NEW");
        X509Certificate cert = (X509Certificate)remote.createCertificate("foo", "foo123", keytoolp10);
        assertNotNull("Failed to create certificate", cert);
        cat.debug("Cert="+cert.toString());
        cat.debug("<test04TestKeytoolPKCS10()");
    }
    public void test05TestIEPKCS10() throws Exception {
        cat.debug(">test05TestIEPKCS10()");
        UserDataPK pk = new UserDataPK();
        pk.username = "foo";
        UserData data = userhome.findByPrimaryKey(pk);
        data.setStatus(UserData.STATUS_NEW);
        cat.debug("Reset status of 'foo' to NEW");
        X509Certificate cert = (X509Certificate)remote.createCertificate("foo", "foo123", iep10);
        assertNotNull("Failed to create certificate", cert);
        cat.debug("Cert="+cert.toString());
        cat.debug("<test05TestIEPKCS10()");
    }
}

