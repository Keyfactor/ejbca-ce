package se.anatom.ejbca.ca.store.junit;

import java.security.cert.*;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;

import se.anatom.ejbca.ca.store.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests Publishers.
 *
 * @version $Id: TestPublisher.java,v 1.1 2002-01-05 15:50:11 anatom Exp $
 */
public class TestPublisher extends TestCase {

    static byte[] testcert = Base64.decode(
    ("MIICETCCAXqgAwIBAgIIEzy5vc2xpOIwDQYJKoZIhvcNAQEFBQAwLjEOMAwGA1UE"
    +"AxMFZWpiY2ExDzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwHhcNMDExMTE0"
    +"MTMxODU5WhcNMDMxMTE0MTMyODU5WjAsMQwwCgYDVQQDEwNmb28xDzANBgNVBAoT"
    +"BkFuYVRvbTELMAkGA1UEBhMCU0UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAqPX5"
    +"YOgT76Tz5uDOmegzA6RRdOFR7/nyWc8Wu4FnU6litDqo1wQCD9Pqtq6XzWJ1smD5"
    +"svNhscRcXPeiucisoQIDAQABo34wfDAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB"
    +"/wQFAwMHoAAwHQYDVR0OBBYEFMrdBFmXrmAtP65uHZmF2Jc3shB1MB8GA1UdIwQY"
    +"MBaAFHxNs2NoKyv7/ipWKfwRyGU6d6voMBgGA1UdEQQRMA+BDWZvb0BhbmF0b20u"
    +"c2UwDQYJKoZIhvcNAQEFBQADgYEAH6AqvzaReZFMvYudIY6lCT5shodNTyjZBT0/"
    +"kBMHp1csVVqJl80Ngr2QzKE55Xhok05i7q9oLcRSbnQ8ZfnTDa9lZaWiZzX7LxF/"
    +"5fd74ol2m/J2LvVglqH9VEINI4RE+HxrMFy8QMROYbsOhl8Jk9TOsuDeQjEtgodm"
    +"gY5ai2k=").getBytes());

    static byte[] testcrl = Base64.decode(
    ("MIIDEzCCAnwCAQEwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UEAxMGVGVzdENBMQ8w"
    +"DQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFFw0wMjAxMDMxMjExMTFaFw0wMjAx"
    +"MDIxMjExMTFaMIIB5jAZAggfi2rKt4IrZhcNMDIwMTAzMTIxMDUxWjAZAghAxdYk"
    +"7mJxkxcNMDIwMTAzMTIxMDUxWjAZAgg+lCCL+jumXxcNMDIwMTAzMTIxMDUyWjAZ"
    +"Agh4AAPpzSk/+hcNMDIwMTAzMTIxMDUyWjAZAghkhx9SFvxAgxcNMDIwMTAzMTIx"
    +"MDUyWjAZAggj4g5SUqaGvBcNMDIwMTAzMTIxMDUyWjAZAghT+nqB0c6vghcNMDIw"
    +"MTAzMTE1MzMzWjAZAghsBWMAA55+7BcNMDIwMTAzMTE1MzMzWjAZAgg8h0t6rKQY"
    +"ZhcNMDIwMTAzMTE1MzMzWjAZAgh7KFsd40ICwhcNMDIwMTAzMTE1MzM0WjAZAggA"
    +"kFlDNU8ubxcNMDIwMTAzMTE1MzM0WjAZAghyQfo1XNl0EBcNMDIwMTAzMTE1MzM0"
    +"WjAZAggC5Pz7wI/29hcNMDIwMTAyMTY1NDMzWjAZAggEWvzRRpFGoRcNMDIwMTAy"
    +"MTY1NDMzWjAZAggC7Q2W0iXswRcNMDIwMTAyMTY1NDMzWjAZAghrfwG3t6vCiBcN"
    +"MDIwMTAyMTY1NDMzWjAZAgg5C+4zxDGEjhcNMDIwMTAyMTY1NDMzWjAZAggX/olM"
    +"45KxnxcNMDIwMTAyMTY1NDMzWqAvMC0wHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsP"
    +"WFzafOFgLmswCgYDVR0UBAMCAQQwDQYJKoZIhvcNAQEFBQADgYEAPvYDZofCOopw"
    +"OCKVGaK1aPpHkJmu5Xi1XtRGO9DhmnSZ28hrNu1A5R8OQI43Z7xFx8YK3S56GRuY"
    +"0EGU/RgM3AWhyTAps66tdyipRavKmH6MMrN4ypW/qbhsd4o8JE9pxxn9zsQaNxYZ"
    +"SNbXM2/YxkdoRSjkrbb9DUdCmCR/kEA=").getBytes());

    static Category cat = Category.getInstance( TestPublisher.class.getName() );
    private static Context ctx;
    private static IPublisherSession pub;

    public TestPublisher(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("LDAPPublisherSession");
        IPublisherSessionHome home = (IPublisherSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IPublisherSessionHome.class);
        pub = home.create();
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

    public void test01AddCertificate() throws Exception {
        cat.debug(">test01AddCertificate()");
        X509Certificate cert = CertTools.getCertfromByteArray(testcert);
        boolean ret = pub.storeCertificate(cert, null, CertificateData.CERT_ACTIVE, SecConst.USER_ENDUSER);
        assertTrue("Storing certificate failed", ret);
        cat.debug("<test01AddCertificate()");
    }
    public void test02StoreCRL() throws Exception {
        cat.debug(">test02StoreCRL()");
        X509CRL crl = CertTools.getCRLfromByteArray(testcrl);
        boolean ret = pub.storeCRL(crl, null, 1);
        assertTrue("Storing CRL failed", ret);
        cat.debug("<test02StoreCRL()");
    }
    public void test03AddCertAgain() throws Exception {
        cat.debug(">test03AddCertAgain()");
        X509Certificate cert = CertTools.getCertfromByteArray(testcert);
        boolean ret = pub.storeCertificate(cert, null, CertificateData.CERT_ACTIVE, SecConst.USER_ENDUSER);
        assertTrue("Storing certificate failed", ret);
        cat.debug("<test03AddCertAgain()");
    }
    public void test04StoreCRLAgain() throws Exception {
        cat.debug(">test04StoreCRLAgain()");
        X509CRL crl = CertTools.getCRLfromByteArray(testcrl);
        boolean ret = pub.storeCRL(crl, null, 1);
        assertTrue("Storing CRL failed", ret);
        cat.debug("<test04StoreCRLAgain()");
    }
    
    
}


