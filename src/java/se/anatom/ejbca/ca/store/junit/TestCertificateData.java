package se.anatom.ejbca.ca.store.junit;

import java.util.Random;
import java.util.*;
import java.lang.Integer;
import java.io.*;

import java.security.cert.*;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ca.sign.*;
import se.anatom.ejbca.ca.store.*;
import se.anatom.ejbca.ca.crl.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests certificate store.
 *
 * @version $Id: TestCertificateData.java,v 1.2 2002-03-19 10:00:38 anatom Exp $
 */
public class TestCertificateData extends TestCase {

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

    static Category cat = Category.getInstance( TestCertificateData.class.getName() );
    private static Context ctx;
    private static CertificateDataHome home;
    private static X509Certificate cert;

    public TestCertificateData(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("CertificateData");
        home = (CertificateDataHome) javax.rmi.PortableRemoteObject.narrow(obj, CertificateDataHome.class);
        cert = CertTools.getCertfromByteArray(testcert);
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

    public void test01CreateNewCert() throws Exception {
        cat.debug(">test01CreateNewCert()");
        X509Certificate cert = CertTools.getCertfromByteArray(testcert);
        CertificateDataPK pk = new CertificateDataPK();
        pk.fp = CertTools.getFingerprintAsString(cert);
        System.out.println("keyed it! ="+ pk);

        CertificateData data1=null;
        try {
            data1 = home.create(cert);
            assertNotNull("Failed to create", data1);
            System.out.println("created it!");
        } catch (javax.ejb.DuplicateKeyException e) {
            home.remove(pk);
            System.out.println("Removed it!");
            data1 = home.create(cert);
            assertNotNull("Failed to create", data1);
            System.out.println("created it!");
            return;
        }
        cat.debug("<test01CreateNewCert()");
    }
    public void test02FindAndChange() throws Exception {
        cat.debug(">test02FindAndChange()");
        CertificateDataPK pk = new CertificateDataPK();
        pk.fp = CertTools.getFingerprintAsString(cert);
        CertificateData data2 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data2);
        System.out.println("found by key! ="+ data2);
        System.out.println("fp="+data2.getFingerprint());
        System.out.println("issuer="+data2.getIssuerDN());
        System.out.println("subject="+data2.getSubjectDN());
        System.out.println("cafp="+data2.getCAFingerprint());
        System.out.println("status="+data2.getStatus());
        System.out.println("type="+data2.getType());
        System.out.println("serno="+data2.getSerialNumber());
        System.out.println("expiredate="+data2.getExpireDate());
        System.out.println("revocationdate="+data2.getRevocationDate());
        System.out.println("revocationreason="+data2.getRevocationReason());

        data2.setCAFingerprint("12345");
        data2.setStatus(CertificateData.CERT_REVOKED);
        data2.setType(SecConst.USER_ENDUSER);
        data2.setRevocationDate(new Date());
        data2.setRevocationReason(CRLData.REASON_KEYCOMPROMISE);
        System.out.println("Changed it");
       cat.debug("<test02FindAndChange()");
    }

    public void test03listAndRevoke() throws Exception {
        cat.debug(">test03listAndRevoke()");
        Object obj2 = ctx.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote store = storehome.create();
        String[] certfps = store.listAllCertificates();
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.length != 0);
        System.out.println("List certs:");
        for (int i=0;i< certfps.length;i++)
            System.out.println(certfps[i]);

        // Revoke all certs
        for (int i=0; i<certfps.length;i++) {
            CertificateDataPK revpk = new CertificateDataPK();
            revpk.fp = certfps[i];
            CertificateData rev = home.findByPrimaryKey(revpk);
            if (rev.getStatus() != CertificateData.CERT_REVOKED) {
                rev.setStatus(CertificateData.CERT_REVOKED);
                rev.setRevocationDate(new Date());
                System.out.println("Revoked cert "+certfps[i]);
            }
        }
        cat.debug("<test03listAndRevoke()");
    }
    public void test04CheckRevoked() throws Exception {
        cat.debug(">test04CheckRevoked()");
        Object obj2 = ctx.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote store = storehome.create();
        String[] certfps = store.listAllCertificates();
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.length != 0);
        // Verify that all certs are revoked
        for (int i=0; i<certfps.length;i++) {
            CertificateDataPK revpk = new CertificateDataPK();
            revpk.fp = certfps[i];
            CertificateData rev = home.findByPrimaryKey(revpk);
            assertTrue(rev.getStatus() == CertificateData.CERT_REVOKED);
            }
        cat.debug("<test04CheckRevoked()");
    }
    public void test05FindAgain() throws Exception {
        cat.debug(">test05FindAgain()");
        CertificateDataPK pk = new CertificateDataPK();
        pk.fp = CertTools.getFingerprintAsString(cert);
        CertificateData data3 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data3);
        System.out.println("found by key! ="+ data3);
        System.out.println("fp="+data3.getFingerprint());
        System.out.println("issuer="+data3.getIssuerDN());
        System.out.println("subject="+data3.getSubjectDN());
        System.out.println("cafp="+data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        System.out.println("status="+data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == CertificateData.CERT_REVOKED);
        System.out.println("type="+data3.getType());
        assertTrue("wrong type", (data3.getType() & SecConst.USER_ENDUSER) == SecConst.USER_ENDUSER);
        System.out.println("serno="+data3.getSerialNumber());
        System.out.println("expiredate="+data3.getExpireDate());
        System.out.println("revocationdate="+data3.getRevocationDate());
        System.out.println("revocationreason="+data3.getRevocationReason());
        assertTrue("wrong reason", (data3.getRevocationReason() & CRLData.REASON_KEYCOMPROMISE) == CRLData.REASON_KEYCOMPROMISE);

        System.out.println("Looking for cert with DN="+cert.getSubjectDN().toString());
        Object obj2 = ctx.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote store = storehome.create();
        Certificate[] certs = store.findCertificatesBySubject(cert.getSubjectDN().toString());
        for (int i=0;i<certs.length;i++)
            System.out.println(certs[i].toString());
        cat.debug("<test05FindAgain()");
    }

    public void test06FindByIssuerAndSerno() throws Exception {
        cat.debug(">test06FindByIssuerAndSerno()");
        CertificateDataPK pk = new CertificateDataPK();
        pk.fp = CertTools.getFingerprintAsString(cert);
        CertificateData data3 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data3);

        System.out.println("Looking for cert with DN:"+cert.getIssuerDN().toString()+" and serno "+cert.getSerialNumber());
        Object obj2 = ctx.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote store = storehome.create();
        Certificate fcert = store.findCertificateByIssuerAndSerno(cert.getIssuerDN().toString(), cert.getSerialNumber());
        assertNotNull("Cant find by issuer and serno", fcert);
        System.out.println(fcert.toString());
        cat.debug("<test06FindByIssuerAndSerno()");
    }

    public void test07IsRevoked() throws Exception {
        cat.debug(">test07IsRevoked()");
        CertificateDataPK pk = new CertificateDataPK();
        pk.fp = CertTools.getFingerprintAsString(cert);
        CertificateData data3 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data3);
        System.out.println("found by key! ="+ data3);
        System.out.println("fp="+data3.getFingerprint());
        System.out.println("issuer="+data3.getIssuerDN());
        System.out.println("subject="+data3.getSubjectDN());
        System.out.println("cafp="+data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        System.out.println("status="+data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == CertificateData.CERT_REVOKED);
        System.out.println("type="+data3.getType());
        assertTrue("wrong type", (data3.getType() & SecConst.USER_ENDUSER) == SecConst.USER_ENDUSER);
        System.out.println("serno="+data3.getSerialNumber());
        System.out.println("expiredate="+data3.getExpireDate());
        System.out.println("revocationdate="+data3.getRevocationDate());
        System.out.println("revocationreason="+data3.getRevocationReason());
        assertTrue("wrong reason", (data3.getRevocationReason() & CRLData.REASON_KEYCOMPROMISE) == CRLData.REASON_KEYCOMPROMISE);

        System.out.println("Checking if cert is revoked DN:'"+cert.getIssuerDN().toString()+"', serno:'"+cert.getSerialNumber().toString()+"'.");
        Object obj2 = ctx.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote store = storehome.create();
        RevokedCertInfo revinfo = store.isRevoked(cert.getIssuerDN().toString(), cert.getSerialNumber());
        assertNotNull("Certificate not revoked, it should be!", revinfo);
        assertTrue("Wrong revocationDate!", revinfo.getRevocationDate().getTime() == data3.getRevocationDate().getTime());
        assertTrue("Wrong reason!", revinfo.getReason() == data3.getRevocationReason());
        home.remove(pk);
        System.out.println("Removed it!");
        cat.debug("<test07IsRevoked()");
    }

}

