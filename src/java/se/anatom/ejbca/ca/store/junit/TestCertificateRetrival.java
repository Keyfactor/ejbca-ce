package se.anatom.ejbca.ca.store.junit;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.crl.*;
import se.anatom.ejbca.ca.store.*;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.*;

import java.security.cert.*;

import java.util.*;

import javax.naming.Context;
import javax.naming.NamingException;

public class TestCertificateRetrival extends TestCase  {

    static byte[] testrootcert = Base64.decode(("MIICnTCCAgagAwIBAgIBADANBgkqhkiG9w0BAQQFADBEMQswCQYDVQQGEwJTRTET"
                                              + "MBEGA1UECBMKU29tZS1TdGF0ZTEPMA0GA1UEChMGQW5hdG9tMQ8wDQYDVQQDEwZU"
                                              + "ZXN0Q0EwHhcNMDMwODIxMTcyMzAyWhcNMTMwNTIwMTcyMzAyWjBEMQswCQYDVQQG"
                                              + "EwJTRTETMBEGA1UECBMKU29tZS1TdGF0ZTEPMA0GA1UEChMGQW5hdG9tMQ8wDQYD"
                                              + "VQQDEwZUZXN0Q0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMoSn6W9BU6G"
                                              + "BLoasmAZ56uuOVV0pspyuPrPVtuNjEiJqwNr6S7Xa3+MoMq/bhogfml8YuU320o3"
                                              + "CWKB4n6kcRMiRZkhWtSL6HlO9MtE5Gq1NT1WrjkMefOYA501//U0LxLerPa8YLlD"
                                              + "CvT6GCY+B1KA8fo2GMditEfVL2uEJZpDAgMBAAGjgZ4wgZswHQYDVR0OBBYEFGU3"
                                              + "qE54h3lFUuQI+TGLRT798DhlMGwGA1UdIwRlMGOAFGU3qE54h3lFUuQI+TGLRT79"
                                              + "8DhloUikRjBEMQswCQYDVQQGEwJTRTETMBEGA1UECBMKU29tZS1TdGF0ZTEPMA0G"
                                              + "A1UEChMGQW5hdG9tMQ8wDQYDVQQDEwZUZXN0Q0GCAQAwDAYDVR0TBAUwAwEB/zAN"
                                              + "BgkqhkiG9w0BAQQFAAOBgQCn9g0SR06RTLFXN0zABYIVHe1+N1n3DcrOIrySg2h1"
                                              + "fIUV9fB9KsPp9zbLkoL2+UmnXsK8kCH0Tc7WaV0xXKrjtMxN6XIc431WS51QGW+B"
                                              + "X4XyXWbKwiJEadp6QZWCHhuXhYZnUNry3uVRWHj465P2OYlYH0rOtA2TVAl8ox5R"
                                              + "iQ==").getBytes());

    static byte[] testcacert = Base64.decode(("MIIB/zCCAWgCAQMwDQYJKoZIhvcNAQEEBQAwRDELMAkGA1UEBhMCU0UxEzARBgNV"
                                            + "BAgTClNvbWUtU3RhdGUxDzANBgNVBAoTBkFuYXRvbTEPMA0GA1UEAxMGVGVzdENB"
                                            + "MB4XDTAzMDkyMjA5MTExNVoXDTEzMDQyMjA5MTExNVowTDELMAkGA1UEBhMCU0Ux"
                                            + "EzARBgNVBAgTClNvbWUtU3RhdGUxDzANBgNVBAoTBkFuYXRvbTEXMBUGA1UEAxMO"
                                            + "U3Vib3JkaW5hdGUgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALATItEt"
                                            + "JrFmMswJRBxwhc8T8MXGrTGmovLCRIYmgX/0cklcK0pM7pDl63cX9Ps+3OsX90Ys"
                                            + "d3v0YWVEULi3YThRnH3HJgB4W4QoALuBhcewzgpLePPhzyhn/YOqRIT/yY0tspCN"
                                            + "AMLdu+Iqn/j20sFwva1NyLoA6sH28o/Jmf5zAgMBAAEwDQYJKoZIhvcNAQEEBQAD"
                                            + "gYEAMBTTmQl6axoNsMflQOzCkZPqk30Z9yltdMMT7Q1tCQDjbOiBs6tS/3au5DSZ"
                                            + "Xf9SBoWysdxNVHdYOIT5dkqJtCjC6nGiqnj5NZDXDUZ/4++NPlTEULy6ECszv2i7"
                                            + "NQ3q4x7h0mgUMaCA7sayQmLe/eOcwYxpGk2x0y5hrHJmcao=").getBytes());
                                            
    static byte[] testcert = Base64.decode(("MIICBDCCAW0CAQMwDQYJKoZIhvcNAQEEBQAwTDELMAkGA1UEBhMCU0UxEzARBgNV"
                                          + "BAgTClNvbWUtU3RhdGUxDzANBgNVBAoTBkFuYXRvbTEXMBUGA1UEAxMOU3Vib3Jk"
                                          + "aW5hdGUgQ0EwHhcNMDMwOTIyMDkxNTEzWhcNMTMwNDIyMDkxNTEzWjBJMQswCQYD"
                                          + "VQQGEwJTRTETMBEGA1UECBMKU29tZS1TdGF0ZTEPMA0GA1UEChMGQW5hdG9tMRQw"
                                          + "EgYDVQQDEwtGb29CYXIgVXNlcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA"
                                          + "xPpmVYVBzlGJxUfZa6IsHsk+HrMTbHWr/EUkiZIam95t+0SIFZHUers2PIv+GWVp"
                                          + "TmH/FTXNWVWw+W6bFlb17rfbatAkVfAYuBGRh+nUS/CPTPNw1jDeCuZRweD+DCNr"
                                          + "icx/svv0Hi/9scUqrADwtO2O7oBy7Lb/Vfa6BOnBdiECAwEAATANBgkqhkiG9w0B"
                                          + "AQQFAAOBgQAo5RzuUkLdHdAyJIG2IRptIJDOa0xq8eH2Duw9Xa3ieI9+ogCNaqWy"
                                          + "V5Oqx2lLsdn9CXxAwT/AsqwZ0ZFOJY1V2BgLTPH+vxnPOm0Xu61fl2XLtRBAycva"
                                          + "9iknwKZ3PCILvA5qjL9VedxiFhcG/p83SnPOrIOdsHykMTvO8/j8mA==").getBytes());

    private static Logger m_log = Logger.getLogger(TestCertificateRetrival.class);

    private Context m_ctx;
    private CertificateDataHome m_home;
    private ICertificateStoreSessionHome m_storehome;
    private HashSet m_certs;
    private String rootCaFp = null;
    private String subCaFp = null;
    private String endEntityFp = null;
    private Admin admin;
    
    private static void dumpCertificates(Collection certs) {
        m_log.debug(">dumpCertificates()");
        if (null != certs && !certs.isEmpty()) {
            Iterator iter = certs.iterator();
            
            while (iter.hasNext()) {
                Object obj = iter.next();
                if (obj instanceof X509Certificate) {
                    m_log.debug("***** X509Certificate");
                    m_log.debug("   SubjectDN : " 
                               + ((X509Certificate)obj).getSubjectDN());
                    m_log.debug("   IssuerDN  : " 
                               + ((X509Certificate)obj).getIssuerDN());
                } else {
                    m_log.warn("Object in collection is not a X509Certificate.");
                }
            }
        } else {
            m_log.warn("Certificate collection is empty or NULL.");        
        }
        m_log.debug("<dumpCertificates()");
    }
    
    public TestCertificateRetrival(String name) {
        super(name);
    }

    private Context getInitialContext() throws NamingException {
        m_log.debug(">getInitialContext");

        Context ctx = new javax.naming.InitialContext();
        m_log.debug("<getInitialContext");

        return ctx;
    }

    protected void setUp() throws Exception {
        m_log.debug(">setUp()");
        CertTools.installBCProvider();

        m_ctx = getInitialContext();        
        Object obj = m_ctx.lookup("CertificateData");
        m_home = (CertificateDataHome) javax.rmi.PortableRemoteObject.narrow(obj,
                CertificateDataHome.class);

        Object obj2 = m_ctx.lookup("CertificateStoreSession");
        m_storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2,
                ICertificateStoreSessionHome.class);

    
        ICertificateStoreSessionRemote store = m_storehome.create();
        X509Certificate cert;
        Admin adm = new Admin(Admin.TYPE_INTERNALUSER);
        m_certs = new HashSet();
        cert = CertTools.getCertfromByteArray(testrootcert);
        m_certs.add(cert);
        rootCaFp = CertTools.getFingerprintAsString(cert);
        boolean stored = false;
        try {
            if (store.findCertificateByFingerprint(adm, rootCaFp) == null) {
                store.storeCertificate(adm
                                   , cert
                                   , "o=AnaTom,c=SE"
                                   , rootCaFp
                                   , CertificateData.CERT_ACTIVE
                                   , SecConst.CERTTYPE_ROOTCA);
            }
            cert = CertTools.getCertfromByteArray(testcacert);
            m_certs.add(cert);
            subCaFp = CertTools.getFingerprintAsString(cert);
            if (store.findCertificateByFingerprint(adm, subCaFp) == null) {                                               
                store.storeCertificate(adm
                                   , cert
                                   , "o=AnaTom,c=SE"
                                   , subCaFp
                                   , CertificateData.CERT_ACTIVE
                                   , SecConst.CERTTYPE_SUBCA);
            }
            cert = CertTools.getCertfromByteArray(testcert);
            m_certs.add(cert);
            endEntityFp = CertTools.getFingerprintAsString(cert);
            if (store.findCertificateByFingerprint(adm, endEntityFp) == null) {
                store.storeCertificate(adm
                                   , cert
                                   , "o=AnaTom,c=SE"
                                   , endEntityFp
                                   , CertificateData.CERT_ACTIVE
                                   , SecConst.CERTTYPE_ENDENTITY);
            }
        } catch (Exception e) {
            m_log.error("Error: ",e);
            assertTrue("Error seting up tests: "+e.getMessage(),false);
        }
        admin = new Admin(Admin.TYPE_INTERNALUSER);
        m_log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    public void test01AddCertificates() throws Exception {
        m_log.debug(">test01AddCertificates()");    
        m_log.debug("<test01AddCertificates()");    
    }
    /**
     *
     * @throws Exception error
     */
    public void test02FindCACertificates() throws Exception {
        m_log.debug(">test02FindCACertificates()");    
        X509Certificate cert;
        X509Certificate storecert;
        cert = CertTools.getCertfromByteArray(testrootcert);
        ICertificateStoreSessionRemote store = m_storehome.create();

        // List all certificates to see
        Collection certfps = store.findCertificatesByType(admin
                                                          , SecConst.CERTTYPE_SUBCA
                                                          , null);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);

        Iterator iter = certfps.iterator();
        while (iter.hasNext()) {
            Object obj = iter.next(); 
            if (!(obj instanceof X509Certificate)) {
                assertTrue("method 'findCertificatesByType' does not return X509Certificate objects.\n"
                           + "Class of returned object '" + obj.getClass().getName() + "'"
                           , false);            
            }
        }
        m_log.debug("<test02FindCACertificates()");    
    }

    /**
     *
     * @throws Exception error
     */
    public void test03FindEndEntityCertificates() throws Exception {
        m_log.debug(">test03FindEndEntityCertificates()");    

        ICertificateStoreSessionRemote store = m_storehome.create();

        // List all certificates to see
        Collection certfps = store.findCertificatesByType(admin
                                                          , SecConst.CERTTYPE_ENDENTITY
                                                          , null);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);
        
        m_log.debug("<test03FindEndEntityCertificates()");    
    }

    /**
     *
     * @throws Exception error
     */
    public void test04FindRootCertificates() throws Exception {
        m_log.debug(">test04FindRootCertificates()");    

        ICertificateStoreSessionRemote store = m_storehome.create();

        // List all certificates to see
        Collection certfps = store.findCertificatesByType(admin
                                                          , SecConst.CERTTYPE_ROOTCA
                                                          , null);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);

        m_log.debug("<test04FindRootCertificates()");    
    }

    /**
     *
     * @throws Exception error
     */
    public void test05CertificatesByIssuerAndSernos() throws Exception {
        m_log.debug(">test05CertificatesByIssuerAndSernos()");    
        ICertificateStoreSessionRemote store = m_storehome.create();
        X509Certificate rootcacert;
        X509Certificate subcacert;
        X509Certificate cert;
        Vector sernos;
        Collection certfps;
        
        rootcacert = CertTools.getCertfromByteArray(testrootcert);
        subcacert = CertTools.getCertfromByteArray(testcacert);
        cert = CertTools.getCertfromByteArray(testcert);

        sernos = new Vector();
        sernos.add(subcacert.getSerialNumber());
        sernos.add(rootcacert.getSerialNumber());
        certfps = store.findCertificatesByIssuerAndSernos(admin
                                                         , rootcacert.getSubjectDN().getName()
                                                         , sernos);
        assertNotNull("failed to list certs", certfps);
        // we expect two certificates cause the rootca certificate is
        // self signed and so the issuer is identical with the subject
        // to which the certificate belongs
        dumpCertificates(certfps);
        assertTrue("failed to list certs", certfps.size() == 2);

        sernos = new Vector();
        sernos.add(cert.getSerialNumber());
        certfps = store.findCertificatesByIssuerAndSernos(admin
                                                         , subcacert.getSubjectDN().getName()
                                                         , sernos);
        assertNotNull("failed to list certs", certfps);
        dumpCertificates(certfps);
        assertTrue("failed to list certs", certfps.size() == 1);
        assertTrue("Unable to find test certificate."
                   , m_certs.contains(certfps.iterator().next()));
        m_log.debug("<test05CertificatesByIssuerAndSernos()");    
    }

    /**
     *
     * @throws Exception error
     */
    public void test06RetriveAllCertificates() throws Exception {
        m_log.debug(">test06CertificatesByIssuer()");    
        ICertificateStoreSessionRemote store = m_storehome.create();

        // List all certificates to see
        Collection certfps = store.findCertificatesByType(admin
                                                          , SecConst.CERTTYPE_ROOTCA + SecConst.CERTTYPE_SUBCA + SecConst.CERTTYPE_ENDENTITY
                                                          , null);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() >= 2);
        // Iterate over m_certs to see that we found all our certs (we probably found alot more...)
        Iterator iter = m_certs.iterator();
        while (iter.hasNext()) {
            assertTrue("Unable to find all test certificates.", certfps.contains(iter.next()));
        }
        m_log.debug("<test06CertificatesByIssuer()");    
    }

    /**
     *
     * @throws Exception error
     */
    public void test07FindCACertificatesWithIssuer() throws Exception {
        m_log.debug(">test07FindCACertificatesWithIssuer()");    

        ICertificateStoreSessionRemote store = m_storehome.create();
        X509Certificate rootcacert = CertTools.getCertfromByteArray(testrootcert);

        // List all certificates to see
        Collection certfps = store.findCertificatesByType(admin
                                                          , SecConst.CERTTYPE_SUBCA
                                                          , rootcacert.getSubjectDN().getName());
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() >= 1);
        Iterator iter = certfps.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate)iter.next();
            if (subCaFp.equals(CertTools.getFingerprintAsString(cert))) {
                found = true;
            }
        }        
        assertTrue("Unable to find all test certificates.", found);
        m_log.debug("<test07FindCACertificatesWithIssuer()");    
    }

    /**
     *
     * @throws Exception error
     */
    public void test08LoadRevocationInfo() throws Exception {
        m_log.debug(">test08LoadRevocationInfo()");    

        Collection revstats;
        X509Certificate rootcacert;
        X509Certificate subcacert;
        ICertificateStoreSessionRemote store = m_storehome.create();

        ArrayList sernos = new ArrayList();
        rootcacert = CertTools.getCertfromByteArray(testrootcert);
        subcacert = CertTools.getCertfromByteArray(testcacert);
        sernos.add(rootcacert.getSerialNumber());
        sernos.add(subcacert.getSerialNumber());
        
        revstats = store.isRevoked(admin
                                   , rootcacert.getSubjectDN().getName()
                                   , sernos);

        assertNotNull("Unable to retrive certificate revocation status.", revstats);
        assertTrue("Method 'isRevoked' does not return status for ALL certificates.", revstats.size() >= 2);

        Iterator iter = revstats.iterator();
        while (iter.hasNext()) {
            RevokedCertInfo rci = (RevokedCertInfo)iter.next();
            m_log.debug("Certificate revocation information:\n"
                        + "   Serialnumber      : " + rci.getUserCertificate().toString() + "\n"
                        + "   Revocation date   : " + rci.getRevocationDate().toString()  + "\n"
                        + "   Revocation reason : " + rci.getReason() + "\n");
        }
        m_log.debug("<test08LoadRevocationInfo()");    
    }
}