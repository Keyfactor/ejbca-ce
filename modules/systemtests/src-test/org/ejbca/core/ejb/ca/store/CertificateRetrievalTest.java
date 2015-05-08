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

package org.ejbca.core.ejb.ca.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminTestSessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class CertificateRetrievalTest {

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

    private static final Logger log = Logger.getLogger(CertificateRetrievalTest.class);

    private HashSet<String> m_certfps;
    private String rootCaFp = null;
    private String subCaFp = null;
    private String endEntityFp = null;

    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);

    private static void dumpCertificates(Collection<Certificate> certs) {
        log.trace(">dumpCertificates()");
        if (null != certs && !certs.isEmpty()) {
            Iterator<Certificate> iter = certs.iterator();

            while (iter.hasNext()) {
                Certificate obj = iter.next();
                log.debug("***** Certificate");
                log.debug("   SubjectDN : " + CertTools.getSubjectDN(obj));
                log.debug("   IssuerDN  : " + CertTools.getIssuerDN(obj));
            }
        } else {
            log.warn("Certificate collection is empty or NULL.");
        }
        log.trace("<dumpCertificates()");
    }

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        Certificate cert;
        AuthenticationToken adm = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        final HashSet<Certificate> m_certs = new HashSet<Certificate>();
        m_certfps = new HashSet<String>();
        cert = CertTools.getCertfromByteArray(testrootcert);
        m_certs.add(cert);
        m_certfps.add(CertTools.getFingerprintAsString(cert));
        // log.debug(cert.getIssuerDN().getName()+";"+cert.getSerialNumber().toString(16)+";"+CertTools.getFingerprintAsString(cert));
        rootCaFp = CertTools.getFingerprintAsString(cert);
        try {
            if (certificateStoreSession.findCertificateByFingerprint(rootCaFp) == null) {
                certificateStoreSession.storeCertificateRemote(adm, cert, "o=AnaTom,c=SE", rootCaFp,
                                                         CertificateConstants.CERT_ACTIVE,
                                                         CertificateConstants.CERTTYPE_ROOTCA,
                                                         CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                                                         null, new Date().getTime());
            }
            cert = CertTools.getCertfromByteArray(testcacert);
            m_certs.add(cert);
            m_certfps.add(CertTools.getFingerprintAsString(cert));
            // log.debug(cert.getIssuerDN().getName()+";"+cert.getSerialNumber().toString(16)+";"+CertTools.getFingerprintAsString(cert));
            subCaFp = CertTools.getFingerprintAsString(cert);
            if (certificateStoreSession.findCertificateByFingerprint(subCaFp) == null) {
                certificateStoreSession.storeCertificateRemote(adm, cert, "o=AnaTom,c=SE", subCaFp,
                                                         CertificateConstants.CERT_ACTIVE,
                                                         CertificateConstants.CERTTYPE_SUBCA,
                        CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, null, new Date().getTime());
            }
            cert = CertTools.getCertfromByteArray(testcert);
            m_certs.add(cert);
            m_certfps.add(CertTools.getFingerprintAsString(cert));
            // log.debug(cert.getIssuerDN().getName()+";"+cert.getSerialNumber().toString(16)+";"+CertTools.getFingerprintAsString(cert));
            endEntityFp = CertTools.getFingerprintAsString(cert);
            if (certificateStoreSession.findCertificateByFingerprint(endEntityFp) == null) {
                certificateStoreSession.storeCertificateRemote(adm, cert, "o=AnaTom,c=SE", endEntityFp,
                                                         CertificateConstants.CERT_ACTIVE,
                                                         CertificateConstants.CERTTYPE_ENDENTITY,
                                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                                                         null, new Date().getTime());
            }
        } catch (Exception e) {
            log.error("Error: ", e);
            assertTrue("Error seting up tests: " + e.getMessage(), false);
        }
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
    }


    @Test
    public void test02FindCACertificates() throws Exception {
        log.trace(">test02FindCACertificates()");
        // List all certificates to see
        Collection<Certificate> certfps =
                certificateStoreSession.findCertificatesByType(CertificateConstants.CERTTYPE_SUBCA,
                                                               null);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);
        log.debug("Query returned " + certfps.size() + " entries.");
        Iterator<Certificate> iter = certfps.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            Object obj = iter.next();
            if (!(obj instanceof Certificate)) {
                assertTrue("method 'findCertificatesByType' does not return Certificate objects.\n" + "Class of returned object '" + obj.getClass().getName()
                        + "'", false);
            }
            Certificate cert = (Certificate) obj;
            String fp = CertTools.getFingerprintAsString(cert);
            if (fp.equals(subCaFp)) {
                found = true;
                break;
            }
        }
        assertTrue(found);
        log.trace("<test02FindCACertificates()");
    }

    @Test
    public void test03FindEndEntityCertificates() throws Exception {
        log.trace(">test03FindEndEntityCertificates()");

        // List all certificates to see, but only from our test certificates
        // issuer, or we might get OutOfMemmory if there are plenty of certs
        Collection<Certificate> certfps = certificateStoreSession
                .findCertificatesByType(CertificateConstants.CERTTYPE_ENDENTITY,
                                        "CN=Subordinate CA,O=Anatom,ST=Some-State,C=SE");
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);
        log.debug("Query returned " + certfps.size() + " entries.");
        Iterator<Certificate> iter = certfps.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            Object obj = iter.next();
            if (!(obj instanceof Certificate)) {
                assertTrue("method 'findCertificatesByType' does not return Certificate objects.\n" + "Class of returned object '" + obj.getClass().getName()
                        + "'", false);
            }
            Certificate cert = (Certificate) obj;
            String fp = CertTools.getFingerprintAsString(cert);
            if (fp.equals(endEntityFp)) {
                found = true;
                break;
            }
        }
        assertTrue(found);

        log.trace("<test03FindEndEntityCertificates()");
    }

    @Test
    public void test04FindRootCertificates() throws Exception {
        log.trace(">test04FindRootCertificates()");

        // List all certificates to see
        Collection<Certificate> certfps =
                certificateStoreSession.findCertificatesByType(CertificateConstants.CERTTYPE_ROOTCA,
                                                               null);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);
        log.debug("Query returned " + certfps.size() + " entries.");
        Iterator<Certificate> iter = certfps.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            Object obj = iter.next();
            if (!(obj instanceof Certificate)) {
                assertTrue("method 'findCertificatesByType' does not return Certificate objects.\n" + "Class of returned object '" + obj.getClass().getName()
                        + "'", false);
            }
            Certificate cert = (Certificate) obj;
            String fp = CertTools.getFingerprintAsString(cert);
            if (fp.equals(rootCaFp)) {
                found = true;
                break;
            }
        }
        assertTrue(found);

        log.trace("<test04FindRootCertificates()");
    }

    @Test
    public void test05CertificatesByIssuerAndSernos() throws Exception {
        log.trace(">test05CertificatesByIssuerAndSernos()");

        Certificate rootcacert;
        Certificate subcacert;
        Certificate cert;
        List<BigInteger> sernos;
        Collection<Certificate> certfps;

        rootcacert = CertTools.getCertfromByteArray(testrootcert);
        subcacert = CertTools.getCertfromByteArray(testcacert);
        cert = CertTools.getCertfromByteArray(testcert);

        sernos = new ArrayList<BigInteger>();
        sernos.add(CertTools.getSerialNumber(subcacert));
        sernos.add(CertTools.getSerialNumber(rootcacert));
        certfps = certificateStoreSession.findCertificatesByIssuerAndSernos(CertTools.getSubjectDN(rootcacert), sernos);
        assertNotNull("failed to list certs", certfps);
        // we expect two certificates cause the rootca certificate is
        // self signed and so the issuer is identical with the subject
        // to which the certificate belongs
        dumpCertificates(certfps);
        assertTrue("failed to list certs", certfps.size() == 2);

        sernos = new ArrayList<BigInteger>();
        sernos.add(CertTools.getSerialNumber(cert));
        certfps = certificateStoreSession.findCertificatesByIssuerAndSernos(CertTools.getSubjectDN(subcacert), sernos);
        assertNotNull("failed to list certs", certfps);
        dumpCertificates(certfps);
        assertTrue("failed to list certs", certfps.size() == 1);
        assertTrue("Unable to find test certificate.", m_certfps.contains(CertTools.getFingerprintAsString((Certificate) certfps.iterator().next())));
        log.trace("<test05CertificatesByIssuerAndSernos()");
    }

    /*
     * Don't run this test since it can lookup a looot of certs and you will get
     * an OutOfMemoryException public void test06RetriveAllCertificates() throws
     * Exception { m_log.trace(">test06CertificatesByIssuer()");
     * ICertificateStoreSessionRemote store =
     * certificateStoreSession;
     * 
     * // List all certificates to see Collection certfps =
     * store.findCertificatesByType(admin , CertificateDataBean.CERTTYPE_ROOTCA
     * + CertificateDataBean.CERTTYPE_SUBCA +
     * CertificateDataBean.CERTTYPE_ENDENTITY , null);
     * assertNotNull("failed to list certs", certfps);
     * assertTrue("failed to list certs", certfps.size() >= 2); // Iterate over
     * m_certs to see that we found all our certs (we probably found alot
     * more...) Iterator iter = m_certs.iterator(); while (iter.hasNext()) {
     * assertTrue("Unable to find all test certificates.",
     * certfps.contains(iter.next())); }
     * m_log.trace("<test06CertificatesByIssuer()"); }
     */

    @Test
    public void test07FindCACertificatesWithIssuer() throws Exception {
        log.trace(">test07FindCACertificatesWithIssuer()");

        Certificate rootcacert = CertTools.getCertfromByteArray(testrootcert);

        // List all certificates to see
        Collection<Certificate> certfps =
                certificateStoreSession.findCertificatesByType(CertificateConstants.CERTTYPE_SUBCA,
                                                               CertTools.getSubjectDN(rootcacert));
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() >= 1);
        log.debug("Query returned " + certfps.size() + " entries.");
        Iterator<Certificate> iter = certfps.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            Certificate cert = iter.next();
            if (subCaFp.equals(CertTools.getFingerprintAsString(cert))) {
                found = true;
                break;
            }
        }
        assertTrue("Unable to find all test certificates.", found);
        log.trace("<test07FindCACertificatesWithIssuer()");
    }

    @Test
    public void test08LoadRevocationInfo() throws Exception {
        log.trace(">test08LoadRevocationInfo()");

        ArrayList<CertificateStatus> revstats = new ArrayList<CertificateStatus>();
        Certificate rootcacert;
        Certificate subcacert;

        ArrayList<BigInteger> sernos = new ArrayList<BigInteger>();
        rootcacert = CertTools.getCertfromByteArray(testrootcert);
        subcacert = CertTools.getCertfromByteArray(testcacert);
        sernos.add(CertTools.getSerialNumber(rootcacert));
        sernos.add(CertTools.getSerialNumber(subcacert));

        Iterator<BigInteger> iter = sernos.iterator();
        while (iter.hasNext()) {
            BigInteger bi = iter.next();
            CertificateStatus rev = certificateStoreSession.getStatus(CertTools.getSubjectDN(rootcacert), bi);
            revstats.add(rev);
        }

        assertNotNull("Unable to retrive certificate revocation status.", revstats);
        assertTrue("Method 'isRevoked' does not return status for ALL certificates.", revstats.size() >= 2);

        Iterator<CertificateStatus> iter2 = revstats.iterator();
        while (iter2.hasNext()) {
            CertificateStatus rci = iter2.next();
            log.debug("Certificate revocation information:\n" + "   Revocation date   : " + rci.revocationDate.toString() + "\n" + "   Revocation reason : "
                    + rci.revocationReason + "\n");
        }
        log.trace("<test08LoadRevocationInfo()");
    }
    
    @Test
    public void test09FindWithMissingCertData() throws Exception {
        log.trace(">test09FindWithMissingCertData()");
        final String username = "TestWithMissingCertData";
        final String dn = "CN="+username;
        
        AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        EndEntityManagementSessionRemote endEntityMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CertificateRequestSessionRemote certReqSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateRequestSessionRemote.class);
        CAAdminTestSessionRemote caAdminTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        
        // Clean up left over test data
        internalCertStoreSession.removeCertificatesBySubject(dn);
        
        List<Certificate> certs = certificateStoreSession.findCertificatesByUsername(username);
        assertNotNull("failed to list certs", certs);
        assertEquals("cert list should be empty", 0, certs.size());
        
        int caid;
        try {
            caid = caSession.getCAInfo(admin, "ManagementCA").getCAId();
        } catch (CADoesntExistsException e1) {
            caid = caSession.getCAInfo(admin, "AdminCA1").getCAId();
        }
        
        EndEntityInformation userdata = new EndEntityInformation(username,  dn, caid, "", null,
            EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER),
            SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
            new Date(), new Date(), SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        String fingerprint = null;
        try {
            endEntityMgmtSession.addUser(admin, userdata, true);
            certReqSession.processSoftTokenReq(admin, userdata, null, "1024", "RSA", false);
            
            // First test as usual
            List<Certificate> certfps = certificateStoreSession.findCertificatesByUsername(username);
            assertNotNull("failed to list certs", certfps);
            assertEquals("failed to list certs", 1, certfps.size());
            fingerprint = CertTools.getFingerprintAsString(certfps.get(0));
            
            // Set the certificate to ""
            caAdminTestSession.clearCertData(certfps.get(0));
            
            log.debug("Trying with removed cert data.");
            
            Collection<Certificate> certcollection = certificateStoreSession.findCertificatesByType(CertificateConstants.CERTTYPE_ENDENTITY, caSession.getCAInfo(admin, caid).getSubjectDN());
            assertNotNull("failed to list certs", certcollection);
            
            certfps = certificateStoreSession.findCertificatesByUsername(username);
            assertNotNull("failed to list certs", certfps);
            assertEquals("failed to list certs", 1, certfps.size());
        } finally {
            // Delete user and certificates
            if (fingerprint != null) {
                internalCertStoreSession.removeCertificate(fingerprint);
            }
            while (true) {
                try {
                    endEntityMgmtSession.deleteUser(admin, username);
                } catch (NotFoundException e) { break; }
            }
        }
        log.trace("<test09FindWithMissingCertData()");
    }
}
