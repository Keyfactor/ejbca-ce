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

package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;

/**
 * Tests certificate store.
 *
 * @version $Id: TestCertificateData.java,v 1.2 2004-07-23 10:24:42 anatom Exp $
 */
public class TestCertificateData extends TestCase {

    static byte[] testcert = Base64.decode(("MIICETCCAXqgAwIBAgIIEzy5vc2xpOIwDQYJKoZIhvcNAQEFBQAwLjEOMAwGA1UE"
            + "AxMFZWpiY2ExDzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwHhcNMDExMTE0"
            + "MTMxODU5WhcNMDMxMTE0MTMyODU5WjAsMQwwCgYDVQQDEwNmb28xDzANBgNVBAoT"
            + "BkFuYVRvbTELMAkGA1UEBhMCU0UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAqPX5"
            + "YOgT76Tz5uDOmegzA6RRdOFR7/nyWc8Wu4FnU6litDqo1wQCD9Pqtq6XzWJ1smD5"
            + "svNhscRcXPeiucisoQIDAQABo34wfDAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB"
            + "/wQFAwMHoAAwHQYDVR0OBBYEFMrdBFmXrmAtP65uHZmF2Jc3shB1MB8GA1UdIwQY"
            + "MBaAFHxNs2NoKyv7/ipWKfwRyGU6d6voMBgGA1UdEQQRMA+BDWZvb0BhbmF0b20u"
            + "c2UwDQYJKoZIhvcNAQEFBQADgYEAH6AqvzaReZFMvYudIY6lCT5shodNTyjZBT0/"
            + "kBMHp1csVVqJl80Ngr2QzKE55Xhok05i7q9oLcRSbnQ8ZfnTDa9lZaWiZzX7LxF/"
            + "5fd74ol2m/J2LvVglqH9VEINI4RE+HxrMFy8QMROYbsOhl8Jk9TOsuDeQjEtgodm"
            + "gY5ai2k=").getBytes());

    private static Logger log = Logger.getLogger(TestCertificateData.class);
    private static Context ctx;
    private static ICertificateStoreSessionHome storehome;
    private static X509Certificate cert;
    private static long revDate;
    private static Admin admin = null;
    private static boolean certAlreadyExists = false;

    /**
     * Creates a new TestCertificateData object.
     *
     * @param name name
     */
    public TestCertificateData(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        CertTools.installBCProvider();

        admin = new Admin(Admin.TYPE_INTERNALUSER);
        ctx = getInitialContext();
        Object obj2 = ctx.lookup("CertificateStoreSession");
        storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
        cert = CertTools.getCertfromByteArray(testcert);
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
     * creates new certs
     *
     * @throws Exception error
     */
    public void test01CreateNewCert() throws Exception {
        log.debug(">test01CreateNewCert()");
        X509Certificate cert = CertTools.getCertfromByteArray(testcert);
        CertificateDataPK pk = new CertificateDataPK();
        String fp = CertTools.getFingerprintAsString(cert);

        ICertificateStoreSessionRemote store = storehome.create();
        try {
            Certificate ce = store.findCertificateByFingerprint(admin,fp);
            if (ce != null) {
                log.info("Certificate with fp="+fp+" already exists in db, cannot add.");
                certAlreadyExists = true;
                return;
            }
        	boolean ret = store.storeCertificate(admin, cert, "foo", "1234", CertificateDataBean.CERT_INACTIVE, CertificateDataBean.CERT_TYPE_ENCRYPTION);
            assertTrue("Failed to store", ret);
            log.debug("stored it!");
        } catch (RemoteException e) {
            log.error("Error storing certificate: ",e);
            assertTrue("Error storing certificate.", false);
            return;
        }
        log.debug("<test01CreateNewCert()");
    }

    /**
     * finds and alters certificates
     *
     * @throws Exception error
     */
    public void test02FindAndChange() throws Exception {
        log.debug(">test02FindAndChange()");
        String fp = CertTools.getFingerprintAsString(cert);
        ICertificateStoreSessionRemote store = storehome.create();
        try {
            X509Certificate ce = (X509Certificate)store.findCertificateByFingerprint(admin,fp);
            assertNotNull("Cannot find certificate with fp="+fp,ce);
            CertificateInfo info = store.getCertificateInfo(admin, fp);
            assertEquals("fingerprint does not match.",fp,info.getFingerprint());
            assertEquals("CAfingerprint does not match.","1234",info.getCAFingerprint());
            assertEquals("serialnumber does not match.",ce.getSerialNumber(),info.getSerialNumber());
            assertEquals("issuerdn does not match.",CertTools.getIssuerDN(ce),info.getIssuerDN());
            assertEquals("subjectdn does not match.",CertTools.getSubjectDN(ce),info.getSubjectDN());
            // Om certet redan finns ?r status troligen 40, d? har vi k?rt testen tidigare
            if (certAlreadyExists) {
                assertEquals("status does not match.",CertificateDataBean.CERT_REVOKED,info.getStatus());
            } else {
                assertEquals("status does not match.",CertificateDataBean.CERT_INACTIVE,info.getStatus());                
            }
            assertEquals("type does not match.",CertificateDataBean.CERT_TYPE_ENCRYPTION,info.getType());
            assertEquals("exiredate does not match.",ce.getNotAfter(),info.getExpireDate());
            // Om certet redan finns ?r reason troligen 3, d? har vi k?rt testen tidigare
            if (certAlreadyExists) {
                assertEquals("revocation reason does not match.",RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED,info.getRevocationReason());
            } else {
                assertEquals("revocation reason does not match.",RevokedCertInfo.NOT_REVOKED,info.getRevocationReason());
            }
            log.info("revocationdate (before rev)=" + info.getRevocationDate());
            store.revokeCertificate(admin,ce,null,RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
            CertificateInfo info1 = store.getCertificateInfo(admin, fp);
            if (certAlreadyExists) {
                assertEquals("revocation reason does not match.",RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED,info1.getRevocationReason());
            } else {
                assertEquals("revocation reason does not match.",RevokedCertInfo.NOT_REVOKED,info1.getRevocationReason());
            }
            log.info("revocationdate (after rev)=" + info1.getRevocationDate());
            assertTrue("Revocation date in future.", new Date().compareTo(info1.getRevocationDate())>=0);
        } catch (RemoteException e) {
            log.error("Error getting or revoking certificate: ",e);
            assertTrue("Error getting or revoking certificate.", false);
            return;
        }
        log.debug("<test02FindAndChange()");
    }

    /**
     * listst and revokes certs
     *
     * @throws Exception error
     */
    public void test03listAndRevoke() throws Exception {
        log.debug(">test03listAndRevoke()");
        ICertificateStoreSessionRemote store = storehome.create();
        String issuerDN = CertTools.getIssuerDN(cert);
        String subjectDN = CertTools.getSubjectDN(cert);
        // List all certificates to see
        Collection certfps = store.listAllCertificates(admin, issuerDN);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);

        int size = certfps.size();
        log.debug("List certs: " + size);

        // List all certificates for user foo, which we have created in TestSignSession
        certfps = store.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), subjectDN, issuerDN);
        assertTrue("something weird with size, all < foos", size >= certfps.size());
        log.debug("List certs for foo: " + certfps.size());
        revDate = new Date().getTime();
        Iterator iter = certfps.iterator();
        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            String fp = CertTools.getFingerprintAsString(cert);
            log.debug("revoking cert with fp="+fp);
            // Revoke all foos certificates
            store.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED);
            log.debug("Revoked cert " + fp);
        }
        log.debug("<test03listAndRevoke()");
    }

    /**
     * checks revoked certs
     *
     * @throws Exception error
     */
    public void test04CheckRevoked() throws Exception {
        log.debug(">test04CheckRevoked()");

        ICertificateStoreSessionRemote store = storehome.create();
        String issuerDN = CertTools.getIssuerDN(cert);
        String subjectDN = CertTools.getSubjectDN(cert);
        // List all certificates for user foo, which we have created in TestSignSession
        Collection certfps = store.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), subjectDN, issuerDN);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);

        // Verify that cert are revoked
        Iterator iter = certfps.iterator();
        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            String fp = CertTools.getFingerprintAsString(cert);
            CertificateInfo rev = store.getCertificateInfo(admin, fp);
            log.info("revocationdate (after rev)=" + rev.getRevocationDate());
            assertTrue("Revocation date in future.", new Date().compareTo(rev.getRevocationDate())>=0);
            assertTrue(rev.getStatus() == CertificateDataBean.CERT_REVOKED);
        }

        log.debug("<test04CheckRevoked()");
    }

    /**
     * finds certificates again
     *
     * @throws Exception error
     */
    public void test05FindAgain() throws Exception {
        log.debug(">test05FindAgain()");

        String fp = CertTools.getFingerprintAsString(cert);

        ICertificateStoreSessionRemote store = storehome.create();
        CertificateInfo data3 = store.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data3);
        log.debug("found by key! =" + data3);
        log.debug("fp=" + data3.getFingerprint());
        log.debug("issuer=" + data3.getIssuerDN());
        log.debug("subject=" + data3.getSubjectDN());
        log.debug("cafp=" + data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        log.debug("status=" + data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == CertificateDataBean.CERT_REVOKED);
        log.debug("type=" + data3.getType());
        assertTrue("wrong type", (data3.getType() & SecConst.USER_ENDUSER) == SecConst.USER_ENDUSER);
        log.debug("serno=" + data3.getSerialNumber());
        log.debug("expiredate=" + data3.getExpireDate());
        log.debug("revocationdate=" + data3.getRevocationDate());
        log.debug("revocationreason=" + data3.getRevocationReason());
        assertTrue("wrong reason", (data3.getRevocationReason() == RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED));

        log.debug("Looking for cert with DN=" + CertTools.getSubjectDN(cert));
        Collection certs = store.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getSubjectDN(cert), CertTools.getIssuerDN(cert));
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            X509Certificate xcert = (X509Certificate) iter.next();
            log.debug(CertTools.getSubjectDN(xcert) + " - " + xcert.getSerialNumber().toString());
            //log.debug(certs[i].toString());
        }
        log.debug("<test05FindAgain()");
    }

    /**
     * finds certs by expire time
     *
     * @throws Exception error
     */
    public void test06FindByExpireTime() throws Exception {
        log.debug(">test06FindByExpireTime()");

        ICertificateStoreSessionRemote store = storehome.create();
        String fp = CertTools.getFingerprintAsString(cert);

        CertificateInfo data = store.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data);
        log.debug("expiredate=" + data.getExpireDate());

        // Seconds in a year
        long yearmillis = 365 * 24 * 60 * 60 * 1000;
        long findDateSecs = data.getExpireDate().getTime() - (yearmillis * 100);
        Date findDate = new Date(findDateSecs);

        log.debug("1. Looking for cert with expireDate=" + findDate);

        Collection certs = store.findCertificatesByExpireTime(new Admin(Admin.TYPE_INTERNALUSER), findDate);
        log.debug("findCertificatesByExpireTime returned " + certs.size() + " certs.");
        assertTrue("No certs should have expired before this date", certs.size() == 0);
        findDateSecs = data.getExpireDate().getTime() + 10000;
        findDate = new Date(findDateSecs);
        log.debug("2. Looking for cert with expireDate=" + findDate);
        certs = store.findCertificatesByExpireTime(new Admin(Admin.TYPE_INTERNALUSER), findDate);
        log.debug("findCertificatesByExpireTime returned " + certs.size() + " certs.");
        assertTrue("Some certs should have expired before this date", certs.size() != 0);

        Iterator iter = certs.iterator();

        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            Date retDate = cert.getNotAfter();
            log.debug(retDate);
            assertTrue("This cert is not expired by the specified Date.",
                    retDate.getTime() < findDate.getTime());
        }

        log.debug("<test06FindByExpireTime()");
    }

    /**
     * finds certs by issuer and serialno
     *
     * @throws Exception error
     */
    public void test07FindByIssuerAndSerno() throws Exception {
        log.debug(">test07FindByIssuerAndSerno()");

        String issuerDN = CertTools.getIssuerDN(cert);
        ICertificateStoreSessionRemote store = storehome.create();
        String fp = CertTools.getFingerprintAsString(cert);
        CertificateInfo data3 = store.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data3);

        log.debug("Looking for cert with DN:" + CertTools.getIssuerDN(cert) + " and serno " +
                cert.getSerialNumber());
        Certificate fcert = store.findCertificateByIssuerAndSerno(new Admin(Admin.TYPE_INTERNALUSER), issuerDN, cert.getSerialNumber());
        assertNotNull("Cant find by issuer and serno", fcert);

        //log.debug(fcert.toString());
        log.debug("<test07FindByIssuerAndSerno()");
    }

    /**
     * checks if a certificate is revoked
     *
     * @throws Exception error
     */
    public void test08IsRevoked() throws Exception {
        log.debug(">test08IsRevoked()");
        ICertificateStoreSessionRemote store = storehome.create();
        String fp = CertTools.getFingerprintAsString(cert);
        CertificateInfo data3 = store.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data3);
        log.debug("found by key! =" + data3);
        log.debug("fp=" + data3.getFingerprint());
        log.debug("issuer=" + data3.getIssuerDN());
        log.debug("subject=" + data3.getSubjectDN());
        log.debug("cafp=" + data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        log.debug("status=" + data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == CertificateDataBean.CERT_REVOKED);
        log.debug("type=" + data3.getType());
        assertTrue("wrong type", (data3.getType() == CertificateDataBean.CERTTYPE_ENDENTITY));
        log.debug("serno=" + data3.getSerialNumber());
        log.debug("expiredate=" + data3.getExpireDate());
        log.debug("revocationdate=" + data3.getRevocationDate());
        log.debug("revocationreason=" + data3.getRevocationReason());
        assertTrue("wrong reason", (data3.getRevocationReason() == RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED));

        log.debug("Checking if cert is revoked DN:'" + CertTools.getIssuerDN(cert) + "', serno:'" + cert.getSerialNumber().toString() + "'.");
        RevokedCertInfo revinfo = store.isRevoked(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getIssuerDN(cert), cert.getSerialNumber());
        assertNotNull("Certificate not found, it should be!", revinfo);
        int reason = revinfo.getReason();
        assertEquals("Certificate not revoked, it should be!", RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED, reason);
        assertTrue("Wrong revocationDate!", revinfo.getRevocationDate().compareTo(data3.getRevocationDate()) == 0);
        assertTrue("Wrong reason!", revinfo.getReason() == data3.getRevocationReason());
        log.debug("Removed it!");
        log.debug("<test08IsRevoked()");
    }

}
