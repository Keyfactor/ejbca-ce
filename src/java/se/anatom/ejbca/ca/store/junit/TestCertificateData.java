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
 
package se.anatom.ejbca.ca.store.junit;

import java.util.*;
import java.security.cert.*;

import javax.naming.Context;
import javax.naming.NamingException;

import se.anatom.ejbca.ca.store.*;
import se.anatom.ejbca.ca.crl.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;

import org.apache.log4j.Logger;
import junit.framework.*;

/**
 * Tests certificate store.
 *
 * @version $Id: TestCertificateData.java,v 1.25 2004-04-16 07:38:56 anatom Exp $
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

    private static Logger log = Logger.getLogger(TestCertificateData.class);
    private static Context ctx;
    private static CertificateDataHome home;
    private static ICertificateStoreSessionHome storehome;
    private static X509Certificate cert;
    private static long revDate;

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

        ctx = getInitialContext();
        Object obj = ctx.lookup("CertificateData");
        home = (CertificateDataHome) javax.rmi.PortableRemoteObject.narrow(obj, CertificateDataHome.class);
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
        pk.fingerprint = CertTools.getFingerprintAsString(cert);
        log.debug("keyed it! ="+ pk);

        CertificateData data1=null;
        try {
            data1 = home.create(cert);
            assertNotNull("Failed to create", data1);
            log.debug("created it!");
        } catch (javax.ejb.DuplicateKeyException e) {
            home.remove(pk);
            log.debug("Removed it!");
            data1 = home.create(cert);
            assertNotNull("Failed to create", data1);
            log.debug("created it!");
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
        CertificateDataPK pk = new CertificateDataPK();
        pk.fingerprint = CertTools.getFingerprintAsString(cert);
        CertificateData data2 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data2);
        log.debug("found by key! ="+ data2);
        log.debug("fp="+data2.getFingerprint());
        log.debug("issuer="+data2.getIssuerDN());
        log.debug("subject="+data2.getSubjectDN());
        log.debug("cafp="+data2.getCAFingerprint());
        log.debug("status="+data2.getStatus());
        log.debug("type="+data2.getType());
        log.debug("serno="+data2.getSerialNumber());
        log.debug("expiredate="+data2.getExpireDate());
        log.debug("revocationdate="+data2.getRevocationDate());
        log.debug("revocationreason="+data2.getRevocationReason());

        data2.setCAFingerprint("12345");
        data2.setStatus(CertificateData.CERT_REVOKED);
        data2.setType(SecConst.USER_ENDUSER);
        data2.setRevocationDate(new Date());
        data2.setRevocationReason(RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        log.debug("Changed it");
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
        String issuerDN=CertTools.getIssuerDN(cert);
        String subjectDN=CertTools.getSubjectDN(cert);
        // List all certificates to see
        Collection certfps = store.listAllCertificates(new Admin(Admin.TYPE_INTERNALUSER), issuerDN);
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
            X509Certificate  cert = (X509Certificate)iter.next();
            String fp = CertTools.getFingerprintAsString(cert);
            log.debug(fp);
            // Revoke all foos certificates
            CertificateDataPK revpk = new CertificateDataPK(fp);
            CertificateData rev = home.findByPrimaryKey(revpk);
            rev.setStatus(CertificateData.CERT_REVOKED);
            rev.setRevocationReason(RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED);
            rev.setRevocationDate(revDate);
            log.debug("Revoked cert "+fp);
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
        String issuerDN=CertTools.getIssuerDN(cert);
        String subjectDN=CertTools.getSubjectDN(cert);
        // List all certificates for user foo, which we have created in TestSignSession
        Collection certfps = store.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), subjectDN, issuerDN);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);

        // Verify that cert are revoked
        Iterator iter = certfps.iterator();
        while (iter.hasNext()) {
            X509Certificate  cert = (X509Certificate)iter.next();
            String fp = CertTools.getFingerprintAsString(cert);
            CertificateDataPK revpk = new CertificateDataPK(fp);
            CertificateData rev = home.findByPrimaryKey(revpk);
            long date = rev.getRevocationDate();
            String date1 = new Date(date).toString();
            String date2 = new Date(revDate).toString();
            assertEquals("Revocation date is not as expected: ",date2,date1);
            assertTrue(rev.getStatus() == CertificateData.CERT_REVOKED);
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

        CertificateDataPK pk = new CertificateDataPK();
        pk.fingerprint = CertTools.getFingerprintAsString(cert);

        CertificateData data3 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data3);
        log.debug("found by key! ="+ data3);
        log.debug("fp="+data3.getFingerprint());
        log.debug("issuer="+data3.getIssuerDN());
        log.debug("subject="+data3.getSubjectDN());
        log.debug("cafp="+data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        log.debug("status="+data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == CertificateData.CERT_REVOKED);
        log.debug("type="+data3.getType());
        assertTrue("wrong type", (data3.getType() & SecConst.USER_ENDUSER) == SecConst.USER_ENDUSER);
        log.debug("serno="+data3.getSerialNumber());
        log.debug("expiredate="+data3.getExpireDate());
        log.debug("revocationdate="+data3.getRevocationDate());
        log.debug("revocationreason="+data3.getRevocationReason());
        assertTrue("wrong reason", (data3.getRevocationReason() == RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED));

        log.debug("Looking for cert with DN="+CertTools.getSubjectDN(cert));
        ICertificateStoreSessionRemote store = storehome.create();
        Collection certs = store.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getSubjectDN(cert),"TODO");
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            X509Certificate xcert = (X509Certificate)iter.next();
            log.debug(CertTools.getSubjectDN(xcert)+" - "+xcert.getSerialNumber().toString());
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

        CertificateDataPK pk = new CertificateDataPK();
        pk.fingerprint = CertTools.getFingerprintAsString(cert);

        CertificateData data = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data);
        log.debug("expiredate="+data.getExpireDate());

        // Seconds in a year
        long yearmillis = 365*24*60*60*1000;
        long findDateSecs = data.getExpireDate() - (yearmillis*100);
        Date findDate = new Date(findDateSecs);

        ICertificateStoreSessionRemote store = storehome.create();
        log.debug("1. Looking for cert with expireDate=" + findDate);

        Collection certs = store.findCertificatesByExpireTime(new Admin(Admin.TYPE_INTERNALUSER), findDate);
        log.debug("findCertificatesByExpireTime returned " + certs.size() + " certs.");
        assertTrue("No certs should have expired before this date", certs.size() == 0);
        findDateSecs = data.getExpireDate() + 10000;
        findDate = new Date(findDateSecs);
        log.debug("2. Looking for cert with expireDate="+findDate);
        certs = store.findCertificatesByExpireTime(new Admin(Admin.TYPE_INTERNALUSER), findDate);
        log.debug("findCertificatesByExpireTime returned "+ certs.size()+" certs.");
        assertTrue("Some certs should have expired before this date", certs.size() != 0);

        Iterator iter = certs.iterator();

        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate)iter.next();
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
        CertificateDataPK pk = new CertificateDataPK();
        pk.fingerprint = CertTools.getFingerprintAsString(cert);

        CertificateData data3 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data3);

        log.debug("Looking for cert with DN:" + CertTools.getIssuerDN(cert) + " and serno " +
            cert.getSerialNumber());

        ICertificateStoreSessionRemote store = storehome.create();
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
        CertificateDataPK pk = new CertificateDataPK();
        pk.fingerprint = CertTools.getFingerprintAsString(cert);
        CertificateData data3 = home.findByPrimaryKey(pk);
        assertNotNull("Failed to find cert", data3);
        log.debug("found by key! ="+ data3);
        log.debug("fp="+data3.getFingerprint());
        log.debug("issuer="+data3.getIssuerDN());
        log.debug("subject="+data3.getSubjectDN());
        log.debug("cafp="+data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        log.debug("status="+data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == CertificateData.CERT_REVOKED);
        log.debug("type="+data3.getType());
        assertTrue("wrong type", (data3.getType() & SecConst.USER_ENDUSER) == SecConst.USER_ENDUSER);
        log.debug("serno="+data3.getSerialNumber());
        log.debug("expiredate="+data3.getExpireDate());
        log.debug("revocationdate="+data3.getRevocationDate());
        log.debug("revocationreason="+data3.getRevocationReason());
        assertTrue("wrong reason", (data3.getRevocationReason() == RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED));

        log.debug("Checking if cert is revoked DN:'"+CertTools.getIssuerDN(cert)+"', serno:'"+cert.getSerialNumber().toString()+"'.");
        ICertificateStoreSessionRemote store = storehome.create();
        RevokedCertInfo revinfo = store.isRevoked(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getIssuerDN(cert), cert.getSerialNumber());
        assertNotNull("Certificate not found, it should be!", revinfo);
        int reason = revinfo.getReason();
        assertEquals("Certificate not revoked, it should be!", RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED, reason);
        assertTrue("Wrong revocationDate!", revinfo.getRevocationDate().getTime() == data3.getRevocationDate());
        assertTrue("Wrong reason!", revinfo.getReason() == data3.getRevocationReason());
        home.remove(pk);
        log.debug("Removed it!");
        log.debug("<test08IsRevoked()");
    }

}
