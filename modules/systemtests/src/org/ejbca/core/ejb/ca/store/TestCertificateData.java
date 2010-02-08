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

package org.ejbca.core.ejb.ca.store;

import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.CreateException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;




/**
 * Tests certificate store.
 *
 * @version $Id$
 */
public class TestCertificateData extends TestCase {

    private static final Logger log = Logger.getLogger(TestCertificateData.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static X509Certificate cert;
    private static X509Certificate cert1;
    private static X509Certificate cert2;
    private static String username = "";
    private static KeyPair keyPair;
    private ICertificateStoreSessionRemote certificateStoreSession = TestTools.getCertificateStoreSession();

    /**
     * Creates a new TestCertificateData object.
     *
     * @param name name
     */
    public TestCertificateData(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    /**
     * creates new certs
     *
     * @throws Exception error
     */
    public void test01CreateNewCertRSASha1() throws Exception {
        log.trace(">test01CreateNewCert()");
        keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        cert = generateCert(SecConst.CERT_INACTIVE);
        log.trace("<test01CreateNewCert()");
    }

    /**
     * finds and alters certificates
     *
     * @throws Exception error
     */
    public void test02FindAndChange() throws Exception {
        log.trace(">test02FindAndChange()");
        String fp = CertTools.getFingerprintAsString(cert);
        try {
            X509Certificate ce = (X509Certificate) certificateStoreSession.findCertificateByFingerprint(admin,fp);
            assertNotNull("Cannot find certificate with fp="+fp,ce);
            CertificateInfo info = certificateStoreSession.getCertificateInfo(admin, fp);
            //log.info("Got certificate info for cert with fp="+fp);
            assertEquals("fingerprint does not match.",fp,info.getFingerprint());
            assertEquals("CAfingerprint does not match.","1234",info.getCAFingerprint());
            assertEquals("serialnumber does not match.",ce.getSerialNumber(),info.getSerialNumber());
            assertEquals("issuerdn does not match.",CertTools.getIssuerDN(ce),info.getIssuerDN());
            assertEquals("subjectdn does not match.",CertTools.getSubjectDN(ce),info.getSubjectDN());
            // The cert was just stored above with status INACTIVE
            assertEquals("status does not match.",SecConst.CERT_INACTIVE,info.getStatus());                
            assertEquals("type does not match.",SecConst.CERT_TYPE_ENCRYPTION,info.getType());
            assertEquals("exiredate does not match.",ce.getNotAfter(),info.getExpireDate());
            // We just stored it above, not revoked
            assertEquals("revocation reason does not match.",RevokedCertInfo.NOT_REVOKED,info.getRevocationReason());
            log.info("revocationdate (before rev)=" + info.getRevocationDate());
            assertEquals(SecConst.CERTPROFILE_FIXED_ENDUSER, info.getCertificateProfileId());
            assertEquals("footag", info.getTag());
            Date now = new Date();
            assertNotNull(info.getUpdateTime());
            assertTrue(now.after(info.getUpdateTime()));
            certificateStoreSession.revokeCertificate(admin,ce,null,RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE, null);
            CertificateInfo info1 = certificateStoreSession.getCertificateInfo(admin, fp);
            assertEquals("revocation reason does not match.",RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE,info1.getRevocationReason());
            log.info("revocationdate (after rev)=" + info1.getRevocationDate());
            assertTrue("Revocation date in future.", new Date().compareTo(info1.getRevocationDate())>=0);
        } catch (RemoteException e) {
            log.error("Error getting or revoking certificate: ",e);
            assertTrue("Error getting or revoking certificate.", false);
            return;
        }
        log.trace("<test02FindAndChange()");
    }

    /**
     * listst and revokes certs
     *
     * @throws Exception error
     */
    public void test03listAndRevoke() throws Exception {
        log.trace(">test03listAndRevoke()");
        String issuerDN = CertTools.getIssuerDN(cert);
        String subjectDN = CertTools.getSubjectDN(cert);
        // List all certificates to see
        Collection certfps = certificateStoreSession.listAllCertificates(admin, issuerDN);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);

        int size = certfps.size();
        log.debug("List certs: " + size);

        // List all certificates for user foo, which we have created in TestSignSession
        certfps = certificateStoreSession.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), subjectDN, issuerDN);
        assertTrue("something weird with size, all < foos", size >= certfps.size());
        log.debug("List certs for foo: " + certfps.size());
        Iterator iter = certfps.iterator();
        while (iter.hasNext()) {
            Certificate cert = (Certificate) iter.next();
            String fp = CertTools.getFingerprintAsString(cert);
            log.debug("revoking cert with fp="+fp);
            // Revoke all foos certificates, note that revokeCertificate will not change status of certificates that are already revoked
            certificateStoreSession.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_AFFILIATIONCHANGED, null);
            log.debug("Revoked cert " + fp);
        }
        log.trace("<test03listAndRevoke()");
    }

    /**
     * checks revoked certs
     *
     * @throws Exception error
     */
    public void test04CheckRevoked() throws Exception {
        log.trace(">test04CheckRevoked()");
        String issuerDN = CertTools.getIssuerDN(cert);
        String subjectDN = CertTools.getSubjectDN(cert);
        // List all certificates for user foo, which we have created in TestSignSession
        Collection certfps = certificateStoreSession.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), subjectDN, issuerDN);
        assertNotNull("failed to list certs", certfps);
        assertTrue("failed to list certs", certfps.size() != 0);

        // Verify that cert are revoked
        Iterator iter = certfps.iterator();
        while (iter.hasNext()) {
            Certificate cert = (Certificate) iter.next();
            String fp = CertTools.getFingerprintAsString(cert);
            CertificateInfo rev = certificateStoreSession.getCertificateInfo(admin, fp);
            log.info("revocationdate (after rev)=" + rev.getRevocationDate());
            assertTrue("Revocation date in future.", new Date().compareTo(rev.getRevocationDate())>=0);
            assertTrue(rev.getStatus() == SecConst.CERT_REVOKED);
        }

        log.trace("<test04CheckRevoked()");
    }

    /**
     * finds certificates again
     *
     * @throws Exception error
     */
    public void test05FindAgain() throws Exception {
        log.trace(">test05FindAgain()");
        String fp = CertTools.getFingerprintAsString(cert);
        CertificateInfo data3 = certificateStoreSession.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data3);
        log.debug("found by key! =" + data3);
        log.debug("fp=" + data3.getFingerprint());
        log.debug("issuer=" + data3.getIssuerDN());
        log.debug("subject=" + data3.getSubjectDN());
        log.debug("cafp=" + data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        log.debug("status=" + data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == SecConst.CERT_REVOKED);
        log.debug("type=" + data3.getType());
        assertTrue("wrong type", (data3.getType() & SecConst.USER_ENDUSER) == SecConst.USER_ENDUSER);
        log.debug("serno=" + data3.getSerialNumber());
        log.debug("expiredate=" + data3.getExpireDate());
        log.debug("revocationdate=" + data3.getRevocationDate());
        log.debug("revocationreason=" + data3.getRevocationReason());
        assertEquals("Wrong revocation reason", data3.getRevocationReason(), RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);

        log.debug("Looking for cert with DN=" + CertTools.getSubjectDN(cert));
        Collection certs = certificateStoreSession.findCertificatesBySubjectAndIssuer(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getSubjectDN(cert), CertTools.getIssuerDN(cert));
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            Certificate xcert = (Certificate) iter.next();
            log.debug(CertTools.getSubjectDN(xcert) + " - " + CertTools.getSerialNumberAsString(xcert));
            //log.debug(certs[i].toString());
        }
        log.trace("<test05FindAgain()");
    }

    /**
     * finds certs by expire time
     *
     * @throws Exception error
     */
    public void test06FindByExpireTime() throws Exception {
        log.trace(">test06FindByExpireTime()");
        String fp = CertTools.getFingerprintAsString(cert);

        CertificateInfo data = certificateStoreSession.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data);
        log.debug("expiredate=" + data.getExpireDate());

        // Seconds in a year
        long yearmillis = 365 * 24 * 60 * 60 * 1000;
        long findDateSecs = data.getExpireDate().getTime() - (yearmillis * 200);
        Date findDate = new Date(findDateSecs);

        log.info("1. Looking for cert with expireDate=" + findDate);

        Collection certs = certificateStoreSession.findCertificatesByExpireTime(new Admin(Admin.TYPE_INTERNALUSER), findDate);
        log.debug("findCertificatesByExpireTime returned " + certs.size() + " certs.");
        assertTrue("No certs should have expired before this date", certs.size() == 0);
        findDateSecs = data.getExpireDate().getTime() + 10000;
        findDate = new Date(findDateSecs);
        log.info("2. Looking for cert with expireDate=" + findDate);
        certs = certificateStoreSession.findCertificatesByExpireTime(new Admin(Admin.TYPE_INTERNALUSER), findDate);
        log.debug("findCertificatesByExpireTime returned " + certs.size() + " certs.");
        assertTrue("Some certs should have expired before this date", certs.size() != 0);

        Iterator iter = certs.iterator();

        while (iter.hasNext()) {
            Certificate cert = (Certificate) iter.next();
            Date retDate = CertTools.getNotAfter(cert);
            log.debug(retDate);
            assertTrue("This cert is not expired by the specified Date.", retDate.getTime() < findDate.getTime());
        }

        log.trace("<test06FindByExpireTime()");
    }

    /**
     * finds certs by issuer and serialno
     *
     * @throws Exception error
     */
    public void test07FindByIssuerAndSerno() throws Exception {
        log.trace(">test07FindByIssuerAndSerno()");

        String issuerDN = CertTools.getIssuerDN(cert);
        String fp = CertTools.getFingerprintAsString(cert);
        CertificateInfo data3 = certificateStoreSession.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data3);

        log.debug("Looking for cert with DN:" + CertTools.getIssuerDN(cert) + " and serno " + cert.getSerialNumber());
        Certificate fcert = certificateStoreSession.findCertificateByIssuerAndSerno(new Admin(Admin.TYPE_INTERNALUSER), issuerDN, cert.getSerialNumber());
        assertNotNull("Cant find by issuer and serno", fcert);

        //log.debug(fcert.toString());
        log.trace("<test07FindByIssuerAndSerno()");
    }

    /**
     * checks if a certificate is revoked
     *
     * @throws Exception error
     */
    public void test08IsRevoked() throws Exception {
        log.trace(">test08IsRevoked()");
        String fp = CertTools.getFingerprintAsString(cert);
        CertificateInfo data3 = certificateStoreSession.getCertificateInfo(admin, fp);
        assertNotNull("Failed to find cert", data3);
        log.debug("found by key! =" + data3);
        log.debug("fp=" + data3.getFingerprint());
        log.debug("issuer=" + data3.getIssuerDN());
        log.debug("subject=" + data3.getSubjectDN());
        log.debug("cafp=" + data3.getCAFingerprint());
        assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
        log.debug("status=" + data3.getStatus());
        assertTrue("wrong status", data3.getStatus() == SecConst.CERT_REVOKED);
        log.debug("type=" + data3.getType());
        assertTrue("wrong type", (data3.getType() == SecConst.CERTTYPE_ENDENTITY));
        log.debug("serno=" + data3.getSerialNumber());
        log.debug("expiredate=" + data3.getExpireDate());
        log.debug("revocationdate=" + data3.getRevocationDate());
        log.debug("revocationreason=" + data3.getRevocationReason());
        assertEquals("wrong reason", data3.getRevocationReason(), RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);

        log.debug("Checking if cert is revoked DN:'" + CertTools.getIssuerDN(cert) + "', serno:'" + cert.getSerialNumber().toString() + "'.");
        CertificateStatus revinfo = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), cert.getSerialNumber());
        assertNotNull("Certificate not found, it should be!", revinfo);
        int reason = revinfo.revocationReason;
        assertEquals("Certificate not revoked, it should be!", RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE, reason);
        assertTrue("Wrong revocationDate!", revinfo.revocationDate.compareTo(data3.getRevocationDate()) == 0);
        assertEquals("Wrong reason!", revinfo.revocationReason, data3.getRevocationReason());
        log.debug("Removed it!");
        log.trace("<test08IsRevoked()");
    }

    /**
     * Adds two certificate request history data to the database.
     *
     * @throws Exception error
     */
    public void test09addCertReqHist() throws Exception {
        log.trace(">test09addCertReqHist()");
                
        cert1 = CertTools.genSelfCert("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1", 24, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        cert2 = CertTools.genSelfCert("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2", 24, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        
        UserDataVO userdata = new UserDataVO();
        Random rand = new Random(new Date().getTime() + 4711);        
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        userdata.setUsername(username);
        userdata.setDN("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1");        
        certificateStoreSession.addCertReqHistoryData(admin,cert1, userdata);
        
        userdata.setDN("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2");
        certificateStoreSession.addCertReqHistoryData(admin,cert2, userdata);       
        log.trace("<test09addCertReqHist()");
    }    

    /**
     * checks that getCertReqHistory(Admin admin, BigInteger certificateSN, String issuerDN)
     * returns the right data.
     *
     * @throws Exception error
     */
    public void test10getCertReqHistByIssuerDNAndSerial() throws Exception {
        log.trace(">test10getCertReqHistByIssuerDNAndSerial()");

        CertReqHistory certreqhist = certificateStoreSession.getCertReqHistory(admin, cert1.getSerialNumber(),cert1.getIssuerDN().toString());
        
        assertNotNull("Error couldn't find the certificate request data stored previously", certreqhist);
        
        UserDataVO userdata = certreqhist.getUserDataVO();
        assertTrue("Error wrong username.", (userdata.getUsername().equals(username)));
        assertTrue("Error wrong DN.", (userdata.getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1")));
       
        log.trace("<test10getCertReqHistByIssuerDNAndSerial()");
    }    
    
    /**
     * checks that getCertReqHistory(Admin admin, String username)
     * returns the the two CertReqHistory object previously stored.
     *
     * @throws Exception error
     */
    public void test11getCertReqHistByUsername() throws Exception {
        log.trace(">test11getCertReqHistByUsername()");
        Collection result = certificateStoreSession.getCertReqHistory(admin, username);
        assertTrue("Error size of the returned collection.", (result.size() == 2));

        Iterator iter = result.iterator();
        while(iter.hasNext()){
          CertReqHistory certreqhist = (CertReqHistory) iter.next();
          assertTrue("Error wrong DN", ((certreqhist.getUserDataVO().getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1"))|| 
         		(certreqhist.getUserDataVO().getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2"))));
        }         
        log.trace("<test11getCertReqHistByUsername()");
    }
    
    /**
     * Removes all the previously stored certreqhist data.
     *
     * @throws Exception error
     */
    public void test12removeCertReqHistData() throws Exception {
        log.trace(">test12removeCertReqHistData()");

        certificateStoreSession.removeCertReqHistoryData(admin, CertTools.getFingerprintAsString(cert1));
        certificateStoreSession.removeCertReqHistoryData(admin, CertTools.getFingerprintAsString(cert2));
        
        CertReqHistory certreqhist = certificateStoreSession.getCertReqHistory(admin, cert1.getSerialNumber(),cert1.getIssuerDN().toString());
        assertNull("Error removing cert req history data, cert1 data is still there", certreqhist);
        
        certreqhist = certificateStoreSession.getCertReqHistory(admin, cert2.getSerialNumber(),cert2.getIssuerDN().toString());
        assertNull("Error removing cert req history data, cert2 data is still there", certreqhist);
        
        log.trace("<test12removeCertReqHistData()");
    }

    public void test13GetStatus() throws Exception {
    	// generate a new certificate
    	X509Certificate xcert = generateCert(SecConst.CERT_ACTIVE);
        // Test getStatus
    	log.debug("Certificate fingerprint: "+CertTools.getFingerprintAsString(xcert));
    	// Certificate is OK to start with
        CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.OK, status);
        // Set status of the certificate to ARCHIVED, as the CRL job does for expired certificates. getStatus should still return OK (see ECA-1527).
        certificateStoreSession.setArchivedStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getFingerprintAsString(xcert));
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.OK, status);
        
        // Revoke certificate and set to ON HOLD, this will change status from ARCHIVED to REVOKED
        certificateStoreSession.setRevokeStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getIssuerDN(xcert), xcert.getSerialNumber(), null, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, null);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.REVOKED, status);
        assertEquals(RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, status.revocationReason);
        // Check the revocation date once, it must be within one minute diff from current time  
        Calendar cal1 = Calendar.getInstance();
        cal1.add(Calendar.MINUTE, -1);
        Date date1 = cal1.getTime();
        Calendar cal2 = Calendar.getInstance();
        cal2.add(Calendar.MINUTE, 1);
        Date date2 = cal2.getTime();
        assertTrue(date1.compareTo(status.revocationDate) < 0);
        assertTrue(date2.compareTo(status.revocationDate) > 0);
        Date revDate = status.revocationDate;

        // Set status of the certificate to ARCHIVED, as the CRL job does for expired certificates. getStatus should still return REVOKED.
        certificateStoreSession.setArchivedStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getFingerprintAsString(xcert));
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.REVOKED, status);
        assertEquals(RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, status.revocationReason);
        assertEquals(revDate, status.revocationDate);

        // Now unrevoke the certificate, REMOVEFROMCRL
        certificateStoreSession.setRevokeStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getIssuerDN(xcert), xcert.getSerialNumber(), null, RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL, null);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.OK, status);

        // Set status of the certificate to ARCHIVED, as the CRL job does for expired certificates. getStatus should still return OK.
        certificateStoreSession.setArchivedStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getFingerprintAsString(xcert));
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.OK, status);

        // Finally revoke for real, this will change status from ARCHIVED to REVOKED
        certificateStoreSession.setRevokeStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getIssuerDN(xcert), xcert.getSerialNumber(), null, RevokedCertInfo.REVOKATION_REASON_PRIVILEGESWITHDRAWN, null);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.REVOKED, status);
        assertEquals(RevokedCertInfo.REVOKATION_REASON_PRIVILEGESWITHDRAWN, status.revocationReason);
        revDate = status.revocationDate;
        // Set status of the certificate to ARCHIVED, as the CRL job does for expired certificates. getStatus should still return REVOKED.
        certificateStoreSession.setArchivedStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getFingerprintAsString(xcert));
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        assertEquals(CertificateStatus.REVOKED, status);
        assertEquals(RevokedCertInfo.REVOKATION_REASON_PRIVILEGESWITHDRAWN, status.revocationReason);
        assertTrue(revDate.compareTo(status.revocationDate) == 0);
    }

    private X509Certificate generateCert(int status) throws NoSuchAlgorithmException,
    NoSuchProviderException, InvalidAlgorithmParameterException,
    SignatureException, InvalidKeyException,
    CertificateEncodingException, CreateException, RemoteException {
    	// create a key pair and a new self signed certificate
    	log.info("Generating a small key pair, might take a few seconds...");
    	X509Certificate xcert = CertTools.genSelfCert("C=SE,O=PrimeCA,OU=TestCertificateData,CN=MyNameIsFoo", 24, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
    	String fp = CertTools.getFingerprintAsString(xcert);

    	try {
    		Certificate ce = certificateStoreSession.findCertificateByFingerprint(admin,fp);
    		if (ce != null) {
    			assertTrue("Certificate with fp="+fp+" already exists in db, very strange since I just generated it.", false);
    		}
    		boolean ret = certificateStoreSession.storeCertificate(admin, xcert, "foo", "1234", status, SecConst.CERTTYPE_ENDENTITY, SecConst.CERTPROFILE_FIXED_ENDUSER, "footag", new Date().getTime());
    		//log.info("Stored new cert with fp="+fp);
    		assertTrue("Failed to store", ret);
    		log.debug("stored it!");
    	} catch (RemoteException e) {
    		log.error("Error storing certificate: ",e);
    		assertTrue("Error storing certificate.", false);
    	}
    	return xcert;
    }

}
