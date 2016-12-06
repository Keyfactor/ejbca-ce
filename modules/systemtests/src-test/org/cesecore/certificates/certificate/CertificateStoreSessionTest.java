/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.EJBTransactionRolledbackException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests certificate store.
 *
 * @version $Id$
 */
public class CertificateStoreSessionTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(CertificateStoreSessionTest.class);
    private static KeyPair keys;
    
    private static final String USERNAME = "foo";
    
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateStoreSessionTest"));
    
    @BeforeClass
    public static void setUpProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Before
    public void setUp() throws Exception {
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("CertStoreSessionTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("CertStoreSessionTest");
    	assertNotNull("Failed to setup test role.", role);

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(alwaysAllowToken, role, accessRules);        
    }

    @After
    public void tearDown() throws Exception {
    	tearDownRemoveRole();
    }

    @Test
    public void test01CreateNewCertRSASha1() throws Exception {
        final String orgValue = cesecoreConfigurationProxySession.getConfigurationValue("database.useSeparateCertificateTable");
        try {
            {
                // Not using database.useSeparateCertificateTable we should create a certificate and  only 1 row should be deleted when we delete it
                cesecoreConfigurationProxySession.setConfigurationValue("database.useSeparateCertificateTable", "false");
                assertEquals("false", cesecoreConfigurationProxySession.getConfigurationValue("database.useSeparateCertificateTable"));
                final Certificate cert = generateCert(RoleUsingTestCase.roleMgmgToken, CertificateConstants.CERT_ACTIVE);
                assertNotNull(cert);
                final int b64tableCerts = this.internalCertStoreSession.removeCertificate(cert);
                log.info("Not using Base64CertTable");
                assertEquals("The Base64CertTable should NOT be used and therefore no certificate should be removed from this table.",  0, b64tableCerts);
            }
            {
                // Using database.useSeparateCertificateTable we should create a certificate and  2 rows should be deleted when we delete it
                cesecoreConfigurationProxySession.setConfigurationValue("database.useSeparateCertificateTable", "true");
                assertEquals("true", cesecoreConfigurationProxySession.getConfigurationValue("database.useSeparateCertificateTable"));
                final Certificate cert = generateCert(RoleUsingTestCase.roleMgmgToken, CertificateConstants.CERT_ACTIVE);
                assertNotNull(cert);
                final int b64tableCerts = this.internalCertStoreSession.removeCertificate(cert);
                log.info("Using Base64CertTable");
                assertEquals("The Base64CertTable should be used and therefore one certificate should be removed from this table.",  1, b64tableCerts);
            }
        } finally {
            // restore configuration
            cesecoreConfigurationProxySession.setConfigurationValue("database.useSeparateCertificateTable", orgValue);
        }
    }

    @Test
    public void test02FindByExpireTime() throws Exception {
    	Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
    	String fp = CertTools.getFingerprintAsString(cert);
    	try {
    		CertificateInfo data = certificateStoreSession.getCertificateInfo(fp);
    		assertNotNull("Failed to find cert", data);
    		log.debug("expiredate=" + data.getExpireDate());

    		// Seconds in a year
    		long yearmillis = 365 * 24 * 60 * 60 * 1000;
    		long findDateSecs = data.getExpireDate().getTime() - (yearmillis * 200);
    		Date findDate = new Date(findDateSecs);

    		log.info("1. Looking for cert with expireDate=" + findDate);

    		Collection<Certificate> certs = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByExpireTimeWithLimit(findDate));
    		log.debug("findCertificatesByExpireTime returned " + certs.size() + " certs.");
    		assertTrue("No certs should have expired before this date", certs.size() == 0);
            Collection<String> usernames = certificateStoreSession.findUsernamesByExpireTimeWithLimit(findDate);
            log.debug("findUsernamesByExpireTimeWithLimit returned " + usernames.size() + " usernames.");
            assertTrue("No certs should have expired before this date", usernames.size() == 0);
    		findDateSecs = data.getExpireDate().getTime() + (yearmillis * 200);
    		findDate = new Date(findDateSecs);
    		log.info("2. Looking for cert with expireDate=" + findDate+", "+findDate.getTime());
    		Collection<Certificate> certs2 = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByExpireTimeWithLimit(findDate));
    		log.debug("findCertificatesByExpireTime returned " + certs2.size() + " certs.");
    		assertTrue("Some certs should have expired before this date", certs2.size() != 0);
            usernames = certificateStoreSession.findUsernamesByExpireTimeWithLimit(findDate);
            log.debug("findUsernamesByExpireTimeWithLimit returned " + usernames.size() + " usernames.");
            assertTrue("Some certs should have expired before this date", usernames.size() != 0);
    		for (final Certificate tmpcert : certs2) {
                Date retDate = CertTools.getNotAfter(tmpcert);
                log.debug(retDate);
                assertTrue("This cert is not expired by the specified Date.", retDate.getTime() < findDate.getTime());
    		}
    	} finally {
    		internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(cert));
    	}
	}

	/**
	 * finds certs by issuer and serialno
	 * 
	 * @throws Exception
	 *             error
	 */
	@Test
	public void test03FindByIssuerAndSerno() throws Exception {
    	Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);

    	try {
    		String issuerDN = CertTools.getIssuerDN(cert);
    		String fp = CertTools.getFingerprintAsString(cert);
    		CertificateInfo data3 = certificateStoreSession.getCertificateInfo(fp);
    		assertNotNull("Failed to find cert", data3);

    		log.debug("Looking for cert with DN:" + CertTools.getIssuerDN(cert) + " and serno " + CertTools.getSerialNumber(cert));
    		Certificate fcert = certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, CertTools.getSerialNumber(cert));
    		assertNotNull("Cant find by issuer and serno", fcert);
    	} finally {
    		internalCertStoreSession.removeCertificate(cert);    		
    	}
	}

	/**
     * finds and alters certificates
     * 
     * @throws Exception
     *             error
     */
	@Test
    public void test04FindAndChange() throws Exception {
    	Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
        String fp = CertTools.getFingerprintAsString(cert);
        try {
        	X509Certificate ce = (X509Certificate) certificateStoreSession.findCertificateByFingerprint(fp);
        	assertNotNull("Cannot find certificate with fp=" + fp, ce);
        	CertificateInfo info = certificateStoreSession.getCertificateInfo(fp);
        	// log.info("Got certificate info for cert with fp="+fp);
        	assertEquals("fingerprint does not match.", fp, info.getFingerprint());
        	assertEquals("CAfingerprint does not match.", "1234", info.getCAFingerprint());
        	assertEquals("serialnumber does not match.", ce.getSerialNumber(), info.getSerialNumber());
        	assertEquals("issuerdn does not match.", CertTools.getIssuerDN(ce), info.getIssuerDN());
        	assertEquals("subjectdn does not match.", CertTools.getSubjectDN(ce), info.getSubjectDN());
        	// The cert was just stored above with status INACTIVE
        	assertEquals("status does not match.", CertificateConstants.CERT_ACTIVE, info.getStatus());
        	assertEquals("type does not match.", CertificateConstants.CERT_TYPE_ENCRYPTION, info.getType());
        	assertEquals("exiredate does not match.", ce.getNotAfter(), info.getExpireDate());
        	// We just stored it above, not revoked
        	assertEquals("revocation reason does not match.", RevokedCertInfo.NOT_REVOKED, info.getRevocationReason());
        	log.info("revocationdate (before rev)=" + info.getRevocationDate());
        	assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, info.getCertificateProfileId());
        	assertEquals("footag", info.getTag());
        	Date now = new Date();
        	assertNotNull(info.getUpdateTime());
        	assertTrue(now.after(info.getUpdateTime()));
        	internalCertStoreSession.setRevokeStatus(roleMgmgToken, ce, new Date(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
        	CertificateInfo info1 = certificateStoreSession.getCertificateInfo(fp);
        	assertEquals("revocation reason does not match.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, info1.getRevocationReason());
        	log.info("revocationdate (after rev)=" + info1.getRevocationDate());
        	assertTrue("Revocation date in future.", new Date().compareTo(info1.getRevocationDate()) >= 0);
        } finally {
        	internalCertStoreSession.removeCertificate(cert);    		
        }
    }

	@Test
    public void test05listAndRevoke() throws Exception {
    	Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
    	try {
    		String issuerDN = CertTools.getIssuerDN(cert);
    		String subjectDN = CertTools.getSubjectDN(cert);
    		// List all certificates to see
    		Collection<String> certfps = certificateStoreSession.listAllCertificates(issuerDN);
    		assertNotNull("failed to list certs", certfps);
    		assertTrue("failed to list certs", certfps.size() != 0);

    		int size = certfps.size();
    		log.debug("List certs: " + size);

    		// List all certificates for user foo, which we have created in
    		Collection<Certificate> certs = certificateStoreSession.findCertificatesBySubjectAndIssuer(subjectDN, issuerDN);
    		assertTrue("something weird with size, all < foos", size >= certfps.size());
    		log.debug("List certs for foo: " + certfps.size());
    		Iterator<Certificate> iter = certs.iterator();
    		while (iter.hasNext()) {
    			Certificate tmpcert = iter.next();
    			String fp = CertTools.getFingerprintAsString(tmpcert);
    			log.debug("revoking cert with fp=" + fp);
    			// Revoke all foos certificates, note that revokeCertificate will
    			// not change status of certificates that are already revoked
    			internalCertStoreSession.setRevokeStatus(roleMgmgToken, tmpcert, new Date(), RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED);
    			log.debug("Revoked cert " + fp);
    		}
    		
    		// Check that they are revoked
			Collection<Certificate> revcerts = certificateStoreSession.findCertificatesBySubjectAndIssuer(subjectDN, issuerDN);
			assertNotNull("failed to list certs", revcerts);
			assertTrue("failed to list certs", revcerts.size() != 0);

			// Verify that cert are revoked
			Iterator<Certificate> reviter = revcerts.iterator();
			while (reviter.hasNext()) {
				Certificate tmpcert = reviter.next();
				String fp = CertTools.getFingerprintAsString(tmpcert);
				CertificateInfo rev = certificateStoreSession.getCertificateInfo(fp);
				log.info("revocationdate (after rev)=" + rev.getRevocationDate());
				assertTrue("Revocation date in future.", new Date().compareTo(rev.getRevocationDate()) >= 0);
				assertTrue(rev.getStatus() == CertificateConstants.CERT_REVOKED);
			}    		
    	} finally {
    		internalCertStoreSession.removeCertificate(cert);    		
    	}
	}

    /**
     * finds certificates again
     * 
     * @throws Exception
     *             error
     */
	@Test
    public void test07FindAgain() throws Exception {
		Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
		try {
			String fp = CertTools.getFingerprintAsString(cert);
			CertificateInfo data3 = certificateStoreSession.getCertificateInfo(fp);
			assertNotNull("Failed to find cert", data3);
			log.debug("found by key! =" + data3);
			log.debug("fp=" + data3.getFingerprint());
			log.debug("issuer=" + data3.getIssuerDN());
			log.debug("subject=" + data3.getSubjectDN());
			log.debug("cafp=" + data3.getCAFingerprint());
			assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
			log.debug("status=" + data3.getStatus());
			assertTrue("wrong status", data3.getStatus() == CertificateConstants.CERT_ACTIVE);
			log.debug("type=" + data3.getType());
			assertTrue("wrong type", (data3.getType() & CertificateConstants.CERTTYPE_ENDENTITY) == CertificateConstants.CERTTYPE_ENDENTITY);
			log.debug("serno=" + data3.getSerialNumber());
			log.debug("expiredate=" + data3.getExpireDate());
			log.debug("revocationdate=" + data3.getRevocationDate());
			log.debug("revocationreason=" + data3.getRevocationReason());
			assertEquals("Wrong revocation reason", data3.getRevocationReason(), RevokedCertInfo.NOT_REVOKED);
            log.debug("subjectAltName=" + data3.getSubjectAltName());
            assertEquals("Wrong SAN", "dNSName=foobar.bar.com", data3.getSubjectAltName());
            log.debug("endEntityProfileId=" + data3.getEndEntityProfileIdOrZero());
            assertEquals("Wrong EEP", EndEntityInformation.NO_ENDENTITYPROFILE, data3.getEndEntityProfileIdOrZero());
            log.debug("notBefore=" + data3.getNotBefore());
            assertEquals("Wrong notBefore", CertTools.getNotBefore(cert), data3.getNotBefore());
			
			internalCertStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
			data3 = certificateStoreSession.getCertificateInfo(fp);
			assertNotNull("Failed to find cert", data3);
			log.debug("found by key! =" + data3);
			log.debug("fp=" + data3.getFingerprint());
			log.debug("issuer=" + data3.getIssuerDN());
			log.debug("subject=" + data3.getSubjectDN());
			log.debug("cafp=" + data3.getCAFingerprint());
			assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
			log.debug("status=" + data3.getStatus());
			assertTrue("wrong status", data3.getStatus() == CertificateConstants.CERT_REVOKED);
			log.debug("type=" + data3.getType());
			assertTrue("wrong type", (data3.getType() & CertificateConstants.CERTTYPE_ENDENTITY) == CertificateConstants.CERTTYPE_ENDENTITY);
			log.debug("serno=" + data3.getSerialNumber());
			log.debug("expiredate=" + data3.getExpireDate());
			log.debug("revocationdate=" + data3.getRevocationDate());
			log.debug("revocationreason=" + data3.getRevocationReason());
			assertEquals("Wrong revocation reason", data3.getRevocationReason(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);

			log.debug("Looking for cert with DN=" + CertTools.getSubjectDN(cert));
			Collection<Certificate> certs = certificateStoreSession.findCertificatesBySubjectAndIssuer(CertTools.getSubjectDN(cert),
					CertTools.getIssuerDN(cert));
			Iterator<Certificate> iter = certs.iterator();
			while (iter.hasNext()) {
				Certificate xcert = iter.next();
				log.debug(CertTools.getSubjectDN(xcert) + " - " + CertTools.getSerialNumberAsString(xcert));
				// log.debug(certs[i].toString());
			}
		} finally {
			internalCertStoreSession.removeCertificate(cert);    		
		}
    }

    /**
     * checks if a certificate is revoked
     * 
     * @throws Exception
     *             error
     */
	@Test
    public void test08IsRevoked() throws Exception {
		Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
		try {
			String fp = CertTools.getFingerprintAsString(cert);
			CertificateInfo data3 = certificateStoreSession.getCertificateInfo(fp);
			assertNotNull("Failed to find cert", data3);
			log.debug("found by key! =" + data3);
			log.debug("fp=" + data3.getFingerprint());
			log.debug("issuer=" + data3.getIssuerDN());
			log.debug("subject=" + data3.getSubjectDN());
			log.debug("cafp=" + data3.getCAFingerprint());
			assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
			log.debug("status=" + data3.getStatus());
			assertTrue("wrong status", data3.getStatus() == CertificateConstants.CERT_ACTIVE);
			log.debug("type=" + data3.getType());
			assertTrue("wrong type", (data3.getType() == CertificateConstants.CERTTYPE_ENDENTITY));
			log.debug("serno=" + data3.getSerialNumber());
			log.debug("expiredate=" + data3.getExpireDate());
			log.debug("revocationdate=" + data3.getRevocationDate());
			log.debug("revocationreason=" + data3.getRevocationReason());
			assertEquals("wrong reason", data3.getRevocationReason(), RevokedCertInfo.NOT_REVOKED);
            log.debug("subjectAltName=" + data3.getSubjectAltName());
            assertEquals("Wrong SAN", "dNSName=foobar.bar.com", data3.getSubjectAltName());
            log.debug("endEntityProfileId=" + data3.getEndEntityProfileIdOrZero());
            assertEquals("Wrong EEP", EndEntityInformation.NO_ENDENTITYPROFILE, data3.getEndEntityProfileIdOrZero());
			
			boolean worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
			assertTrue("Failed to revoke cert that should have worked", worked);
			data3 = certificateStoreSession.getCertificateInfo(fp);
			assertNotNull("Failed to find cert", data3);
			log.debug("found by key! =" + data3);
			log.debug("fp=" + data3.getFingerprint());
			log.debug("issuer=" + data3.getIssuerDN());
			log.debug("subject=" + data3.getSubjectDN());
			log.debug("cafp=" + data3.getCAFingerprint());
			assertNotNull("wrong CAFingerprint", data3.getCAFingerprint());
			log.debug("status=" + data3.getStatus());
			assertTrue("wrong status", data3.getStatus() == CertificateConstants.CERT_REVOKED);
			log.debug("type=" + data3.getType());
			assertTrue("wrong type", (data3.getType() == CertificateConstants.CERTTYPE_ENDENTITY));
			log.debug("serno=" + data3.getSerialNumber());
			log.debug("expiredate=" + data3.getExpireDate());
			log.debug("revocationdate=" + data3.getRevocationDate());
			log.debug("revocationreason=" + data3.getRevocationReason());
			assertEquals("wrong reason", data3.getRevocationReason(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);

			log.debug("Checking if cert is revoked DN:'" + CertTools.getIssuerDN(cert) + "', serno:'" + CertTools.getSerialNumberAsString(cert) + "'.");
			CertificateStatus revinfo = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
			assertNotNull("Certificate not found, it should be!", revinfo);
			int reason = revinfo.revocationReason;
			assertEquals("Certificate not revoked, it should be!", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, reason);
			assertTrue("Wrong revocationDate!", revinfo.revocationDate.compareTo(data3.getRevocationDate()) == 0);
			assertEquals("Wrong reason!", revinfo.revocationReason, data3.getRevocationReason());
			
			// Try to revoke again, should return false since no changes should be done in database since certificate is already revoked
			worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
			assertFalse("Revoked cert in database although it should not have worked", worked);
		} finally {
			internalCertStoreSession.removeCertificate(cert);    		
		}
    }

	@Test
    public void test09GetStatus() throws Exception {
        // generate a new certificate
        X509Certificate xcert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
        try {
        	// Test getStatus
        	log.debug("Certificate fingerprint: " + CertTools.getFingerprintAsString(xcert));
        	// Certificate is OK to start with
        	CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.OK, status);
        	// Set status of the certificate to ARCHIVED, as the CRL job does for
        	// expired certificates. getStatus should still return OK (see
        	// ECA-1527).
        	certificateStoreSession.setStatus(roleMgmgToken, CertTools.getFingerprintAsString(xcert), CertificateConstants.CERT_ARCHIVED);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.OK, status);

        	// Revoke certificate and set to ON HOLD, this will change status from
        	// ARCHIVED to REVOKED
        	boolean worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, xcert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
			assertTrue("Failed to revoke cert that should have worked", worked);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.REVOKED, status);
        	assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);
        	// Check the revocation date once, it must be within one minute diff
        	// from current time
        	Calendar cal1 = Calendar.getInstance();
        	cal1.add(Calendar.MINUTE, -1);
        	Date date1 = cal1.getTime();
        	Calendar cal2 = Calendar.getInstance();
        	cal2.add(Calendar.MINUTE, 1);
        	Date date2 = cal2.getTime();
        	assertTrue(date1.compareTo(status.revocationDate) < 0);
        	assertTrue(date2.compareTo(status.revocationDate) > 0);
        	Date revDate = status.revocationDate;

        	// Set status of the certificate to ARCHIVED, as the CRL job does for
        	// expired certificates. getStatus should still return REVOKED.
        	certificateStoreSession.setStatus(roleMgmgToken, CertTools.getFingerprintAsString(xcert), CertificateConstants.CERT_ARCHIVED);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.REVOKED, status);
        	assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);
        	assertEquals(revDate, status.revocationDate);

        	// Now unrevoke the certificate, REMOVEFROMCRL
        	worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, xcert, new Date(), RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL);
			assertTrue("Failed to revoke cert that should have worked", worked);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.OK, status);

        	// Revoke certificate and set to ON HOLD again, this will change status to REVOKED (again)
        	worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, xcert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
			assertTrue("Failed to revoke cert that should have worked", worked);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.REVOKED, status);
        	assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);

        	// Now unrevoke the certificate, NOT_REVOKED
        	worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, xcert, new Date(), RevokedCertInfo.NOT_REVOKED);
			assertTrue("Failed to revoke cert that should have worked", worked);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.OK, status);

        	// Set status of the certificate to ARCHIVED, as the CRL job does for
        	// expired certificates. getStatus should still return OK.
        	certificateStoreSession.setStatus(roleMgmgToken, CertTools.getFingerprintAsString(xcert), CertificateConstants.CERT_ARCHIVED);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.OK, status);

        	// Finally revoke for real, this will change status from ARCHIVED to REVOKED
        	worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, xcert, new Date(), RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN);
			assertTrue("Failed to revoke cert that should have worked", worked);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.REVOKED, status);
        	assertEquals(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN, status.revocationReason);
        	revDate = status.revocationDate;

        	// Try to unrevoke the certificate, should not work, because it is permanently revoked
        	worked = internalCertStoreSession.setRevokeStatus(roleMgmgToken, xcert, new Date(), RevokedCertInfo.NOT_REVOKED);
			assertFalse("Revoked cert in database although it should not have worked", worked);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.REVOKED, status);
        	assertEquals(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN, status.revocationReason);

        	// Set status of the certificate to ARCHIVED, as the CRL job does for
        	// expired certificates. getStatus should still return REVOKED.
        	certificateStoreSession.setStatus(roleMgmgToken, CertTools.getFingerprintAsString(xcert), CertificateConstants.CERT_ARCHIVED);
        	status = certificateStoreSession.getStatus(CertTools.getIssuerDN(xcert), xcert.getSerialNumber());
        	assertEquals(CertificateStatus.REVOKED, status);
        	assertEquals(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN, status.revocationReason);
        	assertTrue(revDate.compareTo(status.revocationDate) == 0);
        } finally {
        	internalCertStoreSession.removeCertificate(xcert);    		
		}
    }

	@Test
	public void test10Authorization() throws Exception {
        
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CertStoreSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(certificate);
        
        // Try to create a cert with an admin that does not have access to CA
        try {
        	generateCert(adminTokenNoAuth, CertificateConstants.CERT_ACTIVE);
        	assertTrue("Should throw", false);
        } catch (AuthorizationDeniedException e) {
        	// NOPMD
        }

        // Try to change status of a cert with an admin that does not have access to CA
    	X509Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
    	try {
            try {
                internalCertStoreSession.setRevokeStatus(adminTokenNoAuth, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED);
            	assertTrue("Should throw", false);
            } catch (AuthorizationDeniedException e) {
            	// NOPMD
            }
            try {
                internalCertStoreSession.setRevokeStatus(adminTokenNoAuth, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED);
            	assertTrue("Should throw", false);
            } catch (AuthorizationDeniedException e) {
            	// NOPMD
            }
            try {
            	certificateStoreSession.setStatus(adminTokenNoAuth, CertTools.getFingerprintAsString(cert), CertificateConstants.CERT_ARCHIVED);
            	assertTrue("Should throw", false);
            } catch (AuthorizationDeniedException e) {
            	// NOPMD
            }
            // Should work with the right admin though
        	certificateStoreSession.setStatus(roleMgmgToken, CertTools.getFingerprintAsString(cert), CertificateConstants.CERT_ARCHIVED);    		
    	} finally {
    		internalCertStoreSession.removeCertificate(cert);
    	}
	}
	
	@Test
	public void test11FindByType() throws Exception {
    	Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
    	try {
    		String issuerDN = CertTools.getIssuerDN(cert);
    		String fp = CertTools.getFingerprintAsString(cert);
    		CertificateInfo data3 = certificateStoreSession.getCertificateInfo(fp);
    		assertNotNull("Failed to find cert", data3);
    		log.debug("Looking for cert with type:" + CertificateConstants.CERTTYPE_ENDENTITY + " and issuerDN " + issuerDN);
    		Collection<Certificate> fcert = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByType(CertificateConstants.CERTTYPE_ENDENTITY, issuerDN));
    		assertNotNull("Cant find by issuer and type", fcert);
    		assertEquals("Should be one ee cert issued by '"+issuerDN+"'", 1, fcert.size());
    		// Test a query with no issuerDN as well
    		Collection<Certificate> tcert = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByType(CertificateConstants.CERTTYPE_ENDENTITY, null));
    		assertNotNull("Cant find by type", tcert);
    		assertTrue("Should be more than one ee cert", tcert.size()>0);
    	} finally {
    		internalCertStoreSession.removeCertificate(cert);    		
    	}
	}

	@Test
	public void test12FindExpirationInfo() throws Exception {
    	Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
    	try {
    		String issuerDN = CertTools.getIssuerDN(cert);
    		String fp = CertTools.getFingerprintAsString(cert);
    		CertificateInfo data3 = certificateStoreSession.getCertificateInfo(fp);
    		assertNotNull("Failed to find cert", data3);
    		log.debug("Looking for cert with type:" + CertificateConstants.CERTTYPE_ENDENTITY + " and issuerDN " + issuerDN);
    		Collection<String> cas = new ArrayList<String>();
    		cas.add(issuerDN);
    		List<Object[]> fcert = internalCertStoreSession.findExpirationInfo(cas, System.currentTimeMillis(), Long.MAX_VALUE, Long.MAX_VALUE);
    		assertNotNull("Cant find any expiration info", fcert);
    		assertEquals("Should be one ee cert issued by '"+issuerDN+"'.", 1, fcert.size());
    		// Try add another CA that does not exist
    		cas.add("CN=This CA does not exist, I hope");
    		fcert = internalCertStoreSession.findExpirationInfo(cas, System.currentTimeMillis(), Long.MAX_VALUE, Long.MAX_VALUE);
    		assertNotNull("Cant find any expiration info", fcert);
    		assertEquals("Should be one ee cert", 1, fcert.size());
    	} finally {
    		internalCertStoreSession.removeCertificate(cert);    		
    	}
	}

	@Test
	public void test13TestXss() throws Exception {
        X509Certificate xcert = CertTools.genSelfCert("C=SE,O=PrimeKey,OU=TestCertificateData,CN=MyNameIsFoo<tag>mytag</tag>", 24, null, keys.getPrivate(), 
        		keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
		try {
			final String fp = CertTools.getFingerprintAsString(xcert);
			final String username = "foouser<tag>mytag</mytag>!";
	        certificateStoreSession.storeCertificateRemote(roleMgmgToken, EJBTools.wrap(xcert), username, "1234", CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
	        		CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityInformation.NO_ENDENTITYPROFILE, "footag", new Date().getTime());
	        CertificateInfo info = certificateStoreSession.getCertificateInfo(fp);
	        // Username must not include <tag>s or !
	        assertEquals("username must not contain < or ! signs: ", "foouser/tag/mytag//mytag//", info.getUsername());
		} finally {
	        internalCertStoreSession.removeCertificate(xcert);			
		}
	}

    @Test
    public void testFindUsernameByIssuerDnAndSerialNumber() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, SignatureException, IllegalStateException, OperatorCreationException, CertificateException,
            CreateException, AuthorizationDeniedException, IOException {
        Certificate cert = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
        try {
            String issuerDn = CertTools.getIssuerDN(cert);
            BigInteger serialNumber = CertTools.getSerialNumber(cert);
            assertEquals("Username was not delivered properly", USERNAME,
                    certificateStoreSession.findUsernameByIssuerDnAndSerialNumber(issuerDn, serialNumber));
        } finally {
            internalCertStoreSession.removeCertificate(cert);
        }
    }
    
    
    // certificateStoreSession.updateLimitedCertificateDataStatus should not be able to tamper with locally issued certs in CertificateData
    @Test
    public void testLimitedCertificateDataWontUpdateFullEntire() throws Exception {
        final Certificate certificate = generateCert(roleMgmgToken, CertificateConstants.CERT_ACTIVE);
        try {
            final String issuerDn = CertTools.getIssuerDN(certificate);
            final BigInteger serialNumber = CertTools.getSerialNumber(certificate);
            try {
                internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, issuerDn.hashCode(), issuerDn, serialNumber, new Date(),
                        RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, "fakecafp");
            } catch (EJBTransactionRolledbackException e) {
                if (e.getCausedByException() != null && e.getCausedByException() instanceof UnsupportedOperationException) {
                    // This is expected to be unsupported
                } else {
                    throw e;
                }
            } catch (UnsupportedOperationException e) {
                // This is expected to be unsupported
            }
            assertNotNull("Limited CertificateData update removed real certificate.", certificateStoreSession.findCertificateByIssuerAndSerno(issuerDn, serialNumber));
            try {
                internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, issuerDn.hashCode(), issuerDn, serialNumber, new Date(),
                        RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, "fakecafp");
            } catch (EJBTransactionRolledbackException e) {
                if (e.getCausedByException() != null && e.getCausedByException() instanceof UnsupportedOperationException) {
                    // This is expected to be unsupported
                } else {
                    throw e;
                }
            } catch (UnsupportedOperationException e) {
                // This really should be unsupported
            }
            final CertificateStatus certificateStatus = certificateStoreSession.getStatus(issuerDn, serialNumber);
            assertTrue("Limited CertificateData updated real certificate entry.", certificateStatus.equals(CertificateStatus.OK));
        } finally {
            internalCertStoreSession.removeCertificate(certificate);
        }
    }
    
    // verify that certificateStoreSession.getStatus (used by OcspResponseGeneratorSessionBean) returns the correct CertificateStatus for limited entries 
    @Test
    public void testLimitedCertificateDataAddUpdateRemove() throws Exception {
        final KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate caCertificate = CertTools.genSelfCert("CN=testLimitedCertificateDataCA", 3600, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, true);
        final String issuerDn = CertTools.getSubjectDN(caCertificate);
        final String caFingerprint = CertTools.getFingerprintAsString(caCertificate);
        final BigInteger serialNumber = new BigInteger("1234567890");
        // Remove any previous entry created due to a failed test
        internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, issuerDn.hashCode(), issuerDn, serialNumber, new Date(),
                RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, caFingerprint);
        final CertificateStatus certificateStatus1 = certificateStoreSession.getStatus(issuerDn, serialNumber);
        assertTrue("Fake limited CertificateData entry already existed in the database.",
                certificateStatus1.equals(CertificateStatus.NOT_AVAILABLE));
        // certificateStoreSession.updateLimitedCertificateDataStatus should be able to add limited CertificateData entries
        internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, issuerDn.hashCode(), issuerDn, serialNumber, new Date(),
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, caFingerprint);
        final CertificateStatus certificateStatus2 = certificateStoreSession.getStatus(issuerDn, serialNumber);
        assertTrue("Limited CertificateData entry was not created properly.",
                certificateStatus2.equals(CertificateStatus.REVOKED));
        assertEquals("Limited CertificateData entry was not created properly.",
                certificateStatus2.revocationReason, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        // certificateStoreSession.updateLimitedCertificateDataStatus should be able to update limited CertificateData entries (e.g. ONHOLD→ONHOLD)
        internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, issuerDn.hashCode(), issuerDn, serialNumber, new Date(),
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, caFingerprint);
        final CertificateStatus certificateStatus3 = certificateStoreSession.getStatus(issuerDn, serialNumber);
        assertTrue("Limited CertificateData entry was not created properly.",
                certificateStatus3.equals(CertificateStatus.REVOKED));
        assertEquals("Limited CertificateData entry was not created properly.",
                certificateStatus3.revocationReason, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        // certificateStoreSession.updateLimitedCertificateDataStatus should be able to update limited CertificateData entries (e.g. ONHOLD→REVOKED)
        internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, issuerDn.hashCode(), issuerDn, serialNumber, new Date(),
                RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, caFingerprint);
        final CertificateStatus certificateStatus4 = certificateStoreSession.getStatus(issuerDn, serialNumber);
        assertTrue("Limited CertificateData entry was not updated properly.",
                certificateStatus4.equals(CertificateStatus.REVOKED));
        assertEquals("Limited CertificateData entry was not updated properly.",
                certificateStatus4.revocationReason, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        // certificateStoreSession.updateLimitedCertificateDataStatus should be able to remove limited CertificateData entries when REMOVE_FROM_CRL
        internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, issuerDn.hashCode(), issuerDn, serialNumber, new Date(),
                RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL, caFingerprint);
        final CertificateStatus certificateStatus5 = certificateStoreSession.getStatus(issuerDn, serialNumber);
        assertTrue("Limited CertificateData entry was not removed properly.",
                certificateStatus5.equals(CertificateStatus.NOT_AVAILABLE));
    }
    
    @Test
    public void testLimitedCertificateDataFindByUsername() throws AuthorizationDeniedException {
        final String username = CertificateStoreSessionTest.class.getName()+"_NonExistent";
        final String subjectDn = "CN="+username;
        final BigInteger serialNumber = BigInteger.valueOf(username.hashCode()); // Just some value
        try {
            CAInfo cainfo;
            try {
                cainfo = caSession.getCAInfo(alwaysAllowToken, "ManagementCA");
            } catch (CADoesntExistsException e) {
                try {
                    cainfo = caSession.getCAInfo(alwaysAllowToken, "AdminCA1");
                } catch (CADoesntExistsException e1) {
                    throw new IllegalStateException("Couldn't find either ManagementCA or AdminCA1");
                }
            }
            
            final Certificate cacert = cainfo.getCertificateChain().iterator().next();
            final int caid = cainfo.getCAId();
            final String issuerDn = cainfo.getSubjectDN();
            final String cafp = CertTools.getFingerprintAsString(cacert);
            
            // Creates limited certificate entry, with ACTIVE status this time.
            internalCertStoreSession.updateLimitedCertificateDataStatus(alwaysAllowToken, caid, issuerDn, subjectDn, username, serialNumber, CertificateConstants.CERT_ACTIVE, null, -1, cafp);
            
            final Collection<CertificateDataWrapper> cdws = certificateStoreSession.getCertificateDataByUsername(username, false, null);
            assertEquals("Should get list of 1 certificate data wrapper", 1, cdws.size());
            final CertificateDataWrapper cdw = cdws.iterator().next();
            assertEquals("Should get the certificate.", subjectDn, cdw.getCertificateData().getSubjectDnNeverNull());
            final Collection<CertificateDataWrapper> cdws2 = certificateStoreSession.getCertificateDataByUsername(username, true, null);
            assertEquals("Should get list of 1 certificate data wrapper (since we have no expire date for limited entires, excluding expired cert should not matter)", 1, cdws2.size());
            
            // Even if the end entity doesn't exist, and there's no certificate in the database, it should still work.
            final Collection<Certificate> certs = certificateStoreSession.findCertificatesByUsernameAndStatus(username, CertificateConstants.CERT_ACTIVE);
            assertEquals("Should get an empty list (since there's no certificate)", 0, certs.size());
        } finally {
            internalCertStoreSession.removeCertificate(serialNumber);
        }
    }

    @Test
    public void testGetCertificateDataByUsername() throws AuthorizationDeniedException, CertificateParsingException, OperatorCreationException, CertIOException, InvalidAlgorithmParameterException {
        final String TEST_NAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        log.trace(">" + TEST_NAME);
        final String USERNAME = TEST_NAME + "_user";
        final long now = System.currentTimeMillis();
        final Date date10sAgo = new Date(now-10000L);
        final Date date2sAgo = new Date(now-2000L);
        final Date date1hFromNow = new Date(now+3600000L);
        final KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        // Generate self signed certificates
        final X509Certificate x509Certificate1 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date1hFromNow, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint1 = CertTools.getFingerprintAsString(x509Certificate1);
        final X509Certificate x509Certificate2 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date2sAgo, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint2 = CertTools.getFingerprintAsString(x509Certificate2);
        final X509Certificate x509Certificate3 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date1hFromNow, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint3 = CertTools.getFingerprintAsString(x509Certificate3);
        final X509Certificate x509Certificate4 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date1hFromNow, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint4 = CertTools.getFingerprintAsString(x509Certificate4);
        try {
            // Persists self signed certificates
            internalCertStoreSession.storeCertificateNoAuth(alwaysAllowToken, x509Certificate1, USERNAME, fingerprint1, CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, now);
            internalCertStoreSession.storeCertificateNoAuth(alwaysAllowToken, x509Certificate2, USERNAME, fingerprint2, CertificateConstants.CERT_ARCHIVED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, now);
            internalCertStoreSession.storeCertificateNoAuth(alwaysAllowToken, x509Certificate3, USERNAME, fingerprint3, CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, now);
            internalCertStoreSession.storeCertificateNoAuth(alwaysAllowToken, x509Certificate4, USERNAME, fingerprint4, CertificateConstants.CERT_REVOKED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityInformation.NO_ENDENTITYPROFILE, null, now);
            // Check that the expected certificate are returned
            final List<CertificateDataWrapper> cdws1 = certificateStoreSession.getCertificateDataByUsername(USERNAME, false, null);
            assertTrue("Unfiltered result did not return all certificates for user.", isCertificatePresentInList(cdws1, fingerprint1, fingerprint2, fingerprint3, fingerprint4));
            final List<CertificateDataWrapper> cdws2 = certificateStoreSession.getCertificateDataByUsername(USERNAME, false, Arrays.asList(CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION));
            assertTrue("Expected active certificate to not be returned", isCertificatePresentInList(cdws2, fingerprint2, fingerprint4));
            final List<CertificateDataWrapper> cdws3 = certificateStoreSession.getCertificateDataByUsername(USERNAME, true, null);
            assertTrue("Expected expired certificate to not be returned", isCertificatePresentInList(cdws3, fingerprint1, fingerprint3, fingerprint4));
            final List<CertificateDataWrapper> cdws4 = certificateStoreSession.getCertificateDataByUsername(USERNAME, true, Arrays.asList(CertificateConstants.CERT_REVOKED));
            assertTrue("Expected expired and revoked certificate to not be returned", isCertificatePresentInList(cdws4, fingerprint1, fingerprint3));
        } finally {
            // Clean up
            internalCertStoreSession.removeCertificate(fingerprint1);
            internalCertStoreSession.removeCertificate(fingerprint2);
            internalCertStoreSession.removeCertificate(fingerprint3);
            internalCertStoreSession.removeCertificate(fingerprint4);
        }
        log.trace("<" + TEST_NAME);
    }
    private boolean isCertificatePresentInList(final List<CertificateDataWrapper> cdws, final String...expectedFingerprints) {
        final List<String> expectedFingerprintsList = Arrays.asList(expectedFingerprints);
        for (CertificateDataWrapper cdw  : cdws) {
            if (!expectedFingerprintsList.contains(cdw.getCertificateData().getFingerprint())) {
                log.debug("Certificate with status " + cdw.getCertificateData().getStatus() + " is missing! # of returned entries: " + cdws.size());
                return false;
            }
        }
        return cdws.size()==expectedFingerprints.length;
    }

	// Commented out code.
	// Keep it here, because it can be nice to have as a reference how this can be done.
	// Commented out though, since the issue is fixed and the method not available anymore.
//	@Test
//    public void testBlindSQLInjection_findExpirationInfo() throws Exception {
//		/* Vulnerability type : Blind SQL Injection
//	    First, certificatedata table in the database should not be empty in order to exploit the vulnerability
//		The PoC is : We inject a test checking if the database port is set to 3306 (@@global.port = 3306), the sub-query return TRUE and the query isn't affected. It will return some results. If we test a bad port value (@@global.port <> 3306), the full SQL query return null.*
//		
//		Replacing the basic port test by SELECT queries permit the attacker to dump the database.
//		*/
//		// Listing without cASelectString should return nothing
//		List<Object[]> result = certificateStoreSession.findExpirationInfo(null, 1, 1, 1);
//		assertEquals("Result not returned", 0, result.size());
//		// Injecting our "always true" SQL returns values
//		result = certificateStoreSession.findExpirationInfo("1=1) OR (1=1", 1, 1, 1);
//		assertTrue("Result returned", result.size()>0);
//	}
	
    private X509Certificate generateCert(final AuthenticationToken admin, final int status) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            SignatureException, InvalidKeyException, CreateException, AuthorizationDeniedException, IllegalStateException, OperatorCreationException, CertificateException, IOException {
        // create a new self signed certificate
        GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foobar.bar.com");
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(Extension.subjectAlternativeName, false, san);
        Extension sanExtension = extgen.generate().getExtension(Extension.subjectAlternativeName);
        List<Extension> additionalExtensions = new ArrayList<>();
        additionalExtensions.add(sanExtension);
        
        X509Certificate xcert = CertTools.genSelfCertForPurpose("C=SE,O=PrimeKey,OU=TestCertificateData,CN=MyNameIsFoo", 24, null, keys.getPrivate(), 
        		keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false, 0, null, null, BouncyCastleProvider.PROVIDER_NAME, true, additionalExtensions);
        String fp = CertTools.getFingerprintAsString(xcert);

        Certificate ce = certificateStoreSession.findCertificateByFingerprint(fp);
        if (ce != null) {
            assertTrue("Certificate with fp=" + fp + " already exists in db, very strange since I just generated it.", false);
        }
        certificateStoreSession.storeCertificateRemote(admin, EJBTools.wrap(xcert), USERNAME, "1234", status, CertificateConstants.CERTTYPE_ENDENTITY,
        		CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityInformation.NO_ENDENTITYPROFILE, "footag", new Date().getTime());
        return xcert;
    }

}
