/*************************************************************************
 *                                                                       *
 *  EJBCA: Enterprise Certificate Authority                              *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *                                                                       *
 *************************************************************************/ 
package org.ejbca.database;

import static org.junit.Assert.assertTrue;

import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateData;
import org.junit.Before;
import org.junit.Test;

/**
 * Injects different kind of errors in the OCSP responder "ocsp1" and tries to detect them
 * by calling the OCSP monitoring tool.
 * 
 * @version $Id$
 */
public class OcspMonitoringToolTest {

	private static final Logger log = Logger.getLogger(OcspMonitoringToolTest.class);
    private static final String[] args = {"ocspmon", "all", "1000", "60", "1", "9", "-", "ca", "ocsp1"};
	
	private final EntityManager ocspEntityManager = Persistence.createEntityManagerFactory("ocsp1").createEntityManager();
	
	@Before
	public void setUp() throws Exception { }

	/**
	 * 	Run a test to see that the databases made available for testing is equal
	 */
	@Test
	public void test01RunOnOkDatabases() throws Exception {
		log.trace(">test01RunOnOkDatabases");
		assertTrue("This test assumes that you have two configured databases ca and ocsp1 that are identical with only certs from certificateProfileId 1 and 9 .",
				new OcspMonitoringTool().executeInternal(args) == 0);
		log.trace("<test01RunOnOkDatabases");
	}

	/**
	 * (Save) and remove first from OCSP, run test, restore first
	 * (Save) and remove middle from OCSP, run test, restore middle
	 * (Save) and remove last from OCSP, run test, restore last
	 */
	@Test
	public void test02DetectRemovedEntries() throws Exception {
		log.trace(">test02DetectRemovedEntries");
		//ocspEntityManager.setFlushMode(FlushModeType.AUTO);
		Query query = ocspEntityManager.createQuery("select a from CertificateData a WHERE a.certificateProfileId=:certificateProfileId order by a.fingerprint asc");
		query.setParameter("certificateProfileId", 1);
		query.setMaxResults(2);
		@SuppressWarnings("unchecked")
        List<CertificateData> certificateDataList = query.getResultList();
		CertificateData certificateData1 = certificateDataList.get(0);
		CertificateData certificateData2 = certificateDataList.get(1);
		query = ocspEntityManager.createQuery("select a from CertificateData a WHERE a.certificateProfileId=:certificateProfileId order by a.fingerprint desc");
		query.setParameter("certificateProfileId", 1);
		query.setMaxResults(1);
		CertificateData certificateData3 = (CertificateData) query.getSingleResult();

		final EntityTransaction transaction1 = ocspEntityManager.getTransaction();
		transaction1.begin();
		ocspEntityManager.remove(certificateData1);
		transaction1.commit();
		assertTrue("Failed to remove certificate from OCSP. Test is broken.", ocspEntityManager.find(CertificateData.class, certificateData1.getFingerprint())==null);
		int result = new OcspMonitoringTool().executeInternal(args);
        final EntityTransaction transaction2 = ocspEntityManager.getTransaction();
        transaction2.begin();
        ocspEntityManager.persist(certificateData1);
        transaction2.commit();
		assertTrue("Did not detect missing first cert.", result == -1);
		
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.remove(certificateData2);
		ocspEntityManager.getTransaction().commit();
		result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.persist(certificateData2);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect missing second cert.", result == -1);
		
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.remove(certificateData3);
		ocspEntityManager.getTransaction().commit();
		result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.persist(certificateData3);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect missing last cert.", result == -1);

		log.trace("<test02DetectRemovedEntries");
	}

	/**
	 * Insert fake first in OCSP, run test, remove fake
	 * Insert fake in the middle of OCSP, run test, remove fake
	 * Insert fake last in OCSP, run test, remove fake
	 */
	@Test
	public void test03DetectAddedFakes() throws Exception {
		log.trace(">test03DetectAddedFakes");
		Query query = ocspEntityManager.createQuery("select a from CertificateData a WHERE a.certificateProfileId=:certificateProfileId");
		query.setParameter("certificateProfileId", 1);
		query.setMaxResults(1);
		CertificateData fakeCertificateData = (CertificateData) query.getSingleResult();
		ocspEntityManager.clear();	// Detach

		fakeCertificateData.setFingerprint("0000000000000000000000000000000000000000");
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.persist(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		int result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.remove(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect fake first cert.", result == -1);

		fakeCertificateData.setFingerprint("8000000000000000000000000000000000000000");
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.persist(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.remove(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect fake middle cert.", result == -1);
		
		fakeCertificateData.setFingerprint("ffffffffffffffffffffffffffffffffffffffff");
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.persist(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.remove(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect fake last cert.", result == -1);
		
		log.trace(">test03DetectAddedFakes");
	}

	/**
	 * Modify an entity in OCSP: keep updateTime
	 * Modify an entity in OCSP: set updateTime < current updateTime
	 * Modify an entity in OCSP: set updateTime > current updateTime
	 * Modify an entity in OCSP: set updateTime = now
	 */
	@Test
	public void test04DetectTampering() throws Exception {
		log.trace(">test04DetectTampering");
		ocspEntityManager.getTransaction().begin();
		CertificateData certificateData = CertificateData.getNextBatch(ocspEntityManager, 1, "8", 1).get(0);
		long updateTime = certificateData.getUpdateTime();
		String serialNumber = certificateData.getSerialNumber();
		
		certificateData.setSerialNumber("0");
		certificateData.setUpdateTime(updateTime);
		ocspEntityManager.getTransaction().commit();
		int result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		certificateData.setSerialNumber(serialNumber);
		certificateData.setUpdateTime(updateTime);
		ocspEntityManager.merge(certificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect modified cert.", result == -1);
		
		ocspEntityManager.getTransaction().begin();
		certificateData.setSerialNumber("0");
		certificateData.setUpdateTime(updateTime-1000);
		ocspEntityManager.merge(certificateData);
		ocspEntityManager.getTransaction().commit();
		result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		certificateData.setSerialNumber(serialNumber);
		certificateData.setUpdateTime(updateTime);
		ocspEntityManager.merge(certificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect modified cert.", result == -1);
		
		ocspEntityManager.getTransaction().begin();
		certificateData.setSerialNumber("0");
		certificateData.setUpdateTime(updateTime+1000);
		ocspEntityManager.merge(certificateData);
		ocspEntityManager.getTransaction().commit();
		result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		certificateData.setSerialNumber(serialNumber);
		certificateData.setUpdateTime(updateTime);
		ocspEntityManager.merge(certificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect modified cert.", result == -1);

		ocspEntityManager.getTransaction().begin();
		certificateData.setSerialNumber("0");
		certificateData.setUpdateTime(new Date().getTime());
		ocspEntityManager.merge(certificateData);
		ocspEntityManager.getTransaction().commit();
		result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		certificateData.setSerialNumber(serialNumber);
		certificateData.setUpdateTime(updateTime);
		ocspEntityManager.merge(certificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did not detect modified cert.", result == -1);

		log.trace("<test04DetectTampering");
	}

	/**
	 * Insert fake in OCSP with different certificateProfileId, run test and don't detect, remove fake
	 */
	@Test
	public void test05OnlyCheckSpecifiedProfileIds() throws Exception {
		log.trace(">test05OnlyCheckSpecifiedProfileIds");
		Query query = ocspEntityManager.createQuery("select a from CertificateData a WHERE a.certificateProfileId=:certificateProfileId");
		query.setParameter("certificateProfileId", 1);
		query.setMaxResults(1);
		CertificateData fakeCertificateData = (CertificateData) query.getSingleResult();
		ocspEntityManager.clear();	// Detach

		ocspEntityManager.getTransaction().begin();
		fakeCertificateData.setFingerprint("8000000000000000000000000000000000000000");
		fakeCertificateData.setCertificateProfileId(123456);
		ocspEntityManager.persist(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		int result = new OcspMonitoringTool().executeInternal(args);
		ocspEntityManager.getTransaction().begin();
		ocspEntityManager.remove(fakeCertificateData);
		ocspEntityManager.getTransaction().commit();
		assertTrue("Did detect fake cert for unchecked certificate profile.", result == 0);

		log.trace("<test05OnlyCheckSpecifiedProfileIds");
	}
}
