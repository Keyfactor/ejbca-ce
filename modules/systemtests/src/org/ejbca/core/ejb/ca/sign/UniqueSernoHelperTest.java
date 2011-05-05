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

package org.ejbca.core.ejb.ca.sign;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import junit.framework.Assert;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test the behavior of UniqueSernoHelper with help of a mock CertificateStoreSession.
 * (This is a unit test, but the test subject is currently a part of the EJB bundle.)
 * 
 * @version $Id$
 */
public class UniqueSernoHelperTest {

	private static final Logger log = Logger.getLogger(UniqueSernoHelperTest.class);
	private static final Class<?>[] cs = {CertificateStoreSession.class};
	// Error messages
	private static final String MOCKED_NO_INDEX_FAILED = "Mock of no index resulted in 'index present'.";
	private static final String MOCKED_INDEX_FAILED = "Mock of index resulted in 'no index present'.";
	private static final String NO_DATABASE_ERROR = "Was expecting a database error RuntimeException.";
	
	private static Certificate dummyCert = null;
	
	@BeforeClass
	public static void beforeClass() {
		CryptoProviderTools.installBCProvider();
	}
	
	/**
	 * Test case:
	 * - Both certs are present
	 * Expected result:
	 * - Index is not present
	 */
	@Test
	public void test01BothCertsPresent() throws Exception {
		log.trace(">test01BothCertsPresent");
		testInternal(false, new CertificateStoreSessionMock(getDummyCert(), getDummyCert(), null, null));
		log.trace("<test01BothCertsPresent");
	}

	/**
	 * Test case:
	 * - First cert is present, but not the second one.
	 * - Insert of (the second) certificate fails
	 * Expected result:
	 * - Index is present
	 */
	@Test
	public void test02FirstCertsPresent() throws Exception {
		log.trace(">test02BothCertsPresent");
		testInternal(true, new CertificateStoreSessionMock(getDummyCert(), null, new Exception(), null));
		log.trace("<test02BothCertsPresent");
	}

	/**
	 * Test case:
	 * - First cert is present, but not the second one.
	 * - Insert of (the second) certificate is successful
	 * Expected result:
	 * - Index is not present
	 */
	@Test
	public void test03FirstCertsPresent() throws Exception {
		log.trace(">test03BothCertsPresent");
		testInternal(false, new CertificateStoreSessionMock(getDummyCert(), null, true, true));
		log.trace("<test03BothCertsPresent");
	}

	/**
	 * Test case:
	 * - No cert is present
	 * - Insert of certificate fails
	 * Expected result:
	 * - RuntimeException
	 */
	@Test
	public void test04DatabaseError() throws Exception {
		log.trace(">test04DatabaseError");
		try {
			testInternal(false, new CertificateStoreSessionMock(null, null, new Exception(), null));
			Assert.fail(NO_DATABASE_ERROR);
		} catch (RuntimeException e) {
			log.debug("This is the expected Exception we get in case of database failure:", e);
		}
		log.trace("<test04DatabaseError");
	}

	/**
	 * Test case:
	 * - No cert is present
	 * - Insert of first certificate is successful
	 * - Insert of second certificate is successful
	 * Expected result:
	 * - Index is not present
	 */
	@Test
	public void test05NoCertsNoIndex() throws Exception {
		log.trace(">test05NoCertsNoIndex");
		testInternal(false, new CertificateStoreSessionMock(null, null, true, true));
		log.trace("<test05NoCertsNoIndex");
	}

	/**
	 * Test case:
	 * - No cert is present
	 * - Insert of first certificate is successful
	 * - Insert of second certificate is fails
	 * Expected result:
	 * - Index is present
	 */
	@Test
	public void test06NoCertsIndex() throws Exception {
		log.trace(">test06NoCertsIndex");
		testInternal(true, new CertificateStoreSessionMock(null, null, true, new Exception()));
		log.trace("<test06NoCertsIndex");
	}
	
	/** Reset the UniqueSernoHelper object and perform the test twice. */
	private void testInternal(final boolean indexExpectedToBePresent, final InvocationHandler certificateStoreSessionProxy) throws Exception {
		log.trace(">testInternal");
		final CertificateStoreSession certificateStoreSessionMock = (CertificateStoreSession) Proxy.newProxyInstance(CertificateStoreSession.class.getClassLoader(), cs, certificateStoreSessionProxy);
		UniqueSernoHelper.reset();
        // Multiple entries should give the same result, so we run the test twice
		if (indexExpectedToBePresent) {
			Assert.assertTrue(MOCKED_INDEX_FAILED, UniqueSernoHelper.isUniqueCertificateSerialNumberIndex(certificateStoreSessionMock));
			Assert.assertTrue(MOCKED_INDEX_FAILED, UniqueSernoHelper.isUniqueCertificateSerialNumberIndex(certificateStoreSessionMock));
		} else {
			Assert.assertFalse(MOCKED_NO_INDEX_FAILED, UniqueSernoHelper.isUniqueCertificateSerialNumberIndex(certificateStoreSessionMock));
			Assert.assertFalse(MOCKED_NO_INDEX_FAILED, UniqueSernoHelper.isUniqueCertificateSerialNumberIndex(certificateStoreSessionMock));
		}
		log.trace("<testInternal");
	}

	// This is the same as the first dummy cert used by UniqueSernoHelper.. does not really matter as long as it is a cert..
	private Certificate getDummyCert() throws CertificateException, NoSuchProviderException {
		if (dummyCert == null) {
			dummyCert = CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(Base64.decode(
					"MIIB8zCCAVygAwIBAgIESZYC0jANBgkqhkiG9w0BAQUFADApMScwJQYDVQQDDB5D"+
					"QSBmb3IgRUpCQ0EgdGVzdCBjZXJ0aWZpY2F0ZXMwHhcNMTAwNjI2MDU0OTM2WhcN"+
					"MjAwNjI2MDU0OTM2WjA1MTMwMQYDVQQDDCpBbGxvdyBjZXJ0aWZpY2F0ZSBzZXJp"+
					"YWwgbnVtYmVyIG92ZXJyaWRlIDEwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAnnIj"+
					"y8A6CJzASedM5MbZk/ld8R3P0aWfRSW2UUDaskm25oK5SsjwVZD3KEc3IJgyl1/D"+
					"lWdywxEduWwc2nzGGQIDAQABo2AwXjAdBgNVHQ4EFgQUPL3Au/wYZbD3TpNGW1G4"+
					"+Ck4A2swDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ/TRpUbLxt6j6EC3olHGWJ"+
					"7XZqETAOBgNVHQ8BAf8EBAMCBwAwDQYJKoZIhvcNAQEFBQADgYEAPMWjE5hv3G5T"+
					"q/fzPQlRMCQDoM5EgVwJYQu1S+wns/mKPI/bDv9s5nybKoro70LKpqLb1+f2TaD+"+
					"W2Ro+ni8zYm5+H6okXRIc5Kd4LlD3tjsOF7bS7fixvMCSCUgLxQOt2creOqfDVjm"+
					"i6MA48AhotWmx/rlzQXhnvuKnMI3m54="
			)));
		}
		return dummyCert;
	}

	/** Proxy class that mocks two consecutive interactions with CertificateStoreSession for find and store. */
	private class CertificateStoreSessionMock implements InvocationHandler {
		// Methods that we proxy to avoid having to care about when other methods change signature
		private static final String MOCKED_METHOD_FINDCERT = "findCertificateByFingerprint";
		private static final String MOCKED_METHOD_STORECERT = "storeCertificate";

		final Object findResult1;
		final Object findResult2;
		final Object storeResult1;
		final Object storeResult2;

		boolean firstFind = true;
		boolean firstStore = true;

		public CertificateStoreSessionMock(final Object findResult1, final Object findResult2, final Object storeResult1, final Object storeResult2) {
			this.findResult1 = findResult1;
			this.findResult2 = findResult2;
			this.storeResult1 = storeResult1;
			this.storeResult2 = storeResult2;
			// Verify that this proxy is valid, since we use method names as String objects.. (might have changed)
			boolean findPresent = false; 
			boolean storePresent = false; 
			for (final Method m : CertificateStoreSession.class.getDeclaredMethods()) {
				if (MOCKED_METHOD_FINDCERT.equals(m.getName())) {
					findPresent = true;
				} else if (MOCKED_METHOD_STORECERT.equals(m.getName())) {
					storePresent = true;
				}
			}
			if (!findPresent || !storePresent) {
				throw new RuntimeException("This test is no longer valid due to code changes.");
			}
		}
		
		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			final String methodName = method.getName();
			log.debug("proxy method invoked: " + methodName);
			Object result = null;
			if (MOCKED_METHOD_FINDCERT.equals(methodName)) {
				if (firstFind) {
					firstFind = false;
					result = findResult1;
				} else {
					result = findResult2;
				}
			} else if (MOCKED_METHOD_STORECERT.equals(methodName)) {
				if (firstStore) {
					firstStore = false;
					result = storeResult1;
				} else {
					result = storeResult2;
				}
			}
			if (result != null && result instanceof Throwable) {
				throw (Throwable) result;
			}
			return result;
		}
	}
}
