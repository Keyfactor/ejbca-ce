/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

/**
 * The unit test for {@link InternalCertificateRestSessionBean}.
 */
@RunWith(EasyMockRunner.class)
public class InternalCertificateRestSessionBeanUnitTest {

	@Mock
	private CertificateDataSessionLocal certDataSession;

	@TestSubject
	private final InternalCertificateRestSessionBean certificateRestSessionBean = new InternalCertificateRestSessionBean();

	@Test
	public void shouldReturnQuantityOfAllCertificates() {
		//given
		final Long expectedQuantityOfCertificates = 5L;
		expect(certDataSession.findQuantityOfAllCertificates()).andReturn(expectedQuantityOfCertificates);
		replay(certDataSession);

		//when
		Long count = certificateRestSessionBean.getCertificateCount(null);

		//then
		verify(certDataSession);
		assertEquals(expectedQuantityOfCertificates, count);
	}

	@Test
	public void shouldReturnQuantityOfActiveCertificates() {
		//given
		final Long expectedQuantityOfCertificates = 3L;
		expect(certDataSession.findQuantityOfTheActiveCertificates()).andReturn(expectedQuantityOfCertificates);
		replay(certDataSession);

		//when
		Long count = certificateRestSessionBean.getCertificateCount(Boolean.TRUE);

		//then
		verify(certDataSession);
		assertEquals(expectedQuantityOfCertificates, count);
	}
}
