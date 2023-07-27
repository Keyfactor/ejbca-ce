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
package org.cesecore.certificates.certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cesecore.authorization.control.StandardRules.SYSTEMCONFIGURATION_VIEW;
import static org.cesecore.certificates.certificate.InternalCertificateRestSessionBean.ERROR_MESSAGE;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/**
 * The unit test for {@link InternalCertificateRestSessionBean}.
 */
@RunWith(EasyMockRunner.class)
public class InternalCertificateRestSessionBeanUnitTest {

	@Mock
	private CertificateDataSessionLocal certDataSession;

	@Mock
	private AuthorizationSessionLocal authorizationSession;

	@TestSubject
	private final InternalCertificateRestSessionBean certificateRestSessionBean = new InternalCertificateRestSessionBean();

	@Test
	public void shouldReturnQuantityOfAllCertificates() throws AuthorizationDeniedException {
		//given
		final Long expectedQuantityOfCertificates = 5L;
		AuthenticationToken token = createMock(AuthenticationToken.class);
		expect(authorizationSession.isAuthorized(eq(token), eq(SYSTEMCONFIGURATION_VIEW.resource()))).andReturn(true);
		expect(certDataSession.findQuantityOfAllCertificates()).andReturn(expectedQuantityOfCertificates);
		replay(certDataSession);
		replay(authorizationSession);

		//when
		Long count = certificateRestSessionBean.getCertificateCount(token, null);

		//then
		verify(certDataSession);
		verify(authorizationSession);
		assertEquals(expectedQuantityOfCertificates, count);
	}

	@Test
	public void shouldThrowAuthorizationDeniedException_WhenQueryingQuantityOfAllCertificates() {
		//given
		final Long expectedQuantityOfCertificates = 5L;
		AuthenticationToken token = createMock(AuthenticationToken.class);
		expect(authorizationSession.isAuthorized(eq(token), eq(SYSTEMCONFIGURATION_VIEW.resource()))).andReturn(false);
		expect(certDataSession.findQuantityOfTheActiveCertificates()).andReturn(expectedQuantityOfCertificates);
		replay(certDataSession);
		replay(authorizationSession);

		//when
		AuthorizationDeniedException exception = assertThrows(
				AuthorizationDeniedException.class,
				() -> certificateRestSessionBean.getCertificateCount(token, null)
		);

		//then
		verify(authorizationSession);
		assertEquals(String.format(ERROR_MESSAGE, token.toString()), exception.getMessage());
	}

	@Test
	public void shouldReturnQuantityOfActiveCertificates() throws AuthorizationDeniedException {
		//given
		final Long expectedQuantityOfCertificates = 3L;
		AuthenticationToken token = createMock(AuthenticationToken.class);
		expect(authorizationSession.isAuthorized(eq(token), eq(SYSTEMCONFIGURATION_VIEW.resource()))).andReturn(true);
		expect(certDataSession.findQuantityOfTheActiveCertificates()).andReturn(expectedQuantityOfCertificates);
		replay(certDataSession);
		replay(authorizationSession);

		//when
		Long count = certificateRestSessionBean.getCertificateCount(token, Boolean.TRUE);

		//then
		verify(certDataSession);
		verify(authorizationSession);
		assertEquals(expectedQuantityOfCertificates, count);
	}

	@Test
	public void shouldThrowAuthorizationDeniedException_WhenQueryingQuantityOfActiveCertificates() {
		//given
		final Long expectedQuantityOfCertificates = 3L;
		AuthenticationToken token = createMock(AuthenticationToken.class);
		expect(authorizationSession.isAuthorized(eq(token), eq(SYSTEMCONFIGURATION_VIEW.resource()))).andReturn(false);
		expect(certDataSession.findQuantityOfTheActiveCertificates()).andReturn(expectedQuantityOfCertificates);
		replay(certDataSession);
		replay(authorizationSession);

		//when
		AuthorizationDeniedException exception = assertThrows(
				AuthorizationDeniedException.class,
				() -> certificateRestSessionBean.getCertificateCount(token, Boolean.TRUE)
		);

		//then
		verify(authorizationSession);
		assertEquals(String.format(ERROR_MESSAGE, token.toString()), exception.getMessage());
	}
}
