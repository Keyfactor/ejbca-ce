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
package org.ejbca.ui.web.rest.api.resource;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.InternalCertificateRestSessionLocal;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.resource.swagger.CertificateRestResourceV2Swagger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Optional;

import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.isNull;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.junit.Assert.assertEquals;

/**
 * A unit test class for {@link CertificateRestResourceV2} to test its content. <br/> The testing is organised through
 * deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 */
@RunWith(EasyMockRunner.class)
public class CertificateRestResourceV2UnitTest {

	private static final JSONParser jsonParser = new JSONParser();
	private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(
			new UsernamePrincipal("TestRunner"));

	private static class CertificateRestResourceWithoutSecurity extends CertificateRestResourceV2Swagger {
		@Override
		protected AuthenticationToken getAdmin(HttpServletRequest requestContext, boolean allowNonAdmins) {
			return authenticationToken;
		}
	}

	public static InMemoryRestServer server;

	@TestSubject
	private static final CertificateRestResourceWithoutSecurity TEST_CLASS = new CertificateRestResourceWithoutSecurity();

	@Mock
	private InternalCertificateRestSessionLocal certificateSessionLocal;

	@BeforeClass
	public static void beforeClass() throws IOException {
		server = InMemoryRestServer.create(TEST_CLASS);
		server.start();
	}

	@AfterClass
	public static void afterClass() {
		server.close();
	}

	@Test
	public void shouldGetCountOfAllTheIssuedCertificates() throws ParseException {
		// given
		final Long expectedCount = 3L;
		expect(certificateSessionLocal.getCertificateCount(isNull())).andReturn(expectedCount);
		replay(certificateSessionLocal);

		// when
		final Invocation.Builder request = server.newRequest("/v2/certificate/count").request();
		final Response actualResponse = request.get();
		final String actualJsonString = actualResponse.readEntity(String.class);
		final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
		final int actualStatus = actualResponse.getStatus();
		final Long certCount = (Long) actualJsonObject.get("count");

		// then
		verify(certificateSessionLocal);
		assertEquals(Optional.of(expectedCount), Optional.of(certCount));
		assertEquals(Response.Status.OK.getStatusCode(), actualStatus);
		assertJsonContentType(actualResponse);
	}

	@Test
	public void shouldGetCountOfActiveCertificates() throws ParseException {
		// given
		final Long expectedCount = 3L;
		expect(certificateSessionLocal.getCertificateCount(eq(Boolean.TRUE))).andReturn(expectedCount);
		replay(certificateSessionLocal);

		// when
		final Invocation.Builder request = server.newRequest("/v2/certificate/count?isActive=true").request();
		final Response actualResponse = request.get();
		final String actualJsonString = actualResponse.readEntity(String.class);
		final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
		final int actualStatus = actualResponse.getStatus();
		final Long certCount = (Long) actualJsonObject.get("count");

		// then
		verify(certificateSessionLocal);
		assertEquals(Optional.of(expectedCount), Optional.of(certCount));
		assertEquals(Response.Status.OK.getStatusCode(), actualStatus);
		assertJsonContentType(actualResponse);
	}
}
