/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import static org.easymock.EasyMock.anyBoolean;
import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.util.Collections;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response.Status;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.util.EJBTools;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.config.JsonDateSerializer;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A unit test class for CertificateRestResource to test its content.
 * <br/>
 * The testing is organized through deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @version $Id: CertificateRestResourceUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 */
@RunWith(EasyMockRunner.class)
public class CertificateRestResourceUnitTest {

    private static final DateFormat DATE_FORMAT_ISO8601 = JsonDateSerializer.DATE_FORMAT_ISO8601;
    private static final JSONParser jsonParser = new JSONParser();
    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));
    // Extend class to test without security
    private static class CertificateRestResourceWithoutSecurity extends CertificateRestResource {
        @Override
        protected AuthenticationToken getAdmin(final HttpServletRequest requestContext, final boolean allowNonAdmins, final String accessRuleType) {
            return authenticationToken;
        }
    }

    public static InMemoryRestServer server;

    @TestSubject
    private static CertificateRestResourceWithoutSecurity testClass = new CertificateRestResourceWithoutSecurity();

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApiProxy;

    @BeforeClass
    public static void beforeClass() throws IOException {
        server = InMemoryRestServer.create(testClass);
        server.start();
    }

    @AfterClass
    public static void afterClass() {
        server.close();
    }

    @Test
    public void shouldReturnProperStatus() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/certificate/status").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        // then
        assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }

    @Test
    public void shouldReturnProperStatusOnCertificateRevoke() throws Exception {
        // given
        final int expectedCode = Status.OK.getStatusCode();
        final String expectedMessage = "Successfully revoked";
        final boolean expectedRevoked = true;
        final String expectedSerialNumber = "1a2b3c";
        final String expectedRevocationDateString = DATE_FORMAT_ISO8601.format(new Date());
        // when
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        replay(raMasterApiProxy);
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/1a2b3c/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue())
                .queryParameter("date", expectedRevocationDateString);
        final ClientResponse<?> actualResponse = clientRequest.put();
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualMessage = actualJsonObject.get("message");
        final Object actualStatus = actualJsonObject.get("revoked");
        final Object actualSerialNumber = actualJsonObject.get("serial_number");
        final Object actualRevocationDate = actualJsonObject.get("revocation_date");
        // than
        assertEquals(expectedCode, actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals(expectedMessage, actualMessage);
        assertEquals(expectedRevoked, actualStatus);
        assertEquals(expectedSerialNumber, actualSerialNumber);
        assertEquals(expectedRevocationDateString, actualRevocationDate);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnNoMoreExpiredCertificates() throws Exception {
        // given
        final long days = 1;
        final int offset = 0;
        final int maxNumberOfResults = 0;
        expect(raMasterApiProxy.getCountOfCertificatesByExpirationTime(anyObject(AuthenticationToken.class), anyInt())).andReturn(0).times(1);
        expect(raMasterApiProxy.getCertificatesByExpirationTime(anyObject(AuthenticationToken.class), eq(days), eq(maxNumberOfResults), eq(offset)))
                        .andReturn(EJBTools.wrapCertCollection(Collections.<Certificate> emptyList()));

        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/expire")
                .queryParameter("days", days)
                .queryParameter("offset", offset)
                .queryParameter("maxNumberOfResults", maxNumberOfResults);
        final ClientResponse<?> actualResponse = clientRequest.get();
        final Status actualStatus = actualResponse.getResponseStatus();
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final boolean moreResults  = (Boolean) ((JSONObject)actualJsonObject.get("pagination_rest_response_component")).get("more_results");
        // then
        assertEquals(Status.OK, actualStatus);
        assertJsonContentType(actualResponse);
        assertFalse(moreResults);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnAreMoreResultsAndNextOffsetAndNumberOfResultsLeft() throws Exception {
        // given
        final long days = 1;
        final int offset = 0;
        final int maxNumberOfResults = 4;
        final long expectedNextOffset = 4L;
        final long expectedNumberOfResults = 6L;
        expect(raMasterApiProxy.getCountOfCertificatesByExpirationTime(anyObject(AuthenticationToken.class), anyInt())).andReturn(10).times(1);
        expect(raMasterApiProxy.getCertificatesByExpirationTime(anyObject(AuthenticationToken.class), eq(days), eq(maxNumberOfResults), eq(offset)))
                        .andReturn(EJBTools.wrapCertCollection(Collections.<Certificate> emptyList()));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/expire")
                .queryParameter("days", days)
                .queryParameter("offset", offset)
                .queryParameter("maxNumberOfResults", maxNumberOfResults);
        final ClientResponse<?> actualResponse = clientRequest.get();
        final Status actualStatus = actualResponse.getResponseStatus();
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject responseStatus = (JSONObject) actualJsonObject.get("pagination_rest_response_component");
        final boolean moreResults  = (Boolean) responseStatus.get("more_results");
        final long nextOffset  = (Long) responseStatus.get("next_offset");
        final long numberOfResults  = (Long) responseStatus.get("number_of_results");
        // then
        assertEquals(Status.OK, actualStatus);
        assertJsonContentType(actualResponse);
        assertTrue(moreResults);
        assertEquals(expectedNextOffset, nextOffset);
        assertEquals(expectedNumberOfResults, numberOfResults);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnAreMoreResultsAndNextOffsetAndNumberOfResultsLeftWithNotZeroOffset() throws Exception {
        // given
        final long days = 1;
        final int offset = 3;
        final int maxNumberOfResults = 4;
        final long expectedNextOffset = 7L;
        final long expectedNumberOfResults = 3L;
        expect(raMasterApiProxy.getCountOfCertificatesByExpirationTime(anyObject(AuthenticationToken.class), anyInt())).andReturn(10).times(1);
        expect(raMasterApiProxy.getCertificatesByExpirationTime(anyObject(AuthenticationToken.class), eq(days), eq(maxNumberOfResults), eq(offset)))
                        .andReturn(EJBTools.wrapCertCollection(Collections.<Certificate> emptyList()));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/expire")
                .queryParameter("days", days)
                .queryParameter("offset", offset)
                .queryParameter("maxNumberOfResults", maxNumberOfResults);
        final ClientResponse<?> actualResponse = clientRequest.get();
        final Status actualStatus = actualResponse.getResponseStatus();
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject responseStatus = (JSONObject) actualJsonObject.get("pagination_rest_response_component");
        final boolean moreResults  = (Boolean) responseStatus.get("more_results");
        final long nextOffset  = (Long) responseStatus.get("next_offset");
        final long numberOfResults  = (Long) responseStatus.get("number_of_results");
        // then
        assertEquals(Status.OK, actualStatus);
        assertJsonContentType(actualResponse);
        assertTrue(moreResults);
        assertEquals(expectedNextOffset, nextOffset);
        assertEquals(expectedNumberOfResults, numberOfResults);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnRevocationStatusRevokedWithReasonUnspecified() throws Exception {
        // given
        final int reasonUnspecified = 0;
        final CertificateStatus response = new CertificateStatus("REVOKED", new Date().getTime(), reasonUnspecified, 123456);
        expect(raMasterApiProxy.getCertificateStatus(anyObject(AuthenticationToken.class), anyString(), anyObject(BigInteger.class))).andReturn(response);
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/testca/123456/revocationstatus");
        final ClientResponse<?> actualResponse = clientRequest.get();
        final Status actualStatus = actualResponse.getResponseStatus();
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final boolean actualRevocationStatus = (boolean) actualJsonObject.get("revoked");
        final String actualRevocationReason = (String) actualJsonObject.get("revocation_reason");
        // then
        assertEquals(Status.OK, actualStatus);
        assertEquals(true, actualRevocationStatus);
        assertEquals(RevocationReasons.UNSPECIFIED.getStringValue(), actualRevocationReason);
        verify(raMasterApiProxy);
    }

    @Test
    public void inputBadSerialNrShouldReturnBadRequest() throws Exception {
        final String nonHexSerialNumberRequest = "/v1/certificate/testca/qwerty/revocationstatus";
        final ClientRequest clientRequest = server
                .newRequest(nonHexSerialNumberRequest);
        final ClientResponse<?> actualResponse = clientRequest.get();
        final Status actualStatus = actualResponse.getResponseStatus();
        assertEquals(Status.BAD_REQUEST, actualStatus);
    }
}