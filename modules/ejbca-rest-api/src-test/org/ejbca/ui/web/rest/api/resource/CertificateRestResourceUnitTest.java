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

import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.keyfactor.util.CertTools;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.config.JsonDateSerializer;
import org.ejbca.ui.web.rest.api.resource.swagger.CertificateRestResourceSwagger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.keyfactor.util.EJBTools;

/**
 * A unit test class for CertificateRestResource to test its content.
 * <br/>
 * The testing is organized through deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 */
@RunWith(EasyMockRunner.class)
public class CertificateRestResourceUnitTest {

    private static final DateFormat DATE_FORMAT_ISO8601 = JsonDateSerializer.DATE_FORMAT_ISO8601;
    private static final JSONParser jsonParser = new JSONParser();
    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));
    private static final String testCertPem = "-----BEGIN CERTIFICATE-----\n"
        + "MIID+zCCAuOgAwIBAgIULyZUBiXtcmi2U6C4maDQLnvei5swDQYJKoZIhvcNAQEL\n"
        + "BQAwYDEVMBMGA1UEBhMMVVMgSXNzdWVyIEROMRIwEAYDVQQKDAlNYXJrIFRlc3Qx\n"
        + "IjAgBgNVBAsMGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxDzANBgNVBAMMBlN1\n"
        + "YiBDQTAeFw0yMTA0MTMxNjMzMzlaFw0yMzA0MTMxNjMwMjRaMIGNMQswCQYDVQQG\n"
        + "EwJVUzESMBAGA1UECgwJTWFyayBUZXN0MQ4wDAYDVQQLDAVVc2VyczEUMBIGA1UE\n"
        + "AwwLTWFyayBXcmlnaHQxGzAZBgoJkiaJk/IsZAEBDAttYXJrLndyaWdodDEnMCUG\n"
        + "CSqGSIb3DQEJARYYbWFyay53cmlnaHRAcHJpbWVrZXkuY29tMIIBIjANBgkqhkiG\n"
        + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEApsNL/Qu/aqJ0yd2rgByVap9rcwXrHZ/mCcgK\n"
        + "KKyV66vhzrMD+coRtEWui5rllaTFI+xjLWDTAFb5JBvV+XOODoa1+uh7nuLSTBed\n"
        + "VLuP6ob/THXh6HWyyh/wxrQPXg1XWJQn2aVE51aWuX8A7l6OSTjoDyYAZceExMEk\n"
        + "UV2mHJzhMREnKg+f3kCciECvrybq7WCY1D+nS4ZjjBJw9fBGQ8Ro+VT8MbviRgR4\n"
        + "TxXK/Y9SXBjJkTWnSmPA5WaBCzaBBXFWN8QIoJ7Sz6HggMgki0bk41Y1uDq36pdX\n"
        + "bmlDBrluOH5/HtzYSKvq4uwof53CDpRGQ/Q9uwn4gmBRb/jS9QIDAQABo38wfTAM\n"
        + "BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFPTX2DmjnQzcD6Ebs3tXG2aIxoohMB0G\n"
        + "A1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAdBgNVHQ4EFgQUXqZ5qPc4trDJ\n"
        + "s793/9j7ztJOzYEwDgYDVR0PAQH/BAQDAgXgMA0GCSqGSIb3DQEBCwUAA4IBAQCC\n"
        + "+T1gklNgSMe7XutXvlz6/reCbr3oUviy/UkggySffqnodsCQGhq22TlUtrifU7MD\n"
        + "Nv++8cl4PBpdzgom29rPE6JkkfKfpJkRX0LnXQvTQKqDQW/m8tLExRniJ9BlH47w\n"
        + "8YCE5II3oazsl7cUqn6OZWjVxysiOVE34gzDusJFSXQpL6VDjtXL6lw9tmOgYOp7\n"
        + "BI7RwzkzsIXinbvq3SloBcDEeXFeogJ43cdXn2rui6n/wdGBfJAnZKfOQFQcz9GY\n"
        + "7rhOXJyrdmQ3FTgQobnP55mvMLdVFukRfHyHmwr01sKcA474AtpWgIY5TcVzCyUJ\n"
        + "imu7R06cjtJpdhQBJHgF\n"
        + "-----END CERTIFICATE-----\n";
    // Extend class to test without security
    private static class CertificateRestResourceWithoutSecurity extends CertificateRestResourceSwagger {
        @Override
        protected AuthenticationToken getAdmin(HttpServletRequest requestContext, boolean allowNonAdmins) {
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
        final Invocation.Builder request = server.newRequest("/v1/certificate/status").request();
        final Response actualResponse = request.get();
        final String actualJsonString = actualResponse.readEntity(String.class);
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
        final Date expectedRevocationDate = new Date();
        final String expectedRevocationDateString = DATE_FORMAT_ISO8601.format(expectedRevocationDate);
        final RevocationReasons revocationReason = RevocationReasons.KEYCOMPROMISE;
        final CertificateStatus response = new CertificateStatus("REVOKED", expectedRevocationDate.getTime(), revocationReason.getDatabaseValue(), 123456);
        // when
        final Capture<CertRevocationDto> capturedDto = EasyMock.newCapture();
        raMasterApiProxy.revokeCertWithMetadata(anyObject(AuthenticationToken.class), capture(capturedDto));
        EasyMock.expectLastCall().andVoid();
        expect(raMasterApiProxy.getCertificateStatus(anyObject(AuthenticationToken.class), anyString(), anyObject(BigInteger.class))).andReturn(response);
        replay(raMasterApiProxy);
        final Invocation.Builder request = server
                .newRequest("/v1/certificate/CN=TestCa/1a2b3c/revoke")
                .queryParam("reason", revocationReason.getStringValue())
                .queryParam("date", expectedRevocationDateString)
                .request();
        final Entity<String> entity = Entity.text("");
        final Response actualResponse = request.put(entity);
        final String actualJsonString = actualResponse.readEntity(String.class);

        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals(expectedMessage, actualJsonObject.get("message"));
        assertEquals(expectedRevoked, actualJsonObject.get("revoked"));
        assertEquals(expectedSerialNumber, actualJsonObject.get("serial_number"));
        assertEquals(expectedRevocationDateString, actualJsonObject.get("revocation_date"));
        verify(raMasterApiProxy);
        assertTrue(capturedDto.hasCaptured());
        final CertRevocationDto certRevocationMetadata = capturedDto.getValue();
        assertEquals("CN=TestCa", certRevocationMetadata.getIssuerDN());
        assertEquals(expectedSerialNumber, certRevocationMetadata.getCertificateSN());
        assertEquals(Integer.valueOf(revocationReason.getDatabaseValue()), certRevocationMetadata.getReason());
    }

    /** Tests a change of invalidity date of an already revoked certificate */
    @Test
    public void shouldReturnProperStatusOnCertificateInvalidityDateChange() throws Exception {
        // given
        final int expectedCode = Status.OK.getStatusCode();
        final String expectedMessage = "Successfully revoked";
        final boolean expectedRevoked = true;
        final String expectedSerialNumber = "1a2b3c";
        final Date expectedRevocationDate = new Date();
        final String expectedInvalidityDateString = "2023-01-02T12:34:56Z";
        final String expectedRevocationDateString = DATE_FORMAT_ISO8601.format(expectedRevocationDate);
        final RevocationReasons revocationReason = RevocationReasons.KEYCOMPROMISE;
        final CertificateStatus response = new CertificateStatus("REVOKED", expectedRevocationDate.getTime(), revocationReason.getDatabaseValue(), 123456);
        // when
        expect(raMasterApiProxy.getCertificateStatus(anyObject(AuthenticationToken.class), anyString(), anyObject(BigInteger.class))).andReturn(response);
        final Capture<CertRevocationDto> capturedDto = EasyMock.newCapture();
        raMasterApiProxy.revokeCertWithMetadata(anyObject(AuthenticationToken.class), capture(capturedDto));
        EasyMock.expectLastCall().andVoid();
        expect(raMasterApiProxy.getCertificateStatus(anyObject(AuthenticationToken.class), anyString(), anyObject(BigInteger.class))).andReturn(response);
        replay(raMasterApiProxy);
        final Invocation.Builder request = server
                .newRequest("/v1/certificate/CN=TestCa/1a2b3c/revoke")
                .queryParam("invalidity_date", expectedInvalidityDateString)
                .queryParam("date", expectedRevocationDateString)
                .request();
        final Entity<String> entity = Entity.text("");
        final Response actualResponse = request.put(entity);
        final String actualJsonString = actualResponse.readEntity(String.class);

        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        // then
        assertEquals(expectedCode, actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertEquals(expectedMessage, actualJsonObject.get("message"));
        assertEquals(expectedRevoked, actualJsonObject.get("revoked"));
        assertEquals(expectedSerialNumber, actualJsonObject.get("serial_number"));
        assertEquals(expectedRevocationDateString, actualJsonObject.get("revocation_date"));
        assertEquals(expectedInvalidityDateString, actualJsonObject.get("invalidity_date"));
        verify(raMasterApiProxy);
        assertTrue(capturedDto.hasCaptured());
        final CertRevocationDto certRevocationMetadata = capturedDto.getValue();
        assertEquals("CN=TestCa", certRevocationMetadata.getIssuerDN());
        assertEquals(expectedSerialNumber, certRevocationMetadata.getCertificateSN());
        assertEquals(Integer.valueOf(revocationReason.getDatabaseValue()), certRevocationMetadata.getReason());
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
        final Invocation.Builder request = server
                .newRequest("/v1/certificate/expire")
                .queryParam("days", days)
                .queryParam("offset", offset)
                .queryParam("maxNumberOfResults", maxNumberOfResults)
                .request();
        final Response actualResponse = request.get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final int actualStatus = actualResponse.getStatus();
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final boolean moreResults  = (Boolean) ((JSONObject)actualJsonObject.get("pagination_rest_response_component")).get("more_results");
        // then
        assertEquals(Status.OK.getStatusCode(), actualStatus);
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

        final Certificate testCertificate = CertTools.getCertsFromPEM(new ByteArrayInputStream(testCertPem.getBytes()), X509Certificate.class).get(0);
        Collection<Certificate> certificates = List.of(testCertificate, testCertificate, testCertificate, testCertificate);
        expect(raMasterApiProxy.getCertificatesByExpirationTime(anyObject(AuthenticationToken.class), eq(days), eq(maxNumberOfResults), eq(offset)))
                        .andReturn(EJBTools.wrapCertCollection(certificates));

        replay(raMasterApiProxy);

        // when
        final Invocation.Builder request = server
                .newRequest("/v1/certificate/expire")
                .queryParam("days", days)
                .queryParam("offset", offset)
                .queryParam("maxNumberOfResults", maxNumberOfResults)
                .request();
        final Response actualResponse = request.get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final int actualStatus = actualResponse.getStatus();
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject responseStatus = (JSONObject) actualJsonObject.get("pagination_rest_response_component");
        final boolean moreResults  = (Boolean) responseStatus.get("more_results");
        final long nextOffset  = (Long) responseStatus.get("next_offset");
        final long numberOfResults  = (Long) responseStatus.get("number_of_results");
        // then
        assertEquals(Status.OK.getStatusCode(), actualStatus);
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

        final Certificate testCertificate = CertTools.getCertsFromPEM(new ByteArrayInputStream(testCertPem.getBytes()), X509Certificate.class).get(0);
        Collection<Certificate> certificates = List.of(testCertificate, testCertificate, testCertificate, testCertificate);
        expect(raMasterApiProxy.getCertificatesByExpirationTime(anyObject(AuthenticationToken.class), eq(days), eq(maxNumberOfResults), eq(offset)))
                        .andReturn(EJBTools.wrapCertCollection(certificates));
        replay(raMasterApiProxy);
        // when
        final Invocation.Builder request = server
                .newRequest("/v1/certificate/expire")
                .queryParam("days", days)
                .queryParam("offset", offset)
                .queryParam("maxNumberOfResults", maxNumberOfResults)
                .request();
        final Response actualResponse = request.get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final int actualStatus = actualResponse.getStatus();
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONObject responseStatus = (JSONObject) actualJsonObject.get("pagination_rest_response_component");
        final boolean moreResults  = (Boolean) responseStatus.get("more_results");
        final long nextOffset  = (Long) responseStatus.get("next_offset");
        final long numberOfResults  = (Long) responseStatus.get("number_of_results");
        // then
        assertEquals(Status.OK.getStatusCode(), actualStatus);
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

        final Invocation.Builder request = server
                .newRequest("/v1/certificate/testca/123456/revocationstatus")
                .request();
        final Response actualResponse = request.get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        final int actualStatus = actualResponse.getStatus();
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final boolean actualRevocationStatus = (boolean) actualJsonObject.get("revoked");
        final String actualRevocationReason = (String) actualJsonObject.get("revocation_reason");
        // then
        assertEquals(Status.OK.getStatusCode(), actualStatus);
        assertEquals(true, actualRevocationStatus);
        assertEquals(RevocationReasons.UNSPECIFIED.getStringValue(), actualRevocationReason);
        verify(raMasterApiProxy);
    }

    @Test
    public void inputBadSerialNrShouldReturnBadRequest() throws Exception {
        final String nonHexSerialNumberRequest = "/v1/certificate/testca/qwerty/revocationstatus";
        final Invocation.Builder request = server
                .newRequest(nonHexSerialNumberRequest)
                .request();
        final Response actualResponse = request.get();
        final int actualStatus = actualResponse.getStatus();
        assertEquals(Status.BAD_REQUEST.getStatusCode(), actualStatus);
    }
}
