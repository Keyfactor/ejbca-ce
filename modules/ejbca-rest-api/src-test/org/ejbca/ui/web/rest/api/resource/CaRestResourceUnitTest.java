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

import static org.easymock.EasyMock.*;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonExceptionErrorResponse;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.Base64;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaCrlSearchRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.config.JsonDateSerializer;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.jboss.resteasy.client.ClientResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A unit test class for CaRestResource to test its content.
 * <br/>
 * The testing is organized through deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 *
 * @version $Id: CaInfoConverterUnitTest.java 29080 2018-05-31 11:12:13Z andrey_s_helmes $
 */
@RunWith(EasyMockRunner.class)
public class CaRestResourceUnitTest {

    private static final String JSON_PROPERTY_CERTIFICATE_AUTHORITIES = "certificate_authorities";
    private static final DateFormat DATE_FORMAT_ISO8601 = JsonDateSerializer.DATE_FORMAT_ISO8601;

    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));
    // Extend class to test without security
    private static class CaRestResourceWithoutSecurity extends CaRestResource {
        @Override
        protected AuthenticationToken getAdmin(final HttpServletRequest requestContext, final boolean allowNonAdmins) {
            return authenticationToken;
        }
    }
    static InMemoryRestServer server;
    private static final JSONParser jsonParser = new JSONParser();

    @TestSubject
    private static CaRestResource testClass = new CaRestResourceWithoutSecurity();
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
        final String expectedRevision = "ALPHA";
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/ca/status").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }

    @Test
    public void shouldReturnEmptyListOfCas() throws Exception {
        // given
        expect(raMasterApiProxy.getAuthorizedCAInfos(authenticationToken)).andReturn(new IdNameHashMap<CAInfo>());
        replay(raMasterApiProxy);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/ca").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificateAuthorities = (JSONArray)actualJsonObject.get(JSON_PROPERTY_CERTIFICATE_AUTHORITIES);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertNotNull(actualCertificateAuthorities);
        assertEquals(0, actualCertificateAuthorities.size());
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnListOfCasWithOneProperCa() throws Exception {
        // given
        final String expectedSubjectDn = CaInfoBuilder.TEST_CA_SUBJECT_DN;
        final String expectedName = CaInfoBuilder.TEST_CA_NAME;
        final int expectedId = 11;
        final String expectedIssuerDn = CaInfoBuilder.TEST_CA_ISSUER_DN;
        final Date expectedExpirationDate = new Date();
        final String expectedExpirationDateString = DATE_FORMAT_ISO8601.format(expectedExpirationDate);
        final CAInfo cAInfo = CaInfoBuilder.builder()
                .id(expectedId)
                .expirationDate(expectedExpirationDate)
                .build();
        final IdNameHashMap<CAInfo> caInfosMap = new IdNameHashMap<>();
        caInfosMap.put(expectedId, expectedName, cAInfo);
        expect(raMasterApiProxy.getAuthorizedCAInfos(authenticationToken)).andReturn(caInfosMap);
        replay(raMasterApiProxy);
        // when
        final ClientResponse<?> actualResponse = server.newRequest("/v1/ca").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificateAuthorities = (JSONArray)actualJsonObject.get(JSON_PROPERTY_CERTIFICATE_AUTHORITIES);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertNotNull(actualCertificateAuthorities);
        assertEquals(1, actualCertificateAuthorities.size());
        final JSONObject actualCaInfo0JsonObject = (JSONObject) actualCertificateAuthorities.get(0);
        final Object actualId = actualCaInfo0JsonObject.get("id");
        final Object actualName = actualCaInfo0JsonObject.get("name");
        final Object actualSubjectDn = actualCaInfo0JsonObject.get("subject_dn");
        final Object actualIssuerDn = actualCaInfo0JsonObject.get("issuer_dn");
        final Object actualExpirationDateString = actualCaInfo0JsonObject.get("expiration_date");
        assertNotNull(actualId);
        assertEquals((long) expectedId, actualId);
        assertNotNull(actualName);
        assertEquals(expectedName, actualName);
        assertNotNull(actualSubjectDn);
        assertEquals(expectedSubjectDn, actualSubjectDn);
        assertNotNull(actualIssuerDn);
        assertEquals(expectedIssuerDn, actualIssuerDn);
        assertNotNull(actualExpirationDateString);
        assertEquals(expectedExpirationDateString, actualExpirationDateString);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldThrowExceptionOnNonExistingCa() throws Exception {
        // given
        final String expectedMessage = "CA doesn't exist";
        final long expectedCode = Response.Status.NOT_FOUND.getStatusCode();
        // when
        expect(raMasterApiProxy.getCertificateChain(eq(authenticationToken), anyInt())).andThrow(new CADoesntExistsException(expectedMessage));
        replay(raMasterApiProxy);
        final ClientResponse<?> actualResponse = server.newRequest("/v1/ca/CN=Ca name/certificate/download").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        // then
        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJsonString);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnCaCertificateAsPem() throws Exception {
        // given
        final Certificate certificate = getCertificate();
        final CertificateWrapper certificateWrapper = EJBTools.wrap(certificate);
        final List<CertificateWrapper> certificates = Collections.singletonList(certificateWrapper);
        
        // when
        expect(raMasterApiProxy.getCertificateChain(eq(authenticationToken), anyInt())).andReturn(certificates);
        replay(raMasterApiProxy);
        final ClientResponse<?> actualResponse = server.newRequest("/v1/ca/CN=Ca name/certificate/download").get();
        final String actualString = actualResponse.getEntity(String.class);
        // then
        assertTrue(actualString.contains(CertTools.BEGIN_CERTIFICATE));
        assertTrue(actualString.contains(CertTools.END_CERTIFICATE));
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnLatestCrlIssuedByCa() throws Exception {
        // given
        final String expectedCertificate = "Certificate";

        // when
        expect(raMasterApiProxy.getLatestCrlByRequest(eq(authenticationToken), anyObject(RaCrlSearchRequest.class))).andReturn(expectedCertificate.getBytes());
        replay(raMasterApiProxy);
        final ClientResponse<?> actualResponse = server.newRequest("/v1/ca/Ca name/getLatestCrl").get();
        final String actualString = actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualString);
        final String actualCertificate = (String)actualJsonObject.get("crl");
        final byte[] decoded = Base64.decodeBase64(actualCertificate);
        final String decodedActualCertificate = new String(decoded, "utf-8");

        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertNotNull(actualCertificate);
        assertEquals(expectedCertificate, decodedActualCertificate);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldThrowExceptionCaNotExistForLatestCaCrl() throws Exception {
        // given
        final String expectedMessage = "CA doesn't exist";
        final long expectedCode = Response.Status.NOT_FOUND.getStatusCode();
        // when
        expect(raMasterApiProxy.getLatestCrlByRequest(eq(authenticationToken), anyObject(RaCrlSearchRequest.class))).andThrow(new CADoesntExistsException(expectedMessage));
        replay(raMasterApiProxy);
        final ClientResponse<?> actualResponse = server.newRequest("/v1/ca/Ca name/getLatestCrl").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        // then
        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonExceptionErrorResponse(expectedCode, expectedMessage, actualJsonString);
        verify(raMasterApiProxy);
    }

    private Certificate getCertificate() {
        return new Certificate("") {

            @Override
            public byte[] getEncoded() {
                return getType().getBytes();
            }

            @Override
            public void verify(final PublicKey key) {
            }

            @Override
            public void verify(final PublicKey key, final String sigProvider) {
            }

            @Override
            public String toString() {
                return null;
            }

            @Override
            public PublicKey getPublicKey() {
                return null;
            }
        };
    }
}
