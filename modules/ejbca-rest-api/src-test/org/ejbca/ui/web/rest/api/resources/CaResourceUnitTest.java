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
package org.ejbca.ui.web.rest.api.resources;

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.helpers.CADataBuilder;
import org.ejbca.ui.web.rest.api.types.CaInfoType;
import org.ejbca.ui.web.rest.api.types.CaInfoTypes;
import org.ejbca.ui.web.rest.api.types.RestServiceStatusType;
import org.jboss.resteasy.client.ClientResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


/**
 * A unit test class for CaResource to test its content.
 * <br/>
 * The testing is organized through deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 *
 * @version $Id: CaInfoConverterUnitTest.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
@RunWith(EasyMockRunner.class)
public class CaResourceUnitTest {

    public static InMemoryRestServer server;
    private static final JSONParser jsonParser = new JSONParser();

    @TestSubject
    private static CaResource testClass = new CaResource();
    @Mock
    private CaSessionLocal caSessionMock;

    @BeforeClass
    public static void beforeClass() throws IOException {
        server = InMemoryRestServer.create(testClass);
        server.start();
    }

    @AfterClass
    public static void afterClass() {
        server.close();
    }

    @SuppressWarnings("unchecked")
    private String getContentType(final ClientResponse clientResponse) {
        final MultivaluedMap<String, String> headersMap = clientResponse.getHeaders();
        if (headersMap != null) {
            return headersMap.getFirst("Content-type");
        }
        return null;
    }

    @Test
    public void shouldReturnProperStatus() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = "ALPHA";
        // when
        final ClientResponse actualResponse = server.newRequest("/v1/ca/status").get();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualStatus = actualJsonObject.get("status");
        final Object actualVersion = actualJsonObject.get("version");
        final Object actualRevision = actualJsonObject.get("revision");
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualStatus);
        assertEquals(expectedStatus, actualStatus);
        assertNotNull(actualVersion);
        assertEquals(expectedVersion, actualVersion);
        assertNotNull(actualRevision);
        assertEquals(expectedRevision, actualRevision);
    }

    @Test
    public void shouldReturnEmptyListOfCas() throws Exception {
        // given
        expect(caSessionMock.findAll()).andReturn(Collections.<CAData>emptyList());
        replay(caSessionMock);
        // when
        final ClientResponse actualResponse = server.newRequest("/v1/ca").get();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificateAuthorities = (JSONArray)actualJsonObject.get("certificateAuthorities");
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualCertificateAuthorities);
        assertEquals(0, actualCertificateAuthorities.size());
        verify(caSessionMock);
    }

    @Test
    public void shouldReturnListOfCasWithOneProperCa() throws Exception {
        // given
        final String expectedSubjectDn = CADataBuilder.TEST_CA_SUBJECT_DN;
        final String expectedName = CADataBuilder.TEST_CA_NAME;
        final int expectedId = 11;
        final String expectedIssuerDn = CADataBuilder.TEST_CA_ISSUER_DN;
        final Date expectedExpirationDate = new Date();
        final long expectedExpirationDateLong = expectedExpirationDate.getTime();
        final CAData caData = CADataBuilder.builder()
                .id(expectedId)
                .subjectDn(expectedSubjectDn)
                .name(expectedName)
                .status(CAConstants.CA_ACTIVE)
                .expirationDate(expectedExpirationDate)
                .build();
        expect(caSessionMock.findAll()).andReturn(Collections.singletonList(caData));
        replay(caSessionMock);
        // when
        final ClientResponse actualResponse = server.newRequest("/v1/ca").get();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final JSONArray actualCertificateAuthorities = (JSONArray)actualJsonObject.get("certificateAuthorities");
        System.out.println(actualJsonString);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualCertificateAuthorities);
        assertEquals(1, actualCertificateAuthorities.size());
        final JSONObject actualCaInfo0JsonObject = (JSONObject) actualCertificateAuthorities.get(0);
        final Object actualId = actualCaInfo0JsonObject.get("id");
        final Object actualName = actualCaInfo0JsonObject.get("name");
        final Object actualSubjectDn = actualCaInfo0JsonObject.get("subjectDn");
        final Object actualIssuerDn = actualCaInfo0JsonObject.get("issuerDn");
        final Object actualExpirationDateLong = actualCaInfo0JsonObject.get("expirationDate");
        assertNotNull(actualId);
        assertEquals((long) expectedId, actualId);
        assertNotNull(actualName);
        assertEquals(expectedName, actualName);
        assertNotNull(actualSubjectDn);
        assertEquals(expectedSubjectDn, actualSubjectDn);
        assertNotNull(actualIssuerDn);
        assertEquals(expectedIssuerDn, actualIssuerDn);
        assertNotNull(actualExpirationDateLong);
        assertEquals(expectedExpirationDateLong, actualExpirationDateLong);
        verify(caSessionMock);
    }

}
