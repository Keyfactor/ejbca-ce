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

import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.helpers.CADataBuilder;
import org.ejbca.ui.web.rest.api.types.CaInfoType;
import org.ejbca.ui.web.rest.api.types.CaInfoTypes;
import org.ejbca.ui.web.rest.api.types.EndpointStatusType;
import org.jboss.resteasy.client.ClientResponse;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;

// TODO assertEquals(MediaType.APPLICATION_JSON_TYPE, actualResponse)
// TODO Review tests
@RunWith(EasyMockRunner.class)
public class CaResourceUnitTest {

    public static InMemoryRestServer server;

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

    @Test
    public void shouldReturnProperStatus() throws Exception {
        // given
        // when
        final ClientResponse actualResponse = server.newRequest("/v1/ca/status").get();
        final EndpointStatusType actualStatus = (EndpointStatusType) actualResponse.getEntity(EndpointStatusType.class);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals("OK", actualStatus.getStatus());
        assertEquals("1.0", actualStatus.getVersion());
        assertEquals("ALPHA", actualStatus.getRevision());
    }

    @Test
    public void shouldReturnEmptyListOfCas() throws Exception {
        // given
        expect(caSessionMock.findAll()).andReturn(Collections.<CAData>emptyList());
        replay(caSessionMock);
        // when
        final ClientResponse actualResponse = server.newRequest("/v1/ca").get();
        final CaInfoTypes actualCaInfoTypes = (CaInfoTypes) actualResponse.getEntity(CaInfoTypes.class);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals(0, actualCaInfoTypes.getCertificateAuthorities().size());
        verify(caSessionMock);
    }

    // TODO Review asserts
    @Test
    public void shouldReturnListOfCasWithOneCa() throws Exception {
        // given
        expect(caSessionMock.findAll()).andReturn(Arrays.asList(CADataBuilder.withDefaults()));
        replay(caSessionMock);
        // when
        final ClientResponse actualResponse = server.newRequest("/v1/ca").get();
        final CaInfoTypes actualCaInfoTypes = (CaInfoTypes) actualResponse.getEntity(CaInfoTypes.class);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals(1, actualCaInfoTypes.getCertificateAuthorities().size());
        final CaInfoType actualCaInfoType = actualCaInfoTypes.getCertificateAuthorities().get(0);
        assertEquals(1, actualCaInfoType.getId());
        assertEquals("TestCA", actualCaInfoType.getName());
        assertEquals("CN=TestCA", actualCaInfoType.getSubjectDn());
        // TODO Temporary
        assertEquals("unknown", actualCaInfoType.getIssuerDn());
        // TODO Temporary
        assertEquals(0, actualCaInfoType.getExpirationDate().getTime());

        verify(caSessionMock);
    }

}
