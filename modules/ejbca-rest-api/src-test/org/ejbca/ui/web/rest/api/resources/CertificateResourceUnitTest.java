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

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApi;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.types.EnrollCertificateRequestType;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * A unit test class for CertificateResource to test its content.
 * <br/>
 * The testing is organized through deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 *
 * @version $Id: CertificateResourceUnitTest.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
@RunWith(EasyMockRunner.class)
public class CertificateResourceUnitTest {

    public static InMemoryRestServer server;
    private static final JSONParser jsonParser = new JSONParser();

    @TestSubject
    private static CertificateResource testClass = new CertificateResource();
    
    @Mock
    private EjbBridgeSessionLocal ejbLocalHelper;
    
    @Mock
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSessionLocal;

    @Mock
    private RaMasterApi raMasterApi;

    @Mock
    HttpServletRequest requestContext;

    private static EnrollCertificateRequestType requestBody;
    
    
    @BeforeClass
    public static void beforeClass() throws IOException {
        String csr = "-----BEGIN CERTIFICATE REQUEST-----\\r\\n" +
                "MIIDWDCCAkACAQAwYTELMAkGA1UEBhMCRUUxEDAOBgNVBAgTB0FsYWJhbWExEDAO\\r\\n" +
                "BgNVBAcTB3RhbGxpbm4xFDASBgNVBAoTC25hYWJyaXZhbHZlMRgwFgYDVQQDEw9o\\r\\n" +
                "ZWxsbzEyM3NlcnZlcjYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDX\\r\\n" +
                "YnPvA2cih5XfeW9yORYVZf+imaC31B50nhbQMA2okQ9EY+eFEl00UrBqFeuzRIiZ\\r\\n" +
                "ctpZtD40hIYMQ35GMABzvXji9DS9f6Ergn0m3P97sH1L2koV2ogBjLw2VhwBZaD1\\r\\n" +
                "VkrOFWqiHIFR4aORo3fPH9C96gL86prLKRybznJ96MObGsmy9gYR6ktneZ8537Ds\\r\\n" +
                "ouhvuBBt7wfAda/rUPhjoRVrmET5CD/PiCttM8t/AIrFcebnAYU2BbKNqMVF12Xp\\r\\n" +
                "CXkrbUJ9BDs0mqqpd1c9jFBMPd1JZw4+SrPdP7trpIoCYDtoXkIu3igcwsmsYArZ\\r\\n" +
                "3pfinFBp/AhYnqDEEMKlAgMBAAGggbEwga4GCSqGSIb3DQEJDjGBoDCBnTBQBgNV\\r\\n" +
                "HREESTBHggtzb21lZG5zLmNvbYcEwKgBB4ISc29tZS5vdGhlci5kbnMuY29tpB4w\\r\\n" +
                "HDENMAsGA1UEAxMEVGVzdDELMAkGA1UEBxMCWFgwMQYDVR0lBCowKAYIKwYBBQUH\\r\\n" +
                "AwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQwCQYDVR0TBAIwADALBgNV\\r\\n" +
                "HQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEBAEEkExEQEcPf18niLP7VF8XDIik8\\r\\n" +
                "D58VcgBKQDd9e0ZVC9liQ58671480+KrSja9RhlkiewbSmVVFRSCEDOA89Aj+mPy\\r\\n" +
                "UeUrk9yP3Tj2VeMr6JrhhEf39IFqCeQQp7tPXVcb7Rq+ABblSBTEPjXnz+XY0SqW\\r\\n" +
                "YunDQIKyW4cAM4iEcsinykppRyKmaDBgIh1fh3iWpjLoG7nXk65sexVtDBcX3USY\\r\\n" +
                "nNuri7HRJEFr7J1GiKZfTbw3wkHtOE/e1WjS7ZhS78K4OLUaciEpIFXRu2SNyj1D\\r\\n" +
                "+Y+xGNcRBibFqi3j3/00J+bqrXYQCXVMtPa4tDw2GSggKS/rtNK1hKvQfrI=\\r\\n" +
                "-----END CERTIFICATE REQUEST-----";

        requestBody = new EnrollCertificateRequestType();
        requestBody.setCertificateProfileId(1);
        requestBody.setEndEntityProfileId(1);
        requestBody.setCertificateAuthorityId(1652389506);
        requestBody.setCertificateRequest(csr);
        
        server = InMemoryRestServer.create(testClass);
        server.start();
    }

    @AfterClass
    public static void afterClass() {
        server.close();
    }
    
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
        ClientRequest newRequest = server.newRequest("/v1/certificate/status");
        final ClientResponse<?> actualResponse = newRequest.get();
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
    public void shouldGiveUnauthorizedException() throws Exception {
        // given
        expect(ejbLocalHelper.getEjbcaRestHelperSession()).andReturn(ejbcaRestHelperSessionLocal);
        expect(ejbcaRestHelperSessionLocal.getAdmin(EasyMock.anyBoolean(), (X509Certificate)EasyMock.anyObject())).andThrow(new AuthorizationDeniedException());
        
        // when
        ClientRequest request = server.newRequest("/v1/certificate/pkcs10enroll");
        request.body(MediaType.APPLICATION_JSON, requestBody);
        final ClientResponse actualResponse = request.post();
        Status responseStatus = actualResponse.getResponseStatus();
        // then
        assertEquals(Status.UNAUTHORIZED, responseStatus);
    }
}
