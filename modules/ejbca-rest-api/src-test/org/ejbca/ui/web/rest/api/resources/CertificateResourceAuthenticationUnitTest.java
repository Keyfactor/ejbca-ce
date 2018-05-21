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
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.ui.web.rest.api.InMemoryRestServer;
import org.ejbca.ui.web.rest.api.types.EnrollCertificateRequestType;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * A unit test class for CertificateResourceAuthenticationUnitTest to test the unauthorized flow.
 * <br/>
 * The testing is organized through deployment of this resource with mocked dependencies into InMemoryRestServer.
 *
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 *
 * @version $Id: CertificateResourceAuthenticationUnitTest.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
@RunWith(EasyMockRunner.class)
public class CertificateResourceAuthenticationUnitTest {

    public static InMemoryRestServer server;
    
    @TestSubject
    private static CertificateResource testClass = new CertificateResource();
    
    @Mock
    private EjbBridgeSessionLocal ejbLocalHelper;
    
    @Mock
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSessionLocal;    

    @Mock
    HttpServletRequest requestContext;
    
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
    public void shouldGiveUnauthorizedException() throws Exception {
        // given
        EnrollCertificateRequestType requestBody = new EnrollCertificateRequestType();
        
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
