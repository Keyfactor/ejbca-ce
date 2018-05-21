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

import static org.easymock.EasyMock.anyBoolean;
import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response.Status;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.util.Base64;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
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
 * @version $Id: CertificateResourceUnitTest.java 28909 2018-05-21 12:16:53Z andrey_s_helmes $
 * @see org.ejbca.ui.web.rest.api.InMemoryRestServer
 */
@RunWith(EasyMockRunner.class)
public class CertificateResourceUnitTest {

    private static final int END_ENTITY_PROFILE_ID = 1;
    private static final int CERTIFICATE_AUTHORITY_ID = 1652389506;
    private static final int CERTIFICATE_PROFILE_ID = 1;
    private static final JSONParser jsonParser = new JSONParser();
    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));
    // Extend class to test without security
    private static class CertificateResourceWithoutSecurity extends CertificateResource {
        @Override
        protected AuthenticationToken getAdmin(HttpServletRequest requestContext, boolean allowNonAdmins) throws AuthorizationDeniedException {
            return authenticationToken;
        }
    }
    public static InMemoryRestServer server;
    @TestSubject
    private static CertificateResourceWithoutSecurity testClass = new CertificateResourceWithoutSecurity();
    
    @Mock
    private EjbBridgeSessionLocal ejbLocalHelper;
    @Mock
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSessionLocal;

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApiProxy;

    @Mock
    HttpServletRequest requestContext;
    

    static final byte[] testCertificateBytes = Base64.decode((
            "MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw"
            + "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
            + "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
            + "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe"
            + "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
            + "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM"
            + "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
            + "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS"
            + "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
            + "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+"
            + "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==")
            .getBytes());

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
        ClientRequest newRequest = server.newRequest("/v1/certificate/status");
        final ClientResponse<?> actualResponse = newRequest.get();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualStatus = actualJsonObject.get("status");
        final Object actualVersion = actualJsonObject.get("version");
        final Object actualRevision = actualJsonObject.get("revision");
        // then
        assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualStatus);
        assertEquals(expectedStatus, actualStatus);
        assertNotNull(actualVersion);
        assertEquals(expectedVersion, actualVersion);
        assertNotNull(actualRevision);
        assertEquals(expectedRevision, actualRevision);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithAuthorizationDeniedException() throws Exception {
        // given
        final int expectedErrorCode = Status.FORBIDDEN.getStatusCode();
        final String expectedErrorMessage = "This is AuthorizationDeniedException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new AuthorizationDeniedException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithRestException() throws Exception {
        // given
        final int expectedErrorCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedErrorMessage = "Invalid revocation reason.";
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", "BAD_REVOCATION_REASON_DOES_NOT_EXIST");
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithNoSuchEndEntityException() throws Exception {
        // given
        final int expectedErrorCode = Status.NOT_FOUND.getStatusCode();
        final String expectedErrorMessage = "This is NoSuchEndEntityException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new NoSuchEndEntityException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithAlreadyRevokedException() throws Exception {
        // given
        final int expectedErrorCode = Status.CONFLICT.getStatusCode();
        final String expectedErrorMessage = "This is AlreadyRevokedException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new AlreadyRevokedException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithWaitingForApprovalException() throws Exception {
        // given
        final int expectedErrorCode = Status.ACCEPTED.getStatusCode();
        final String expectedErrorMessage = "This is WaitingForApprovalException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new WaitingForApprovalException(expectedErrorMessage, 1));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithApprovalException() throws Exception {
        // given
        final int expectedErrorCode = Status.BAD_REQUEST.getStatusCode();
        final String expectedErrorMessage = "This is ApprovalException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new ApprovalException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithRevokeBackDateNotAllowedForProfileException() throws Exception {
        // given
        final int expectedErrorCode = 422;
        final String expectedErrorMessage = "This is RevokeBackDateNotAllowedForProfileException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new RevokeBackDateNotAllowedForProfileException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }

    @Test
    public void shouldReturnProperErrorResponseOnRevokeCertificateWithCADoesntExistsException() throws Exception {
        // given
        final int expectedErrorCode = Status.NOT_FOUND.getStatusCode();
        final String expectedErrorMessage = "This is CADoesntExistsException.";
        raMasterApiProxy.revokeCert(anyObject(AuthenticationToken.class), anyObject(BigInteger.class), anyObject(Date.class), anyString(), anyInt(), anyBoolean());
        expectLastCall().andThrow(new CADoesntExistsException(expectedErrorMessage));
        replay(raMasterApiProxy);
        // when
        final ClientRequest clientRequest = server
                .newRequest("/v1/certificate/TestCa/111/revoke")
                .queryParameter("reason", RevocationReasons.KEYCOMPROMISE.getStringValue());
        final ClientResponse actualResponse = clientRequest.put();
        final String actualContentType = getContentType(actualResponse);
        final String actualJsonString = (String) actualResponse.getEntity(String.class);
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final Object actualErrorCode = actualJsonObject.get("errorCode");
        final Object actualErrorMessage = actualJsonObject.get("errorMessage");
        // then
        assertEquals(expectedErrorCode, actualResponse.getStatus());
        assertEquals(MediaType.APPLICATION_JSON, actualContentType);
        assertNotNull(actualErrorCode);
        assertEquals((long) expectedErrorCode, actualErrorCode);
        assertNotNull(actualErrorMessage);
        assertEquals(expectedErrorMessage, actualErrorMessage);
        verify(raMasterApiProxy);
    }
    @Test
    public void shouldEnrollCert() throws Exception {
        
        // given
        String csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIDWDCCAkACAQAwYTELMAkGA1UEBhMCRUUxEDAOBgNVBAgTB0FsYWJhbWExEDAO\nBgNVBAcTB3RhbGxpbm4xFDASBgNVBAoTC25hYWJyaXZhbHZlMRgwFgYDVQQDEw9o\nZWxsbzEyM3NlcnZlcjYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDe\nlRzGyeXlCQL3lgLjzEn4qcbD0qtth8rXAwjg/eEN1u8lpQp3GtByWm6LeeB7CEyP\nfyy+rW9C7nQmXvJ09cJaLAlETpGjjfZLy6pHzle/D192THB2MYZRuvvAPCfpjjnV\nhP9sYn7GN7kCaYh61fvlD2fVquzqRdz9kjib3mVEmswkS6lHuAPIsmI7SG9UuvPR\nND1DOsmVwqOL62EOE/RlHRStxZDHQDoYMqZISAO5arpbDujn666IVqLs1QpsQ5Ih\nAvxlw+EGNzzYMCbFEkuGs5JK/YNS7JL3JrvMor8XLngaatbteztK0o+khgT2K9x7\nBCkqEoz9iJrmO3B8JDATAgMBAAGggbEwga4GCSqGSIb3DQEJDjGBoDCBnTBQBgNV\nHREESTBHggtzb21lZG5zLmNvbYcEwKgBB4ISc29tZS5vdGhlci5kbnMuY29tpB4w\nHDENMAsGA1UEAxMEVGVzdDELMAkGA1UEBxMCWFgwMQYDVR0lBCowKAYIKwYBBQUH\nAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQwCQYDVR0TBAIwADALBgNV\nHQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEBAM2cW62D4D4vxaKVtIYpgolbD0zv\nWyEA6iPa4Gg2MzeLJVswQoZXCj5gDOrttHDld3QQTDyT9GG0Vg8N8Tr9i44vUr7R\ngK5w+PMq2ExGS48YrCoMqV+AJHaeXP+gi23ET5F6bIJnpM3ru6bbZC5IUE04YjG6\nxQux6UsxQabuaTrHpExMgYjwJsekEVe13epUq5OiEh7xTJaSnsZm+Ja+MV2pn0gF\n3V1hMBajTMGN9emWLR6pfj5P7QpVR4hkv3LvgCPf474pWA9l/4WiKBzrI76T5yz1\nKoobCZQ2UrqnKFGEbdoNFchb2CDgdLnFu6Tbf6MW5zO5ypOIUih61Zf9Qyo=\n-----END CERTIFICATE REQUEST-----\n";

        EnrollCertificateRequestType requestBody = new EnrollCertificateRequestType();
        requestBody.setCertificateProfileId(CERTIFICATE_PROFILE_ID);
        requestBody.setEndEntityProfileId(END_ENTITY_PROFILE_ID);
        requestBody.setCertificateAuthorityId(CERTIFICATE_AUTHORITY_ID);
        requestBody.setCertificateRequest(csr);
        
        X509Certificate mockX509Cert = EasyMock.mock(X509Certificate.class);

        X509Certificate[] certs = new X509Certificate[1];
        certs[0] = mockX509Cert;

        String subjectdn = "mydn=123";
        String name = "test123";
        int status = 20;
        int certificateProfileId = CERTIFICATE_PROFILE_ID;
        String encodedValidity = "";
        int signedby = 1;
        Collection<Certificate> certificatechain = new ArrayList<>();
        CAToken caToken = EasyMock.mock(CAToken.class);

        CAInfo caInfo = new X509CAInfo(subjectdn, name, status, certificateProfileId, encodedValidity, signedby, certificatechain, caToken);

        IdNameHashMap<CAInfo> authorizedCAInfos = new IdNameHashMap<>();
        authorizedCAInfos.put(CERTIFICATE_AUTHORITY_ID, "test-cainfo-name", caInfo);
        
        CertificateProfile certificateProfile = new CertificateProfile();

        IdNameHashMap<CertificateProfile> certificateProfiles = new IdNameHashMap<>();
        certificateProfiles.put(CERTIFICATE_PROFILE_ID, "test-profile-name", certificateProfile);
        
        EndEntityProfile endEntityProfile = new EndEntityProfile();
        
        IdNameHashMap<EndEntityProfile> endEntityProfiles =  new IdNameHashMap<>();
        endEntityProfiles.put(END_ENTITY_PROFILE_ID, "test-endentity-profile-name", endEntityProfile);
        
        expect(raMasterApiProxy.getAuthorizedCAInfos((AuthenticationToken) EasyMock.anyObject())).andReturn(authorizedCAInfos);
        expect(raMasterApiProxy.getAuthorizedCertificateProfiles((AuthenticationToken) EasyMock.anyObject())).andReturn(certificateProfiles);
        expect(raMasterApiProxy.getAuthorizedEndEntityProfiles((AuthenticationToken)EasyMock.anyObject(), EasyMock.anyString())).andReturn(endEntityProfiles);
        expect(raMasterApiProxy.searchUser((AuthenticationToken)EasyMock.anyObject(), EasyMock.anyString())).andReturn(null);
        expect(raMasterApiProxy.addUser((AuthenticationToken)EasyMock.anyObject(), (EndEntityInformation)EasyMock.anyObject(), EasyMock.anyBoolean())).andReturn(true);
        expect(raMasterApiProxy.createCertificate((AuthenticationToken)EasyMock.anyObject(), (EndEntityInformation)EasyMock.anyObject())).andReturn(testCertificateBytes);
        
        replay(raMasterApiProxy);
        
        
        // when

        // TODO verify dn and an
        String dn = "C=EE,ST=Alabama,L=tallinn,O=naabrivalve,CN=hello123server6";
        String an = "dNSName=somedns.com, iPAddress=192.168.1.7, dNSName=some.other.dns.com, directoryName=CN=Test\\,L=XX";
        
        ClientRequest request = server.newRequest("/v1/certificate/pkcs10enroll");
        request.body(MediaType.APPLICATION_JSON, requestBody);

        final ClientResponse actualResponse = request.post();
        Status responseStatus = actualResponse.getResponseStatus();
        assertEquals(Status.OK, responseStatus);
        EasyMock.verify(raMasterApiProxy);
    }

}
