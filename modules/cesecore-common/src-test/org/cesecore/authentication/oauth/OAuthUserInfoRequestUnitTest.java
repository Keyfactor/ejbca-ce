/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authentication.oauth;

import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.newCapture;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.http.Header;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicStatusLine;
import org.apache.log4j.Logger;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

/**
 * Test of {@link OAuthUserInfoRequest}
 */
public class OAuthUserInfoRequestUnitTest {

    private static final Logger log = Logger.getLogger(OAuthUserInfoRequestUnitTest.class);

    private static final String USERINFO_ENDPOINT_URI = "https://authserver.test/userinfo";
    private static final String RESPONSE_MIMETYPE = "application/json; charset=UTF-8";
    private static final String ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmQWh0VHJRZlJJQjBDMzFpQ2RQVWU5WkpfOHd4NE92LXduNU" + 
            "1kVXhDd29RIn0.eyJleHAiOjE2MDg2NDc4MTksImlhdCI6MTYwODY0NzUxOSwiYXV0aF90aW1lIjoxNjA4NjQ3NTE5LCJqdGkiOiIwZjUzN2ZkNy0yOGI4LTQ0N2YtODdkMi1iYWYxMTUxMWQ3ZmEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjcwNzAvYXV0aC9yZWFsbXMvRUpCQ0EiLCJhdWQiOiJhY2NvdW50Iiwi" + 
            "c3ViIjoiYzE5ZjVlY2UtYzkxZC00ZGUwLWE3OWEtNzliOTJlZTlhZmY4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiRUpCQ0FBZG1pbldlYiIsInNlc3Npb25fc3RhdGUiOiJlMWRkNjdmYy00NzI0LTQxMjEtYWQ1Yy05ZGVhNWJmYzk2ODciLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbm" + 
            "VfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJFSkJDQUFkbWluV2ViIjp7InJvbGVzIjpbIkVqYmNhVXNlclJvbGUiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3Bl" + 
            "IjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IkpvaG4gRG9lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZWpiY2F1c2VyIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.EEUKL10Bm3xUvpjkbr9EdoDF4Hd-yMMbaCbdkBsomktUG52XBqf5rKom-gKKk" + 
            "-AiM2C0IvbJI09xv4G5LpbZxgBqiRXxpNja0j-qkkHdpK3r6ki6sRix9l5_Lwq8Yzn0THhlkFrHy2TOV-K2aHSBnGzHuFTM0YVEFCnqxylnAcQTsUHsM3HSf1sj-8Ct3_x1EJvPUjXr3PTbUzqD5k-O24i4dQU3O6JdoqQHuUROGsbxDp04sulu6rrDbm3WDN7Es4n-nA5WxNwct90RY84whwjeSEbD8-3deHO-PfjT4xD" + 
            "7Bd1KSx1RI43Ourv-eQ-d2vWwn7tGw8tdn60LBeXwVA";
    private static final String GOOD_RESPONSE = "{\"name\":\"Test User\",\"sub\":\"f0a70f43-a8b6-4c11-bdc8-0c18a95c458c\",\"email_verified\":false,\"preferred_username\":\"testuser\",\"given_name\":\"Test\",\"family_name\":\"User\"}";
    private static final String SUBJECT = "f0a70f43-a8b6-4c11-bdc8-0c18a95c458c";
    private static final String NAME = "Test User";
    private static final String PREFERRED_USERNAME = "testuser";
    
    private final CloseableHttpClient httpClientMock = EasyMock.createStrictMock(CloseableHttpClient.class);
    private final CloseableHttpResponse httpResponse = EasyMock.createNiceMock(CloseableHttpResponse.class);

    @Before
    public void before() {
        reset(httpClientMock, httpResponse);
    }

    @Test
    public void simpleRequest() throws Exception {
        log.trace(">simpleRequest");
        final OAuthUserInfoRequest req = new OAuthUserInfoRequest();
        req.setUri(USERINFO_ENDPOINT_URI);
        final Capture<HttpUriRequest> requestCapture = newCapture();
        expect(httpClientMock.execute(capture(requestCapture))).andReturn(httpResponse);
        expect(httpResponse.getStatusLine()).andReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, 200, "Ok"));
        expect(httpResponse.getHeaders("Content-Type")).andReturn(new Header[] { new BasicHeader("Content-Type", RESPONSE_MIMETYPE) });
        expect(httpResponse.getEntity()).andReturn(makeEntity(GOOD_RESPONSE, RESPONSE_MIMETYPE));
        replay(httpClientMock, httpResponse);
        final OAuthUserInfoResponse grantResponse = req.execute(ACCESS_TOKEN, httpClientMock);
        verify(httpClientMock, httpResponse);
        final HttpUriRequest request = requestCapture.getValue();
        assertEquals("Wrong request URI", USERINFO_ENDPOINT_URI, request.getURI().toString());
        assertEquals("Wrong request method", "GET", request.getMethod());
        assertEquals("Wrong subject was returned",  SUBJECT, grantResponse.getSubject());
        assertTrue("Claims did not contain the correct name",  grantResponse.getClaims().contains(NAME));
        assertTrue("Claims did not contain the correct preferred username",  grantResponse.getClaims().contains(PREFERRED_USERNAME));
        log.trace("<simpleRequest");
    }

    @Test
    public void wrongMimeType() throws Exception {
        log.trace(">wrongMimeType");
        final OAuthUserInfoRequest req = new OAuthUserInfoRequest();
        req.setUri(USERINFO_ENDPOINT_URI);
        final Capture<HttpUriRequest> requestCapture = newCapture();
        expect(httpClientMock.execute(capture(requestCapture))).andReturn(httpResponse);
        expect(httpResponse.getStatusLine()).andReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, 200, "Ok"));
        expect(httpResponse.getHeaders("Content-Type")).andReturn(new Header[] { new BasicHeader("Content-Type", "text/html") });
        replay(httpClientMock, httpResponse);
        try {
            req.execute(ACCESS_TOKEN, httpClientMock);
            fail("Should throw");
        } catch (IOException e) {
            assertEquals("Wrong exception message", "Invalid MIME type on response from userinfo endpoint: text/html", e.getMessage());
        }
        verify(httpClientMock, httpResponse);
        log.trace("<wrongMimeType");
    }

    private BasicHttpEntity makeEntity(final String contents, final String mimeType) {
        final BasicHttpEntity entity = new BasicHttpEntity();
        final byte[] entityBytes = contents.getBytes(StandardCharsets.US_ASCII);
        entity.setContent(new ByteArrayInputStream(entityBytes));
        entity.setContentLength(entityBytes.length);
        entity.setContentType(mimeType);
        return entity;
    }
}
