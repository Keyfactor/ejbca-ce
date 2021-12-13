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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

/**
 * Test of {@link OAuthTokenRequest}
 */
public class OAuthTokenRequestUnitTest {

    private static final Logger log = Logger.getLogger(OAuthTokenRequestUnitTest.class);

    private static final String REDIRECT_URI = "https://app.test/redirecturi";
    private static final String CLIENTID = "Client123";
    private static final String AUTHSERVER_URI = "https://authserver.test/";
    private static final String AUTHORIZATION_CODE = "auth123";
    private static final String REQUEST_MIMETYPE = "application/x-www-form-urlencoded";
    private static final String RESPONSE_MIMETYPE = "application/json; charset=UTF-8";
    // The data below is extracted from actual responses from KeyClock
    private static final String ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmQWh0VHJRZlJJQjBDMzFpQ2RQVWU5WkpfOHd4NE92LXduNU" + 
            "1kVXhDd29RIn0.eyJleHAiOjE2MDg2NDc4MTksImlhdCI6MTYwODY0NzUxOSwiYXV0aF90aW1lIjoxNjA4NjQ3NTE5LCJqdGkiOiIwZjUzN2ZkNy0yOGI4LTQ0N2YtODdkMi1iYWYxMTUxMWQ3ZmEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjcwNzAvYXV0aC9yZWFsbXMvRUpCQ0EiLCJhdWQiOiJhY2NvdW50Iiwi" + 
            "c3ViIjoiYzE5ZjVlY2UtYzkxZC00ZGUwLWE3OWEtNzliOTJlZTlhZmY4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiRUpCQ0FBZG1pbldlYiIsInNlc3Npb25fc3RhdGUiOiJlMWRkNjdmYy00NzI0LTQxMjEtYWQ1Yy05ZGVhNWJmYzk2ODciLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbm" + 
            "VfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJFSkJDQUFkbWluV2ViIjp7InJvbGVzIjpbIkVqYmNhVXNlclJvbGUiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3Bl" + 
            "IjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IkpvaG4gRG9lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZWpiY2F1c2VyIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.EEUKL10Bm3xUvpjkbr9EdoDF4Hd-yMMbaCbdkBsomktUG52XBqf5rKom-gKKk" + 
            "-AiM2C0IvbJI09xv4G5LpbZxgBqiRXxpNja0j-qkkHdpK3r6ki6sRix9l5_Lwq8Yzn0THhlkFrHy2TOV-K2aHSBnGzHuFTM0YVEFCnqxylnAcQTsUHsM3HSf1sj-8Ct3_x1EJvPUjXr3PTbUzqD5k-O24i4dQU3O6JdoqQHuUROGsbxDp04sulu6rrDbm3WDN7Es4n-nA5WxNwct90RY84whwjeSEbD8-3deHO-PfjT4xD" + 
            "7Bd1KSx1RI43Ourv-eQ-d2vWwn7tGw8tdn60LBeXwVA";
    private static final String GOOD_RESPONSE = "{\"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmQWh0VHJRZlJJQjBDMzFpQ2RQVWU5WkpfOHd4NE92LXduNU" + 
            "1kVXhDd29RIn0.eyJleHAiOjE2MDg2NDc4MTksImlhdCI6MTYwODY0NzUxOSwiYXV0aF90aW1lIjoxNjA4NjQ3NTE5LCJqdGkiOiIwZjUzN2ZkNy0yOGI4LTQ0N2YtODdkMi1iYWYxMTUxMWQ3ZmEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjcwNzAvYXV0aC9yZWFsbXMvRUpCQ0EiLCJhdWQiOiJhY2NvdW50Iiwi" + 
            "c3ViIjoiYzE5ZjVlY2UtYzkxZC00ZGUwLWE3OWEtNzliOTJlZTlhZmY4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiRUpCQ0FBZG1pbldlYiIsInNlc3Npb25fc3RhdGUiOiJlMWRkNjdmYy00NzI0LTQxMjEtYWQ1Yy05ZGVhNWJmYzk2ODciLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbm" + 
            "VfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJFSkJDQUFkbWluV2ViIjp7InJvbGVzIjpbIkVqYmNhVXNlclJvbGUiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3Bl" + 
            "IjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IkpvaG4gRG9lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZWpiY2F1c2VyIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.EEUKL10Bm3xUvpjkbr9EdoDF4Hd-yMMbaCbdkBsomktUG52XBqf5rKom-gKKk" + 
            "-AiM2C0IvbJI09xv4G5LpbZxgBqiRXxpNja0j-qkkHdpK3r6ki6sRix9l5_Lwq8Yzn0THhlkFrHy2TOV-K2aHSBnGzHuFTM0YVEFCnqxylnAcQTsUHsM3HSf1sj-8Ct3_x1EJvPUjXr3PTbUzqD5k-O24i4dQU3O6JdoqQHuUROGsbxDp04sulu6rrDbm3WDN7Es4n-nA5WxNwct90RY84whwjeSEbD8-3deHO-PfjT4xD" + 
            "7Bd1KSx1RI43Ourv-eQ-d2vWwn7tGw8tdn60LBeXwVA\",\"expires_in\":300,\"refresh_expires_in\":1800,\"refresh_token\":\"eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4ZTQyODc1YS05MjIxLTQ4OGYtOWY1My03YmI5N2Y1OGVhMTIifQ.eyJleHAiOjE2MDg2NDkzMTksImlhdC" + 
            "I6MTYwODY0NzUxOSwianRpIjoiOTAxNWI4ODktMGM5Yy00ZmE1LWEyMjgtNDkzYTljMWQwNjdhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo3MDcwL2F1dGgvcmVhbG1zL0VKQkNBIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo3MDcwL2F1dGgvcmVhbG1zL0VKQkNBIiwic3ViIjoiYzE5ZjVlY2UtYzkxZC00ZGUw" + 
            "LWE3OWEtNzliOTJlZTlhZmY4IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6IkVKQkNBQWRtaW5XZWIiLCJzZXNzaW9uX3N0YXRlIjoiZTFkZDY3ZmMtNDcyNC00MTIxLWFkNWMtOWRlYTViZmM5Njg3Iiwic2NvcGUiOiJlbWFpbCBwcm9maWxlIn0.x0CPBkdo_-KOL67MilcLvOx_zuRmIYmA-mNOKaOHE-o\",\"token_ty" + 
            "pe\":\"bearer\",\"not-before-policy\":0,\"session_state\":\"e1dd67fc-4724-4121-ad5c-9dea5bfc9687\",\"scope\":\"email profile\"}";

    private final CloseableHttpClient httpClientMock = EasyMock.createStrictMock(CloseableHttpClient.class);
    private final CloseableHttpResponse httpResponse = EasyMock.createNiceMock(CloseableHttpResponse.class);

    @Before
    public void before() {
        reset(httpClientMock, httpResponse);
    }

    @Test
    public void simpleRequest() throws Exception {
        log.trace(">simpleRequest");
        final OAuthTokenRequest req = new OAuthTokenRequest();
        req.setClientId(CLIENTID);
        req.setRedirectUri(REDIRECT_URI);
        req.setUri(AUTHSERVER_URI);
        final Capture<HttpUriRequest> requestCapture = newCapture();
        expect(httpClientMock.execute(capture(requestCapture))).andReturn(httpResponse);
        expect(httpResponse.getStatusLine()).andReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, 200, "Ok"));
        expect(httpResponse.getHeaders("Content-Type")).andReturn(new Header[] { new BasicHeader("Content-Type", RESPONSE_MIMETYPE) });
        expect(httpResponse.getEntity()).andReturn(makeEntity(GOOD_RESPONSE, RESPONSE_MIMETYPE));
        replay(httpClientMock, httpResponse);
        final OAuthGrantResponseInfo grantResponse = req.execute(AUTHORIZATION_CODE, httpClientMock, false);
        verify(httpClientMock, httpResponse);
        final HttpUriRequest request = requestCapture.getValue();
        assertEquals("Wrong request URI", AUTHSERVER_URI, request.getURI().toString());
        assertEquals("Wrong request method", "POST", request.getMethod());
        assertEquals("Wrong request MIME type", REQUEST_MIMETYPE, request.getFirstHeader("Content-Type").getValue());
        final HttpPost post = (HttpPost) request;
        final String requestData = EntityUtils.toString(post.getEntity());
        checkRequest(requestData);
        if (log.isTraceEnabled()) {
            log.trace("Request data from EJBCA: " + requestData);
            log.trace("token_type: " + grantResponse.getTokenType());
            log.trace("access_token: " + grantResponse.getAccessToken());
        }
        assertEquals("Wrong token type was returned",  "bearer", grantResponse.getTokenType());
        assertEquals("Wrong access token was returned",  ACCESS_TOKEN, grantResponse.getAccessToken());
        log.trace("<simpleRequest");
    }

    private void checkRequest(final String requestData) {
        final List<NameValuePair> paramsList = URLEncodedUtils.parse(requestData, StandardCharsets.US_ASCII);
        final Map<String,String> params = new HashMap<>();
        for (final NameValuePair param : paramsList) {
            assertFalse("Duplicate parameter", params.containsKey(param.getName()));
            params.put(param.getName(), param.getValue());
        }
        assertEquals("Wrong grant_type", "authorization_code", params.get("grant_type"));
        assertEquals("Wrong code", AUTHORIZATION_CODE, params.get("code"));
        assertEquals("Wrong redirect_uri", REDIRECT_URI, params.get("redirect_uri"));
        assertEquals("Wrong client_id", CLIENTID, params.get("client_id"));
    }

    @Test
    public void wrongMimeType() throws Exception {
        log.trace(">wrongMimeType");
        final OAuthTokenRequest req = new OAuthTokenRequest();
        req.setClientId(CLIENTID);
        req.setRedirectUri(REDIRECT_URI);
        req.setUri(AUTHSERVER_URI);
        final Capture<HttpUriRequest> requestCapture = newCapture();
        expect(httpClientMock.execute(capture(requestCapture))).andReturn(httpResponse);
        expect(httpResponse.getStatusLine()).andReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, 200, "Ok"));
        expect(httpResponse.getHeaders("Content-Type")).andReturn(new Header[] { new BasicHeader("Content-Type", "text/html") });
        replay(httpClientMock, httpResponse);
        try {
            req.execute("auth123", httpClientMock, false);
            fail("Should throw");
        } catch (IOException e) {
            assertEquals("Wrong exception message", "Invalid MIME type on response from authorization server: text/html", e.getMessage());
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
