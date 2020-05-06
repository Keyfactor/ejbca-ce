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

package org.ejbca.core.model.validation;

import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Unit tests for {@link GoogleSafeBrowsingValidator}.
 *
 * @version $Id$
 */
public class GoogleSafeBrowsingValidatorTest {

    @Test
    public void test1GoodDomain() throws IOException {
        final String json = "{}";
        final CloseableHttpClient mockHttpClient = mock(CloseableHttpClient.class);
        final CloseableHttpResponse mockHttpResponse = mock(CloseableHttpResponse.class);
        final StringEntity entity = new StringEntity(json, StandardCharsets.UTF_8);
        final StatusLine mockStatusLine = mock(StatusLine.class);
        expect(mockStatusLine.getStatusCode()).andReturn(200);
        expect(mockHttpResponse.getEntity()).andReturn(entity).anyTimes();
        expect(mockHttpResponse.getStatusLine()).andReturn(mockStatusLine);
        expect(mockHttpClient.execute(anyObject(HttpPost.class))).andReturn(mockHttpResponse);
        mockHttpClient.close();
        expectLastCall();
        mockHttpResponse.close();
        expectLastCall();
        replay(mockHttpClient, mockHttpResponse, mockStatusLine);
        final GoogleSafeBrowsingValidator validator = new GoogleSafeBrowsingValidator(() -> mockHttpClient);
        final Map.Entry<Boolean, List<String>> result = validator.validate(null, "primekey.com");
        verify(mockHttpClient, mockHttpResponse, mockStatusLine);
        assertTrue("A good domain should pass validation.", result.getKey());
        assertEquals(1, result.getValue().size());
    }

    @Test
    public void test1PhishingDomainAnd1GoodDomain() throws IOException {
        final String json = "{" +
                "  \"matches\": [{" +
                    "\"threatType\": \"MALWARE\"," +
                    "\"platformType\": \"WINDOWS\"," +
                    "\"threatEntryType\": \"URL\"," +
                    "\"threat\": {\"url\": \"g00gle.com\"}," +
                    "\"threatEntryMetadata\": {" +
                      "\"entries\": [{" +
                        "\"key\": \"malware_threat_type\"," +
                        "\"value\": \"landing\"" +
                     "}]" +
                    "}," +
                    "\"cacheDuration\": \"300.000s\"" +
                  "}]" +
                "}";
        final CloseableHttpClient mockHttpClient = mock(CloseableHttpClient.class);
        final CloseableHttpResponse mockHttpResponse = mock(CloseableHttpResponse.class);
        final StringEntity entity = new StringEntity(json, StandardCharsets.UTF_8);
        final StatusLine mockStatusLine = mock(StatusLine.class);
        expect(mockStatusLine.getStatusCode()).andReturn(200);
        expect(mockHttpResponse.getEntity()).andReturn(entity).anyTimes();
        expect(mockHttpResponse.getStatusLine()).andReturn(mockStatusLine);
        expect(mockHttpClient.execute(anyObject(HttpPost.class))).andReturn(mockHttpResponse);
        mockHttpClient.close();
        expectLastCall();
        mockHttpResponse.close();
        expectLastCall();
        replay(mockHttpClient, mockHttpResponse, mockStatusLine);
        final GoogleSafeBrowsingValidator validator = new GoogleSafeBrowsingValidator(() -> mockHttpClient);
        final Map.Entry<Boolean, List<String>> result = validator.validate(null, "primekey.com", "g00gle.com");
        verify(mockHttpClient, mockHttpResponse, mockStatusLine);
        assertFalse("A phishing domain should not pass validation.", result.getKey());
        assertEquals("One validation message per domain name should be produced", 2, result.getValue().size());
    }

    @Test
    public void testNetworkError() throws IOException {
        final CloseableHttpClient mockHttpClient = mock(CloseableHttpClient.class);
        expect(mockHttpClient.execute(anyObject(HttpPost.class))).andThrow(new IOException());
        mockHttpClient.close();
        expectLastCall();
        replay(mockHttpClient);
        final GoogleSafeBrowsingValidator validator = new GoogleSafeBrowsingValidator(() -> mockHttpClient);
        final Map.Entry<Boolean, List<String>> result = validator.validate(null, "primekey.com");
        verify(mockHttpClient);
        assertFalse("Validation should not pass when a network error occurs.", result.getKey());
        assertEquals(1, result.getValue().size());
    }

    @Test
    public void testNotFound() throws IOException {
        final CloseableHttpClient mockHttpClient = mock(CloseableHttpClient.class);
        final CloseableHttpResponse mockHttpResponse = mock(CloseableHttpResponse.class);
        final StringEntity entity = new StringEntity("{}", StandardCharsets.UTF_8);
        final StatusLine mockStatusLine = mock(StatusLine.class);
        expect(mockStatusLine.getStatusCode()).andReturn(404).anyTimes();
        expect(mockHttpResponse.getEntity()).andReturn(entity).anyTimes();
        expect(mockHttpResponse.getStatusLine()).andReturn(mockStatusLine).anyTimes();
        expect(mockHttpClient.execute(anyObject(HttpPost.class))).andReturn(mockHttpResponse);
        mockHttpClient.close();
        expectLastCall();
        mockHttpResponse.close();
        expectLastCall();
        replay(mockHttpClient, mockHttpResponse, mockStatusLine);
        final GoogleSafeBrowsingValidator validator = new GoogleSafeBrowsingValidator(() -> mockHttpClient);
        final Map.Entry<Boolean, List<String>> result = validator.validate(null, "primekey.com");
        verify(mockHttpClient, mockHttpResponse, mockStatusLine);
        assertFalse("Validation should not pass if Google returns 404.", result.getKey());
        assertEquals(1, result.getValue().size());
    }
}