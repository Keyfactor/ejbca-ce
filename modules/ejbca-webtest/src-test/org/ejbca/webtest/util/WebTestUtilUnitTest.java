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
package org.ejbca.webtest.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * A Unit Test for WebTestUtil.
 *
 * @version $Id: WebTestUtilUnitTest.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
 */
public class WebTestUtilUnitTest {

    @Test
    public void shouldReturnNullUriPathOnNullUrl() {
        // given
        // when
        final String actualUri = WebTestUtil.getUriPathFromUrl(null);
        // then
        assertNull("URI doesn't match", actualUri);
    }

    @Test
    public void shouldReturnEmptyUriPathOnEmptyUrl() {
        // given
        final String expectedUri = "";
        // when
        final String actualUri = WebTestUtil.getUriPathFromUrl("");
        // then
        assertEquals("URI doesn't match", expectedUri, actualUri);
    }

    @Test
    public void shouldReturnUriPathWithoutDuplicatedSlash() {
        // given
        final String url = "https://localhost:8443/ejbca/adminweb//ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        final String expectedUri = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        // when
        final String actualUri = WebTestUtil.getUriPathFromUrl(url);
        // then
        assertEquals("URI doesn't match", expectedUri, actualUri);
    }

    @Test
    public void shouldReturnUriPathWithoutSession() {
        // given
        final String url = "https://localhost:8443/ejbca/adminweb//ca/editcertificateprofiles/editcertificateprofiles.xhtml;jsessionid=CwN+cVjtwFRVth+sm9SvU-CW";
        final String expectedUri = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        // when
        final String actualUri = WebTestUtil.getUriPathFromUrl(url);
        // then
        assertEquals("URI doesn't match", expectedUri, actualUri);
    }

    @Test
    public void shouldReturnUriPathWithoutQueryString() {
        // given
        final String url = "https://localhost:8443/ejbca/adminweb//ca/editcertificateprofiles/editcertificateprofiles.xhtml?param1=a&param2=b";
        final String expectedUri = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        // when
        final String actualUri = WebTestUtil.getUriPathFromUrl(url);
        // then
        assertEquals("URI doesn't match", expectedUri, actualUri);
    }

    @Test
    public void shouldReturnUriPathWithoutFragment() {
        // given
        final String url = "https://localhost:8443/ejbca/adminweb//ca/editcertificateprofiles/editcertificateprofiles.xhtml#top";
        final String expectedUri = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        // when
        final String actualUri = WebTestUtil.getUriPathFromUrl(url);
        // then
        assertEquals("URI doesn't match", expectedUri, actualUri);
    }

    @Test
    public void shouldReturnUriPathWithoutSessionAndQueryStringAndFragment() {
        // given
        final String url = "https://localhost:8443/ejbca/adminweb//ca/editcertificateprofiles/editcertificateprofiles.xhtml;jsessionid=CwN+cVjtwFRVth+sm9SvU-CW?param1=a&param2=b#top";
        final String expectedUri = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        // when
        final String actualUri = WebTestUtil.getUriPathFromUrl(url);
        // then
        assertEquals("URI doesn't match", expectedUri, actualUri);
    }
}
