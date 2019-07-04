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
package org.ejbca.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * This is Unit test for URIUtil class.
 *
 * @version $Id$
 */
public class URIUtilUnitTest {

    @Test
    public void shouldReturnApplicationUriForDomainName() {
        // given
        final String expectedApplicationUri = "qwerty://my-host.abc:11/my-app/";
        // when
        final String actualApplicationUri = URIUtil.getApplicationUri("qwerty", "my-host.abc", 11, "my-app");
        // then
        assertEquals("Application URI is incorrect.", expectedApplicationUri, actualApplicationUri);
    }

    @Test
    public void shouldReturnApplicationUriForIPv4() {
        // given
        final String expectedApplicationUri = "qwerty://192.168.1.1:123/my-app/";
        // when
        final String actualApplicationUri = URIUtil.getApplicationUri("qwerty", "192.168.1.1", 123, "my-app");
        // then
        assertEquals("Application URI is incorrect.", expectedApplicationUri, actualApplicationUri);
    }

    @Test
    public void shouldReturnApplicationUriForIPv6WithBracketsUnchanged() {
        // given
        final String expectedApplicationUri = "qwerty://[::]:111/my-ipv6-app/";
        // when
        final String actualApplicationUri = URIUtil.getApplicationUri("qwerty", "[::]", 111, "my-ipv6-app");
        // then
        assertEquals("Application URI is incorrect.", expectedApplicationUri, actualApplicationUri);
    }

    @Test
    public void shouldReturnApplicationUriForIPv6WithBrackets() {
        // given
        final String expectedApplicationUri = "qwerty://[fd79:e9b3:50e7:946::]:112/my-ipv6-app/";
        // when
        final String actualApplicationUri = URIUtil.getApplicationUri("qwerty", "fd79:e9b3:50e7:946::", 112, "my-ipv6-app");
        // then
        assertEquals("Application URI is incorrect.", expectedApplicationUri, actualApplicationUri);
    }
}
