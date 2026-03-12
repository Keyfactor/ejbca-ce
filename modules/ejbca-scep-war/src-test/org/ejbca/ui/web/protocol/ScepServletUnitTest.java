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

package org.ejbca.ui.web.protocol;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ScepServletUnitTest {

    @Test
    public void testGetAlias_simpleAndValid() {
        // Given
        final String expected = "someAlias";
        final String path = "/"+expected+"/pkiclient.exe";

        // When
        final String actual = ScepServlet.getAlias(path);

        // Then
        assertEquals("Wrong alias", expected, actual);
    }

    @Test
    public void testGetAlias_complexAndValid() {
        // Given
        final String expected = "someAlias";
        final String path = "/some-stuff/and-some-more-stuff/"+expected+"/pkiclient.exe";

        // When
        final String actual = ScepServlet.getAlias(path);

        // Then
        assertEquals("Wrong alias", expected, actual);
    }

    @Test
    public void testGetAliasMissing() {
        // Given
        final String expected = ScepServlet.DEFAULT_SCEP_ALIAS;
        final String path = "/pkiclient.exe";

        // When
        final String actual = ScepServlet.getAlias(path);

        // Then
        assertEquals("Wrong alias", expected, actual);
    }

    @Test
    public void testGetAliasEmptyPath() {
        // Given
        final String path = "";

        // When
        final String actual = ScepServlet.getAlias(path);

        // Then
        assertNull("Wrong alias", actual);
    }

}
