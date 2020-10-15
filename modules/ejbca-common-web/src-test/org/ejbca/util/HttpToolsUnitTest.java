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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * @version $Id$
 */
public class HttpToolsUnitTest {

    private static final String FILENAME_PARAM = "filename";

    @Test
    public void extractUploadFilenameFromValidHeader() {
        // The header is optional, so null should be allowed
        assertEquals("", HttpTools.getUploadFilenameFromHeader(null));
        // Specifying a filename parameter is optional
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; name=value"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment;name=value; other=value"));
        // Unquoted values
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; filename="));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; filename=;"));
        assertEquals("fileU1.txt", HttpTools.getUploadFilenameFromHeader("attachment; filename=fileU1.txt"));
        assertEquals("fileU2.txt", HttpTools.getUploadFilenameFromHeader("attachment; FILENAME=fileU2.txt; name=value"));
        assertEquals("fileU3.txt", HttpTools.getUploadFilenameFromHeader("attachment; name=value; filename =  fileU3.txt ; name=value"));
        assertEquals("fileU4.txt", HttpTools.getUploadFilenameFromHeader("attachment;name=value;filename=fileU4.txt;name=value"));
        // Quoted values
        assertEquals("fileQ1.txt", HttpTools.getUploadFilenameFromHeader("attachment; filename=\"fileQ1.txt\""));
        assertEquals("fileQ2.txt", HttpTools.getUploadFilenameFromHeader("attachment; name1=\"value 1\"; filename=\"fileQ2.txt\"; name=value"));
        assertEquals("fileQ3;.t=xt", HttpTools.getUploadFilenameFromHeader("attachment; filename=\"fileQ3;.t=xt\""));
        // Quoted values with backslashes. getUploadFilenameFromHeader strips paths, so these are tested using extractParameterFromHeader instead
        assertEquals("fileQ4\\\".txt", HttpTools.extractParameterFromHeader("attachment; filename=\"fileQ4\\\".txt\"", FILENAME_PARAM));
        assertEquals("fileQ5", HttpTools.extractParameterFromHeader("attachment; filename=\"fileQ5\"; junk\"", FILENAME_PARAM));
        assertEquals("fileQ6\\\\", HttpTools.extractParameterFromHeader("attachment; filename=\"fileQ6\\\\\"; junk\"", FILENAME_PARAM));
        // Test stripping paths
        assertEquals("Some file 1.svg", HttpTools.getUploadFilenameFromHeader("attachment; name=upload; filename=\"C:\\Some file 1.svg\""));
        assertEquals("Some file 2.svg", HttpTools.getUploadFilenameFromHeader("attachment; name=upload; filename=\"/home/user/My files/Some file 2.svg\""));
        // Test with URL-encoded data
        assertEquals("Some file 3.svg", HttpTools.getUploadFilenameFromHeader("attachment; name=upload; filename=\"C:%5CSome file 3.svg\""));
        assertEquals("Some file 4.svg", HttpTools.getUploadFilenameFromHeader("attachment; name=upload; filename=%2Fhome%2Fuser%2FMy%20files%2FSome%20file%204.svg"));
    }

    @Test
    public void extractUploadFilenameFromExtendedHeader() {
        assertEquals("å.pdf", HttpTools.getUploadFilenameFromHeader("attachment; filename*=ISO-8859-1''%e5.pdf"));
        assertEquals("å.pdf", HttpTools.getUploadFilenameFromHeader("attachment; filename*=UTF-8''%c3%a5.pdf"));
        assertEquals("Б.pdf", HttpTools.getUploadFilenameFromHeader("attachment; filename*=UTF-8'en'%d0%91.pdf"));
    }

    @Test
    public void extractUploadFilenameFromInvalidHeader() {
        // All these are non-compliant with RFC 6266
        assertEquals("", HttpTools.getUploadFilenameFromHeader(""));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("x"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment;"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment;;"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; =test"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; =filename;==;;;"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; filename=\""));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; filename=\";"));
        assertEquals("", HttpTools.getUploadFilenameFromHeader("attachment; filename=\"\\"));
        assertEquals("file1.txt", HttpTools.getUploadFilenameFromHeader("attachment; filename=file1.txt junk"));
    }

    @Test
    public void testUrlDecode() {
        assertEquals("", HttpTools.urlDecode(""));
        assertEquals("%", HttpTools.urlDecode("%"));
        assertEquals("/", HttpTools.urlDecode("%2f"));
        assertEquals("1:å", HttpTools.urlDecode("1:%E5"));
        assertEquals("2:å", HttpTools.urlDecode("2:%C3%A5"));
        assertEquals("3:Б", HttpTools.urlDecode("3:%D0%91"));
    }

    @Test
    public void decodeRfc5987() {
        assertNull(HttpTools.decodeRfc5987(null));
        assertNull(HttpTools.decodeRfc5987(""));
        assertNull(HttpTools.decodeRfc5987("UTF-8'x"));
        assertNull(HttpTools.decodeRfc5987("''"));
        assertNull(HttpTools.decodeRfc5987("INVALID-ENCODING''test%20file.pdf"));
        assertEquals("å.pdf", HttpTools.decodeRfc5987("ISO-8859-1''%e5.pdf"));
        assertEquals("å.pdf", HttpTools.decodeRfc5987("UTF-8''%c3%a5.pdf"));
        assertEquals("Б.pdf", HttpTools.decodeRfc5987("UTF-8'en'%d0%91.pdf"));
    }

    @Test
    public void extractAuthorizationDataFromHeader() {
        assertNull("Should be null with null parameter", HttpTools.extractAuthorizationOfScheme(null, HttpTools.AUTHORIZATION_SCHEME_BEARER));
        assertNull("Should be null with blank parameter", HttpTools.extractAuthorizationOfScheme("", HttpTools.AUTHORIZATION_SCHEME_BEARER));
        assertNull("Should be null with missing space", HttpTools.extractAuthorizationOfScheme("Bearer", HttpTools.AUTHORIZATION_SCHEME_BEARER));
        assertNull("Should be null with wrong scheme", HttpTools.extractAuthorizationOfScheme("Other xyz", HttpTools.AUTHORIZATION_SCHEME_BEARER));
        assertEquals("Should strip scheme name.", "xyz", HttpTools.extractAuthorizationOfScheme("Bearer xyz", HttpTools.AUTHORIZATION_SCHEME_BEARER));
        assertEquals("Should strip scheme name with multiple spaces.", "xyz", HttpTools.extractAuthorizationOfScheme("Bearer   xyz", HttpTools.AUTHORIZATION_SCHEME_BEARER));
        assertEquals("Should be case insensitive.", "xyz", HttpTools.extractAuthorizationOfScheme("bEaReR xyz", HttpTools.AUTHORIZATION_SCHEME_BEARER));
        assertEquals("Should preserve case.", "XyZ", HttpTools.extractAuthorizationOfScheme("bEaReR XyZ", HttpTools.AUTHORIZATION_SCHEME_BEARER));
    }

    @Test
    public void extractBearerToken() {
        // extractBearerAuthorization uses extractAuthorizationOfScheme, so we only do some basic checks here
        assertNull(HttpTools.extractBearerAuthorization(null));
        assertNull(HttpTools.extractBearerAuthorization("Basic xyz")); // note: scheme is basic not bearer
        assertEquals("aBcD.eFgH.iJk", HttpTools.extractBearerAuthorization("BeArEr   aBcD.eFgH.iJk"));
    }
}
