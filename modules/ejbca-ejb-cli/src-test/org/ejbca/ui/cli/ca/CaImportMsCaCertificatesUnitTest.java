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
package org.ejbca.ui.cli.ca;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CaImportMsCaCertificatesUnitTest {

    private final CaImportMsCaCertificates importer = new CaImportMsCaCertificates();

    @Test
    public void testParseCertTemplateWithQuotedOidAndName() throws IOException {
        final String template = "Certificate Template: \"1.2.3.4.5.6.7.8.9\" MS_CA_CertificateTemplate\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("MS_CA_CertificateTemplate", actual);
    }

    @Test
    public void testParseCertTemplateWithQuotedOidOnly() throws IOException {
        final String template = "Certificate Template: \"1.2.3.4.5.6.7.8.9\"\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("1.2.3.4.5.6.7.8.9", actual);
    }

    @Test
    public void testParseCertTemplateWithQuotedNameOnly() throws IOException {
        final String template = "Certificate Template: \"MS_CA_CertificateTemplate\"\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("MS_CA_CertificateTemplate", actual);
    }

    @Test
    public void testParseCertTemplateWithUnquotedOid() throws IOException {
        final String template = "Certificate Template: 1.2.3.4.5.6.7.8.9\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("1.2.3.4.5.6.7.8.9", actual);
    }

    @Test
    public void testParseCertTemplateWithUnquotedName() throws IOException {
        final String template = "Certificate Template: MS_CA_CertificateTemplate\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("MS_CA_CertificateTemplate", actual);
    }

    @Test
    public void testParseCertTemplateWithSpacesInName() throws IOException {
        final String template = "Certificate Template: MS CA CertificateTemplate\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("MS CA CertificateTemplate", actual);
    }

    @Test
    public void testParseCertTemplateWithQuotedNameWithSpaces() throws IOException {
        final String template = "Certificate Template: \"MS CA CertificateTemplate\"\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("MS CA CertificateTemplate", actual);
    }

    @Test
    public void testParseCertTemplateWithQuotedOidAndQuotedName() throws IOException {
        final String template = "Certificate Template: \"1.2.3.4.5.6.7.8.9\" \"MS_CA_CertificateTemplate\"\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("MS_CA_CertificateTemplate", actual);
    }

    @Test
    public void testParseCertTemplateWithQuotedOidAndQuotedNameWithSpaces() throws IOException {
        final String template = "Certificate Template: \"1.2.3.4.5.6.7.8.9\" \"MS CA CertificateTemplate\"\n";
        final String actual = importer.parseCertificateTemplate(new BufferedReader(new StringReader(template)));
        assertEquals("MS CA CertificateTemplate", actual);
    }
}
