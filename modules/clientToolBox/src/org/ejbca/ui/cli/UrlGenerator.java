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

package org.ejbca.ui.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.util.CertTools;

/**
 * Generate URLs for URL rewriting given a set of issuers.
 *
 * @version $Id$
 */
public class UrlGenerator extends ClientToolBox {

    @Override
    protected void execute(final String[] args) {
        final List<String> argsList = new ArrayList<String>(Arrays.asList(args));
        argsList.remove(0);
        if (argsList.contains("--help")) {
            System.out.println("Generate URLs for URL rewriting given a set of issuers.");
            System.out.println();
            System.out.println("Usage:");
            System.out.println("    UrlGenerator [options] [<PATH>]");
            System.out.println();
            System.out.println("Where <PATH> is a directory containing one or more issuers. Each issuer should be a single PEM-encoded CA certificate with the .pem extension.");
            System.out.println("Files with other file extensions are ignored. If no directory is supplied, the current working directory is used.");
            System.out.println();
            System.out.println("The available options are:");
            System.out.println("    --tls Generate HTTPS URLs.");
            System.out.println("    --appliance Generate URLs compatible with PrimeKey PKI Appliance.");
            return;
        }
        final Map<String, String> cdps = new HashMap<>();
        final File directory = new File(argsList.isEmpty() ? System.getProperty("user.dir") : argsList.get(argsList.size() - 1));
        final File[] files = directory.listFiles();
        if (files == null) {
            System.err.println(directory + " is not a valid directory.");
            return;
        }
        for (final File file : files) {
            if (file.isDirectory()) {
                System.out.println("Skipping directory: " + file.getName());
                continue;
            }
            if (!file.canRead()) {
                System.out.println("Skipping non-readable file: " + file.getName());
                continue;
            }
            if (file.isHidden()) {
                System.out.println("Skipping hidden file: " + file.getName());
                continue;
            }
            if (!file.getName().toLowerCase().endsWith(".pem")) {
                System.out.println("Skipping file with wrong file extension: " + file.getName());
                continue;
            }
            try {
                final List<Certificate> certificates = CertTools.getCertsFromPEM(new FileInputStream(file), Certificate.class);
                if (certificates.isEmpty()) {
                    System.out.println("Skipping file without any certificates " + file.getName());
                }
                if (certificates.size() > 1) {
                    System.out.println("File " + file.getName() + " contains more than one certificate, using the first one in the chain.");
                }
                final Certificate certificate = certificates.get(0);
                cdps.put(CertTools.getSubjectDN(certificate), getCrlUrl(argsList, certificate));
            } catch (CertificateParsingException | FileNotFoundException e) {
                System.out.println("Skipping file " + file.getName() + " due to error during parsing: " + e.getMessage());
            } catch (UnsupportedEncodingException e) {
                System.out.println("Skipping file " + file.getName() + " due to error when URL encoding: " + e.getMessage());
            }
        }
        System.out.println("CRL Distribution Points:");
        System.out.println();
        for (final String subjectDn : cdps.keySet()) {
            System.out.println("Issuer: " + subjectDn);
            System.out.println("    " + cdps.get(subjectDn));
        }
        if (cdps.isEmpty()) {
            System.out.println("    No CDPs were generated :(");
        }
    }

    private String getCrlUrl(final List<String> argsList, final Certificate certificate) throws UnsupportedEncodingException {
        final String baseUrl = "%s://<HOSTNAME>%s/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=%s";
        final String protocol = argsList.contains("--tls") ? "https" : "http";
        final String port = argsList.contains("--appliance") ? "" : (argsList.contains("--tls") ? ":8442" : ":8080");
        final String subjectDn = URLEncoder.encode(CertTools.getSubjectDN(certificate), "UTF-8");
        return String.format(baseUrl, protocol, port, subjectDn);
    }

    @Override
    protected String getName() {
        return "UrlGenerator";
    }
}
