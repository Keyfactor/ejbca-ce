/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.util.log;

import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

/**
 * <p>Parses contents from log lines produced by the application server.
 *
 * <p>See {@link org.ejbca.ui.cli.RecoverCommand} for an implementation example.
 */
public class LogLineParser {
    private String data;
    private Exception error;

    public LogLineParser(final String logLine) {
        this.data = logLine;
    }

    /**
     * Extracts data matching the first capture group in a regex.
     *
     * @param regex a regex containing a capture group used to extract data.
     * @return this {@link LogLineParser} containing the extracted data.
     */
    public LogLineParser extractDataFromCaptureGroup(final String regex) {
        final Pattern pattern = Pattern.compile(regex);
        final Matcher matcher = pattern.matcher(data);
        if (matcher.find()) {
            data = matcher.group(1);
            if (data == null) {
                error = new IllegalArgumentException("Capture group in regex '" + regex + "' is not matching.");
            }
        } else {
            data = null;
            error = new IllegalArgumentException("Regex '" + regex + "' is not matching.");
        }
        return this;
    }

    /**
     * Base64 decode data.
     *
     * @return this {@link LogLineParser} containing the base64 decoded data.
     */
    public LogLineParser base64Decode() {
        try {
            data = new String(Base64.decode(data.getBytes(StandardCharsets.US_ASCII)));
        } catch (RuntimeException e) {
            this.error = e;
        }
        return this;
    }

    /**
     * Get the data as a {@link String}.
     *
     * @return the parsed data as a {@link String}.
     * @throws IllegalArgumentException if this {@link LogLineParser} holds no valid data.
     */
    public String getString() throws IllegalArgumentException {
        if (error != null) {
            throw new IllegalArgumentException("Cannot parse data: " + data, error);
        }
        return data;
    }

    /**
     * Get an optional containing the parsed data or an empty optional if
     * nothing could be parsed.
     *
     * @return the parsed data as an {@link Optional}.
     */
    public Optional<String> getOptionalString() {
        if (error != null) {
            return Optional.empty();
        }
        return Optional.of(data);
    }

    /**
     * Get the data as a {@link Certificate}.
     *
     * @return the parsed data as a {@link Certificate}.
     * @throws IllegalArgumentException if the data could not be parsed as a certificate.
     */
    public Certificate getCertificateFromBase64Data() throws IllegalArgumentException {
        try {
            if (error != null) {
                throw new IllegalArgumentException("Cannot parse data: " + data, error);
            }
            return CertTools.getCertfromByteArray(Base64.decode(data.getBytes(StandardCharsets.US_ASCII)), Certificate.class);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Data is not a certificate: " + data, error);
        }
    }

    /**
     * Get the data as an {@link Integer}.
     *
     * @return the parsed data as an {@link Integer}.
     * @throws IllegalArgumentException if the data could not be parsed as an integer.
     */
    public int getInteger() throws IllegalArgumentException {
        try {
            if (error != null) {
                throw new IllegalArgumentException("Cannot parse data: " + data, error);
            }
            return Integer.valueOf(data);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Data is not an integer: " + data, error);
        }
    }
}
