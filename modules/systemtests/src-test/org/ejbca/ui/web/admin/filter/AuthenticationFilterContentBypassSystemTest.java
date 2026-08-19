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

package org.ejbca.ui.web.admin.filter;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;

/**
 * Verifies that {@code org.ejbca.ui.web.admin.filter.AuthenticationFilter} cannot be evaded by
 * percent-encoding the request URI in a way the Servlet container decodes back to a protected path
 * after the filter's literal comparison has already let the request through.
 *
 * <p>Covers every URL pattern the filter is bound to in adminweb's {@code web.xml}. For the two
 * endpoints whose response can be parsed ({@code /ca/getcrl/getcrl}, {@code /ca/cacert}) the test also
 * confirms no genuine CRL or CA certificate was leaked, not just that the response was HTTP 200.
 */
public class AuthenticationFilterContentBypassSystemTest {

    private static final Logger log = Logger.getLogger(AuthenticationFilterContentBypassSystemTest.class);

    private static final String CA_NAME = "AuthFilterBypassTestCA";
    private static final String CA_DN = "CN=" + CA_NAME;

    private static final String ADMINWEB = "/ejbca/adminweb";

    private final AuthenticationToken alwaysAllowToken =
            new TestAlwaysAllowLocalAuthenticationToken(AuthenticationFilterContentBypassSystemTest.class.getSimpleName());

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    private final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private String httpHost;
    private int httpPort;
    private String issuerDn;
    private int caId;

    @Before
    public void setUp() throws Exception {
        Assume.assumeTrue("Skipped if not on GITLAB CI", Boolean.parseBoolean(System.getProperty("CI")));

        CryptoProviderTools.installBCProviderIfNotAvailable();

        httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        httpPort = Integer.parseInt(SystemTestsConfiguration
                .getRemotePortHttp(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERPRIVHTTPS)));

        // In case a previous run was aborted before tearDown.
        CaTestUtils.removeCa(alwaysAllowToken, CA_NAME, CA_NAME);
        CaTestUtils.createActiveX509Ca(alwaysAllowToken, CA_NAME, CA_NAME, CA_DN);

        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(alwaysAllowToken, CA_NAME);
        issuerDn = caInfo.getSubjectDN();
        caId = caInfo.getCAId();
        publishingCrlSession.forceCRL(alwaysAllowToken, caId);

        if (crlStoreSession.getLastCRL(issuerDn, CertificateConstants.NO_CRL_PARTITION, false) == null) {
            fail("Test setup failed: no CRL was generated for the freshly created CA '" + CA_NAME + "'.");
        }
    }

    @After
    public void tearDown() throws Exception {
        CaTestUtils.removeCa(alwaysAllowToken, CA_NAME, CA_NAME);
    }

    /** Baseline: if this fails, the encoded-variant test below says nothing about URI parsing. */
    @Test
    public void testCanonicalProtectedPathsAreDeniedWithoutAuthentication() throws IOException {
        final List<String> failures = new ArrayList<>();
        for (final Endpoint endpoint : protectedEndpoints()) {
            final String target = endpoint.canonicalTarget();
            final RawResponse response = sendRawGet(target);
            log.info("anonymous canonical: GET %s -> %s".formatted(target, response.statusCode));

            if (response.statusCode == 200) {
                failures.add("GET %s returned HTTP 200 without authentication.".formatted(target));
            }
        }
        reportFailures(failures);
    }

    @Test
    public void testEncodedProtectedPathsDoNotBypassAuthentication() throws IOException {
        final List<String> failures = new ArrayList<>();
        for (final Endpoint endpoint : protectedEndpoints()) {
            final String target = endpoint.encodedTarget();
            final RawResponse response = sendRawGet(target);
            log.info("anonymous encoded:   GET %s -> %s (%s bytes)".formatted(
                    target, response.statusCode, response.body.length
            ));

            if (endpoint.validator != null && endpoint.validator.apply(response.body)) {
                failures.add(
                        "Authentication bypass reproduced: unauthenticated GET %s returned HTTP %s with a genuine %s for '%s' (%s bytes).".formatted(
                                target, response.statusCode, endpoint.artifactName, issuerDn, response.body.length
                        )
                );
            } else if (response.statusCode == 200) {
                failures.add("Unauthenticated GET %s reached the protected servlet (HTTP 200).".formatted(target));
            }
        }
        reportFailures(failures);
    }

    private List<Endpoint> protectedEndpoints() {
        final String encodedIssuerDn = URLEncoder.encode(issuerDn, StandardCharsets.UTF_8);
        return Arrays.asList(
                new Endpoint("/ca/getcrl/getcrl", "cmd=crl&issuer=%s".formatted(encodedIssuerDn), "CRL", this::isCrl),
                new Endpoint("/ca/cacert", "cmd=iecacert&level=0&issuer=%s".formatted(encodedIssuerDn) , "CA certificate", this::isCaCertificate),
                new Endpoint("/ca/editcas/cacertreq", "cmd=cacertreq&caid=" + caId, null, null),
                new Endpoint("/ca/exportca", "cany=1", null, null),
                new Endpoint("/ca/endentitycert", "cmd=iecert", null, null),
                new Endpoint("/ca/certreq", "", null, null),
                new Endpoint("/profilesexport", "profileType=cp", null, null),
                new Endpoint("/cryptotoken/cryptoTokenDownloads", "cryptoTokenId=1&alias=signKey", null, null)
        );
    }

    /** True if {@code body} is a DER-encoded X.509 CRL issued by the test CA. */
    private boolean isCrl(final byte[] body) {
        if (body == null || body.length == 0) {
            log.info("getcrl response body was empty");
            return false;
        }
        try {
            final X509CRL crl = CertTools.getCRLfromByteArray(body);
            return isDnEquals(crl.getIssuerX500Principal().getName(), issuerDn);
        } catch (final Exception e) {
            log.info("getcrl response body did not parse as an X.509 CRL: %s".formatted(e.getMessage()));
            return false;
        }
    }

    /** True if {@code body} is the DER-encoded X.509 certificate of the test CA. */
    private boolean isCaCertificate(final byte[] body) {
        if (body == null || body.length == 0) {
            log.info("cacert response body was empty");
            return false;
        }
        try {
            final X509Certificate certificate = CertTools.getCertfromByteArray(body, X509Certificate.class);
            return isDnEquals(CertTools.getSubjectDN(certificate), issuerDn);
        } catch (final Exception e) {
            log.info("cacert response body did not parse as an X.509 certificate: %s".formatted(e.getMessage()));
            return false;
        }
    }

    private boolean isDnEquals(final String actual, final String expected) {
        return DnComponents.stringToBCDNString(actual).equalsIgnoreCase(DnComponents.stringToBCDNString(expected));
    }

    private void reportFailures(final List<String> failures) {
        final String failureMessage = "Unauthenticated requests reached protected AdminWeb resources:\n" + String.join("\n", failures);
        assertTrue(failureMessage, failures.isEmpty());
    }

    /** A single filter-protected mapping and how to probe it. */
    private record Endpoint(String servletPath, String query, String artifactName, Function<byte[], Boolean> validator) {

        private String canonicalTarget() {
            return withQuery(ADMINWEB + servletPath);
        }

        /** Percent-encodes every character after the context path, separators included. */
        private String encodedTarget() {
            final StringBuilder sb = new StringBuilder(ADMINWEB);
            for (final char c : servletPath.toCharArray()) {
                sb.append(String.format("%%%02X", (int) c));
            }
            return withQuery(sb.toString());
        }

        private String withQuery(final String path) {
            return query.isEmpty() ? path : path + "?" + query;
        }
    }

    /** Sends the request target verbatim, without any client-side normalization or encoding. */
    private RawResponse sendRawGet(final String requestTarget) throws IOException {
        final String request = """
        GET %s HTTP/1.1
        Host: %s:%d
        Accept: application/pkix-crl, application/octet-stream, */*
        Connection: close
        
        """.formatted(requestTarget, httpHost, httpPort);

        try (Socket socket = new Socket(InetAddress.getByName(httpHost), httpPort)) {
            socket.setSoTimeout(30000);
            final OutputStream os = socket.getOutputStream();
            os.write(request.getBytes(StandardCharsets.US_ASCII));
            os.flush();
            return RawResponse.read(socket.getInputStream());
        }
    }

    private record RawResponse(int statusCode, byte[] body) {

        private static RawResponse read(final InputStream is) throws IOException {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final byte[] buffer = new byte[4096];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, read);
                }
                final byte[] raw = baos.toByteArray();
                // ISO-8859-1 is a 1:1 byte<->char mapping, so binary artifact bytes survive the round-trip below.
                final String asText = new String(raw, StandardCharsets.ISO_8859_1);
                final int endOfStatusLine = asText.indexOf("\r\n");
                if (endOfStatusLine == -1) {
                    throw new IOException("Malformed HTTP response of " + raw.length + " bytes.");
                }
                final String[] statusLine = asText.substring(0, endOfStatusLine).split(" ");
                if (statusLine.length < 2) {
                    throw new IOException("Malformed HTTP status line: " + asText.substring(0, endOfStatusLine));
                }
                final int endOfHeaders = asText.indexOf("\r\n\r\n");
                final byte[] body = endOfHeaders == -1 ? new byte[0]
                        : asText.substring(endOfHeaders + 4).getBytes(StandardCharsets.ISO_8859_1);
                return new RawResponse(Integer.parseInt(statusLine[1]), body);
            }
        }
}
