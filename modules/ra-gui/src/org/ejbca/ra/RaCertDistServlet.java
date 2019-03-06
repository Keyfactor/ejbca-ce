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
package org.ejbca.ra;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

/**
 * Servlet for download of CA certificates and chains.
 *
 * @version $Id$
 */
@WebServlet("/cert")
public class RaCertDistServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaCertDistServlet.class);
    private static final String PARAMETER_FINGERPRINTSHEET = "fpsheet";
    private static final String PARAMETER_CERT_BUNDLE = "certbundle";
    private static final String PARAMETER_CAID = "caid";
    private static final String PARAMETER_FINGERPRINT = "fp";
    private static final String PARAMETER_FORMAT = "format";
    private static final String PARAMETER_FORMAT_OPTION_FIREFOX = "ns";
    private static final String PARAMETER_FORMAT_OPTION_PEM = "pem";    // Applies to both certificate chain and individual certificates download
    private static final String PARAMETER_FORMAT_OPTION_DER = "der";
    private static final String PARAMETER_FORMAT_OPTION_JKS = "jks";    // Applies only to certificate chain download
    private static final String PARAMETER_FORMAT_OPTION_P7C = "pkcs7";  // Applies to both certificate chain and individual certificates download
    private static final String PARAMETER_CHAIN = "chain";

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;
    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;

    private RaAuthenticationHelper raAuthenticationHelper = null;

    @Override
    protected void service(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) throws ServletException, IOException {
        if (raAuthenticationHelper==null) {
            // Initialize the authentication helper function
            raAuthenticationHelper = new RaAuthenticationHelper(webAuthenticationProviderSession);
        }
        if (httpServletRequest.getParameter(PARAMETER_FINGERPRINTSHEET) != null) {
            downloadFingerprintSheet(httpServletRequest, httpServletResponse);
            return;
        }
        if (httpServletRequest.getParameter(PARAMETER_CERT_BUNDLE) != null) {
            downloadCertificateBundle(httpServletRequest, httpServletResponse);
            return;
        }
        final boolean fullChain = Boolean.valueOf(httpServletRequest.getParameter(PARAMETER_CHAIN));
        if (httpServletRequest.getParameter(PARAMETER_CAID) != null) {
            List<Certificate> chain = null;
            try {
                final int caId = Integer.valueOf(httpServletRequest.getParameter(PARAMETER_CAID));
                final AuthenticationToken authenticationToken = raAuthenticationHelper.getAuthenticationToken(httpServletRequest, httpServletResponse);
                final List<CAInfo> caInfos = raMasterApi.getAuthorizedCas(authenticationToken);
                if (log.isDebugEnabled()) {
                    log.debug(authenticationToken.toString() + " was authorized to " + caInfos.size() + " CAs.");
                }
                for (final CAInfo caInfo : caInfos) {
                    if (caId == caInfo.getCAId()) {
                        chain = new ArrayList<>(caInfo.getCertificateChain());
                        break;
                    }
                }
            } catch (NumberFormatException e) {
                log.debug("Unable to parse " + PARAMETER_CAID + " request parameter: " + e.getMessage());
            }
            if (chain==null) {
                httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unable to parse " + PARAMETER_CAID + " request parameter.");
                return;
            } else {
                try {
                    final Certificate caCertificate = chain.get(0);
                    String filename = RequestHelper.getFileNameFromCertNoEnding(caCertificate, "ca");
                    String contentType = "application/octet-stream";
                    byte[] response = null;
                    if (fullChain) {
                        switch (httpServletRequest.getParameter(PARAMETER_FORMAT)) {
                        case PARAMETER_FORMAT_OPTION_JKS: {
                            // Create a JKS truststore with the CA certificates in
                            final KeyStore keyStore = KeyStore.getInstance("JKS");
                            keyStore.load(null, null);
                            for (int i=0; i<chain.size(); i++) {
                                final String subjectDn = CertTools.getSubjectDN(chain.get(i));
                                String alias = CertTools.getPartFromDN(subjectDn, "CN");
                                if (alias == null) {
                                    alias = CertTools.getPartFromDN(subjectDn, "O");
                                }
                                if (alias == null) {
                                    alias = "cacert"+i;
                                }
                                alias.replaceAll(" ", "_").substring(0, Math.min(15, alias.length()));
                                keyStore.setCertificateEntry(alias, chain.get(i));
                            }
                            try (ByteArrayOutputStream out = new ByteArrayOutputStream();) {
                                keyStore.store(out, "changeit".toCharArray());
                                response = out.toByteArray();
                            }
                            filename += "-chain.jks";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_P7C: {
                            response = CertTools.createCertsOnlyCMS(CertTools.convertCertificateChainToX509Chain(chain));
                            filename += "-chain.p7c";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_PEM:
                        default: {
                            response = CertTools.getPemFromCertificateChain(chain);
                            filename += "-chain.pem";
                            break;
                        }
                        }
                    } else {
                        response = caCertificate.getEncoded();
                        switch (httpServletRequest.getParameter(PARAMETER_FORMAT)) {
                        case PARAMETER_FORMAT_OPTION_FIREFOX: {
                            filename = null;
                            contentType = "application/x-x509-ca-cert";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_DER: {
                            filename += (caCertificate instanceof CardVerifiableCertificate) ? ".cvcert" : ".crt";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_P7C: {
                            response = CertTools.createCertsOnlyCMS(CertTools.convertCertificateChainToX509Chain(Arrays.asList(new Certificate[]{ caCertificate })));
                            filename += ".p7c";
                            break;
                        }
                        case PARAMETER_FORMAT_OPTION_PEM:
                        default: {
                            filename += ".pem";
                            response = CertTools.getPemFromCertificateChain(Arrays.asList(new Certificate[]{ caCertificate }));
                            break;
                        }
                        }
                    }
                    writeResponseBytes(httpServletResponse, filename, contentType, response);
                } catch (NoSuchFieldException | KeyStoreException | NoSuchAlgorithmException | CertificateException | ClassCastException | CMSException e) {
                    httpServletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unable to serve request due to internal error.");
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to provide certificate download to client. " + e.getMessage());
                    }
                    return;
                }
            }
        } else if (httpServletRequest.getParameter(PARAMETER_FINGERPRINT) != null) {
            final String fingerprint = httpServletRequest.getParameter(PARAMETER_FINGERPRINT);
            // Serving regular leaf certificate (optionally with full chain)
            final AuthenticationToken authenticationToken = raAuthenticationHelper.getAuthenticationToken(httpServletRequest, httpServletResponse);
            final List<CAInfo> caInfos = raMasterApi.getAuthorizedCas(authenticationToken);
            // Only process request if there is a chance the client is authorized to the CA that issued it
            if (!caInfos.isEmpty()) {
                final CertificateDataWrapper cdw = raMasterApi.searchForCertificate(authenticationToken, fingerprint);
                if (cdw!=null) {
                    for (final CAInfo caInfo : caInfos) {
                        if (caInfo.getSubjectDN().equals(cdw.getCertificateData().getIssuerDN())) {
                            List<Certificate> chain = new ArrayList<>();
                            chain.add(cdw.getCertificate());
                            if (fullChain) {
                                chain.addAll(caInfo.getCertificateChain());
                            }
                            try {
                                byte[] response = null;
                                String filename = "cert"+fingerprint;
                                switch (httpServletRequest.getParameter(PARAMETER_FORMAT)) {
                                case PARAMETER_FORMAT_OPTION_DER: {
                                    response = chain.get(0).getEncoded();
                                    filename += (chain.get(0) instanceof CardVerifiableCertificate) ? ".cvcert" : ".crt";
                                    break;
                                }
                                case PARAMETER_FORMAT_OPTION_P7C: {
                                    response = CertTools.createCertsOnlyCMS(CertTools.convertCertificateChainToX509Chain(chain));
                                    if (fullChain) {
                                        filename += "-chain";
                                    }
                                    filename += ".p7c";
                                    break;
                                }
                                case PARAMETER_FORMAT_OPTION_PEM:
                                default: {
                                    response = CertTools.getPemFromCertificateChain(chain);
                                    if (fullChain) {
                                        filename += "-chain";
                                    }
                                    filename += ".pem";
                                    break;
                                }
                                }
                                writeResponseBytes(httpServletResponse, filename, "application/octet-stream", response);
                                return;
                            } catch (CertificateEncodingException | ClassCastException | CMSException e) {
                                log.warn("Failed to provide download of certificate with fingerprint " + fingerprint);
                            }
                        }
                    }
                }
            }
            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unable to parse " + PARAMETER_FINGERPRINT + " request parameter.");
        } else {
            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unable to request parameters.");
        }
    }

    private void writeResponseBytes(final HttpServletResponse httpServletResponse, final String filename, final String contentType, final byte[] response) throws IOException {
        ServletUtils.removeCacheHeaders(httpServletResponse);
        if (filename!=null) {
            httpServletResponse.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        }
        httpServletResponse.setContentType(contentType);
        httpServletResponse.setContentLength(response.length);
        httpServletResponse.getOutputStream().write(response);
    }

    /**
     * Creates and outputs a YAML document containing the CA certificate fingerprints of all active Certification Authorities
     * on this system to which the current user has access. The CA certificate fingerprints are computed using SHA-256.
     * <p>Certification Authorities without a certificate, i.e. CAs with status {@link org.cesecore.certificates.ca.CAConstants#CA_UNINITIALIZED} or
     * {@link org.cesecore.certificates.ca.CAConstants#CA_WAITING_CERTIFICATE_RESPONSE} are excluded.
     * @param httpServletRequest the HTTP request for CA certificate fingerprints
     * @param httpServletResponse the HTTP response to which the fingerprint sheet should be written
     * @throws IOException if an error occurred when creating the response
     */
    public void downloadFingerprintSheet(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse)
            throws IOException {
        final Map<String, Object> entries = new LinkedHashMap<>();
        final AuthenticationToken authenticationToken = raAuthenticationHelper.getAuthenticationToken(httpServletRequest, httpServletResponse);
        for (final CAInfo caInfo : raMasterApi.getAuthorizedCas(authenticationToken)) {
            if (caInfo.getCertificateChain() == null || caInfo.getCertificateChain().size() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Not computing CA certificate fingerprint for CA " + caInfo.getName()
                            + " because no CA certificate is available. Status of this CA is " + caInfo.getStatus());
                }
                continue;
            }
            try {
                final Certificate caCertificate = caInfo.getCertificateChain().get(0);
                final String caFingerprint = Hex.encodeHexString(CertTools.generateSHA256Fingerprint(caCertificate.getEncoded()));
                final Map<String, Object> caEntry = new LinkedHashMap<>();
                final Map<String, String> fingerprintEntry = new LinkedHashMap<>();
                fingerprintEntry.put("Algorithm", "SHA-256");
                fingerprintEntry.put("Fingerprint", caFingerprint.toUpperCase());
                caEntry.put("Subject DN", caInfo.getSubjectDN());
                caEntry.put("CA Certificate Fingerprint", fingerprintEntry);
                entries.put(caInfo.getName(), caEntry);
                if (log.isDebugEnabled()) {
                    log.debug("Computed CA certificate fingerprint for CA " + caInfo.getName() + ".");
                }
            } catch (final CertificateEncodingException e) {
                log.warn("Cannot compute CA certificate fingerprint for CA " + caInfo.getName()
                        + " because the CA certificate could not be encoded. The error was: " + e.getMessage());
                continue;
            }
        }
        final DumperOptions dumperOptions = new DumperOptions();
        dumperOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        dumperOptions.setPrettyFlow(true);
        final Yaml yaml = new Yaml(dumperOptions);
        log.info("User " + authenticationToken.toString() + " requested a CA certificate fingerprint file.");
        writeResponseBytes(httpServletResponse, "fingerprints.yaml", "text/plain; charset=utf-8",
                yaml.dumpAsMap(entries).getBytes(Charset.forName("UTF-8")));
    }

    /**
     * Creates and outputs a compressed certificate bundle containing the CA certificates of all active Certification Authorities
     * on this system to which the current user has access. The certificate bundle is provided as a zip file of DER-encoded certificates.
     * <p>Certification Authorities without a certificate, i.e. CAs with status {@link org.cesecore.certificates.ca.CAConstants#CA_UNINITIALIZED} or
     * {@link org.cesecore.certificates.ca.CAConstants#CA_WAITING_CERTIFICATE_RESPONSE} are excluded.
     * @param httpServletRequest the HTTP request for a certificate bundle
     * @param httpServletResponse the HTTP response to which the certificate bundle should be written
     * @throws IOException if an error occurred when creating the response
     */
    private void downloadCertificateBundle(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse)
            throws IOException {
        try (final ByteArrayOutputStream zipContent = new ByteArrayOutputStream()) {
            try (final ZipOutputStream certificateBundle = new ZipOutputStream(zipContent)) {
                final AuthenticationToken authenticationToken = raAuthenticationHelper.getAuthenticationToken(httpServletRequest, httpServletResponse);
                for (final CAInfo caInfo : raMasterApi.getAuthorizedCas(authenticationToken)) {
                    if (caInfo.getCertificateChain() == null || caInfo.getCertificateChain().size() == 0) {
                        if (log.isDebugEnabled()) {
                            log.debug("Not adding CA certificate for CA " + caInfo.getName()
                                    + " to certificate bundle because no CA certificate is available. Status of this CA is " + caInfo.getStatus());
                        }
                        continue;
                    }
                    try {
                        final byte[] encodedCertificate = caInfo.getCertificateChain().get(0).getEncoded();
                        final String filename = caInfo.getName() + ".crt";
                        certificateBundle.putNextEntry(new ZipEntry(filename));
                        certificateBundle.write(encodedCertificate);
                        certificateBundle.closeEntry();
                        if (log.isDebugEnabled()) {
                            log.debug("Added CA certificate for CA " + caInfo.getName() + " to certificate bundle.");
                        }
                    } catch (final CertificateEncodingException e) {
                        log.warn("Cannot add CA certificate for CA " + caInfo.getName()
                                + " to certificate bundle because the CA certificate could not be encoded. The error was: " + e.getMessage());
                        continue;
                    }
                }
                log.info("User " + authenticationToken.toString() + " requested a CA certificate bundle.");
            }
            writeResponseBytes(httpServletResponse, "certbundle.zip", "application/octet-stream", zipContent.toByteArray());
        }
    }
}
