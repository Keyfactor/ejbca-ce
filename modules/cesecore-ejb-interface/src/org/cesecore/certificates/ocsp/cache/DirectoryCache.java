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
package org.cesecore.certificates.ocsp.cache;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;

/**
 * This class contains a cache of the OCSP trusted directory, containing hard certificates. This class is built according to the thread safe enum
 * singleton pattern.
 * 
 * @version $Id$
 * 
 */
public enum DirectoryCache {
    INSTANCE;

    private static final Logger log = Logger.getLogger(DirectoryCache.class);

    private static final InternalResources intres = InternalResources.getInstance();

    private final int requestRestrictMethod = OcspConfiguration.getRestrictSignaturesByMethod();
    private final int signTrustValidTime = OcspConfiguration.getSignTrustValidTimeInSeconds();
    private final String signTrustDir = OcspConfiguration.getSignTrustDir();

    /** A list of CA's trusted for issuing certificates for signing requests */
    private Map<String, X509Certificate> trustedReqSigIssuers;
    private Map<String, X509Certificate> trustedReqSigSigners;

    /**
     * The interval on which new OCSP signing certs are loaded in seconds.
     */
    private long trustDirValidTo;

    private DirectoryCache()  {
        loadTrustDir();
    }

    public void loadTrustDir() throws OcspFailureException {
        // Check if we have a cached collection that is not too old
        if (requestRestrictMethod == OcspConfiguration.RESTRICTONISSUER) {
            if (trustedReqSigIssuers != null && trustDirValidTo > new Date().getTime()) {
                return;
            }
            try {
                trustedReqSigIssuers = getCertificatesFromDirectory(signTrustDir);
            } catch (IOException e) {
                throw new OcspFailureException("An error was encountered when extracting canonical path from directory " + signTrustDir, e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Loaded " + trustedReqSigIssuers == null ? "0" : trustedReqSigIssuers.size()
                        + " CA-certificates as trusted for OCSP-request signing");
            }
            trustDirValidTo = signTrustValidTime > 0 ? new Date().getTime() + signTrustValidTime : Long.MAX_VALUE;

        }
        if (requestRestrictMethod == OcspConfiguration.RESTRICTONSIGNER) {
            if (trustedReqSigSigners != null && trustDirValidTo > new Date().getTime()) {
                return;
            }
            try {
                trustedReqSigSigners = getCertificatesFromDirectory(signTrustDir);
            } catch (IOException e) {
                throw new OcspFailureException("An error was encountered when extracting canonical path from directory " + signTrustDir, e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Loaded " + trustedReqSigSigners == null ? "0" : trustedReqSigSigners.size()
                        + " Signer-certificates as trusted for OCSP-request signing");
            }
            trustDirValidTo = signTrustValidTime > 0 ? new Date().getTime() + signTrustValidTime : Long.MAX_VALUE;

        }
    }

    private Map<String, X509Certificate> getCertificatesFromDirectory(String certificateDir) throws IOException {
        // read all files from trustDir, expect that they are PEM formatted certificates
        CryptoProviderTools.installBCProvider();
        File dir = new File(certificateDir);
        Map<String, X509Certificate> trustedCerts = new HashMap<String, X509Certificate>();
        if (dir == null || dir.isDirectory() == false) {
            log.error(dir.getCanonicalPath() + " is not a directory.");
            throw new IllegalArgumentException(dir.getCanonicalPath() + " is not a directory.");
        }
        File files[] = dir.listFiles();
        if (files == null || files.length == 0) {
            String errMsg = intres.getLocalizedMessage("ocsp.errornotrustfiles", dir.getCanonicalPath());
            log.error(errMsg);
        }
        for (File file : files) {
            final String fileName = file.getCanonicalPath();
            // Read the file, don't stop completely if one file has errors in it
            try {
                byte[] bytes = FileTools
                        .getBytesFromPEM(FileTools.readFiletoBuffer(fileName), CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
                X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(bytes);
                String key = cert.getIssuerDN() + ";" + cert.getSerialNumber().toString(16);
                trustedCerts.put(key, cert);
            } catch (CertificateException e) {
                String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", fileName, "trustDir", e.getMessage());
                log.error(errMsg, e);
            } catch (IOException e) {
                String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", fileName, "trustDir", e.getMessage());
                log.error(errMsg, e);
            }
        }
        return trustedCerts;
    }

    /**
     * @return the trustedReqSigIssuers
     */
    public Map<String, X509Certificate> getTrustedReqSigIssuers() {
        return trustedReqSigIssuers;
    }

    /**
     * @return the trustedReqSigSigners
     */
    public Map<String, X509Certificate> getTrustedReqSigSigners() {
        return trustedReqSigSigners;
    }

}
