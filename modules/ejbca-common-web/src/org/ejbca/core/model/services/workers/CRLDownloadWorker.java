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
package org.ejbca.core.model.services.workers;

import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.math.IntRange;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CrlImportException;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.util.CertTools;
import org.cesecore.util.NetworkTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;

/**
 * Worker used for downloading external CRLs and populating the local database with limited CertificateData entries,
 * that can be used to service OCSP responses and stores the CRL locally, so it could be served for example through
 * the public web.
 * <p>
 * If the freshest CRL extension is present in a full CRL, the delta CRL will be downloaded and processed as well.
 * <p>
 * The worker can be configured to not respect the nextUpdate
 *
 * @version $Id$
 */
public class CRLDownloadWorker extends BaseWorker {
    private static final Logger log = Logger.getLogger(CRLDownloadWorker.class);

    public static final String PROP_IGNORE_NEXT_UPDATE = "ignoreNextUpdate";
    public static final String PROP_MAX_DOWNLOAD_SIZE = "maxDownloadSize";
    public static final int DEFAULT_MAX_DOWNLOAD_SIZE = 1 * 1024 * 1024;

    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        //This service worker has no other error states than misconfiguration, so can technically always run.       
    }
    
    @Override
    public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) {
        // Get references to all EJB's that will be used
        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        final CrlStoreSessionLocal crlStoreSession = (CrlStoreSessionLocal) ejbs.get(CrlStoreSessionLocal.class);
        final ImportCrlSessionLocal importCrlSession = (ImportCrlSessionLocal) ejbs.get(ImportCrlSessionLocal.class);
        // Parse worker configuration
        Collection<Integer> caIdsToCheck;
        try {
            caIdsToCheck = getCAIdsToCheck(true);
        } catch (ServiceExecutionFailedException e) {
            throw new IllegalStateException(e);
        }
        if (caIdsToCheck != null && caIdsToCheck.contains(CAConstants.ALLCAS)) {
            caIdsToCheck = caSession.getAllCaIds();
        }
        if(caIdsToCheck.isEmpty()) {
            return new ServiceExecutionResult(Result.NO_ACTION, "CRL Download Worker " + serviceName + " ran, but has no CAs configured.");
        }
        // Process all the configured CAs
        List<String> failedCas = new ArrayList<>();
        List<String> checkedCas = new ArrayList<>();
        for (final int caId : caIdsToCheck) {
            if (log.isTraceEnabled()) {
                log.trace("Processing CA with Id " + caId);
            }
            final CAInfo caInfo = caSession.getCAInfoInternal(caId);
            if (caInfo != null && caInfo.getCAType() == CAInfo.CATYPE_X509 && caInfo.getStatus() == CAConstants.CA_EXTERNAL) {
                final X509Certificate caCertificate = (X509Certificate) caInfo.getCertificateChain().iterator().next();
                // Parse the configured external CDP into a URL
                final String cdp = ((X509CAInfo) caInfo).getExternalCdp();
                if (cdp == null || cdp.length() == 0) {
                    log.info("No external CDP configured for CA '" + caInfo.getName() + "'. Ignoring CA.");
                    continue;
                }
                final URL url = NetworkTools.getValidHttpUrl(cdp);
                if (url == null) {
                    log.info("Invalid HTTP URL '" + cdp + "' in external CDP configured for CA '" + caInfo.getName() + "'. Ignoring CA.");
                    continue;
                }
                final Date now = new Date();
                IntRange crlPartitionIndexes = caInfo.getAllCrlPartitionIndexes();
                try {
                    getCrlAndUpdateIfNeeded(caInfo, caCertificate, url, CertificateConstants.NO_CRL_PARTITION, now, crlStoreSession,
                            importCrlSession);
                    checkedCas.add(caInfo.getName());
                } catch (ServiceExecutionFailedException e) {
                    failedCas.add(caInfo.getName());
                }
                if (crlPartitionIndexes != null) {
                    for (int i = crlPartitionIndexes.getMinimumInteger(); i <= crlPartitionIndexes.getMaximumInteger(); i++) {
                        final URL partitionUrl = NetworkTools.getValidHttpUrl(((X509CAInfo) caInfo).getCrlPartitionUrl(cdp, i));
                        try {
                            getCrlAndUpdateIfNeeded(caInfo, caCertificate, partitionUrl, i, now, crlStoreSession, importCrlSession);
                        } catch (ServiceExecutionFailedException e) {
                            failedCas.add(caInfo.getName());
                        }
                    }
                }
               
            } else {
                log.info("'" + (caInfo != null ? caInfo.getName() : caId) + "' is not an external X509 CA. Ignoring.");
            }
        }
        if (checkedCas.isEmpty()) {
            return new ServiceExecutionResult(Result.NO_ACTION, "CRL Download Worker " + serviceName + " ran, but has no external CAs exist.");
        } else {
            if (failedCas.isEmpty()) {
                return new ServiceExecutionResult(Result.SUCCESS, "All external CA's were sucessfully checked for updated CRLs by CRL Download Worker " + serviceName);
            } else {
                return new ServiceExecutionResult(Result.FAILURE,
                        "CRL Download Worker " + serviceName + " ran. All external CA's were checked for updated CRLs, but the following CA's CDPs were unreachable: "
                                + constructNameList(failedCas));
            }
        }
    }

    /**
     * @throws ServiceExecutionFailedException if the CRL failed to download
     */
    private void getCrlAndUpdateIfNeeded(final CAInfo caInfo, final X509Certificate caCertificate, final URL url, final int crlPartitionIndex, final Date now,
                                         final CrlStoreSessionLocal crlStoreSession, final ImportCrlSessionLocal importCrlSession) throws ServiceExecutionFailedException {
        try {
            final String issuerDn = CertTools.getSubjectDN(caCertificate);
            final boolean ignoreNextUpdate = Boolean.valueOf(properties.getProperty(PROP_IGNORE_NEXT_UPDATE, Boolean.FALSE.toString()));
            // Get last known CRL (if any) and check when the next update will be
            final X509CRL lastFullCrl = getCRLFromBytes(crlStoreSession.getLastCRL(issuerDn, crlPartitionIndex, false));
            final X509CRL newestFullCrl;
            if (!ignoreNextUpdate && lastFullCrl != null && now.before(lastFullCrl.getNextUpdate())) {
                log.info("Next full CRL update for CA '" + caInfo.getName() + "' will be " + ValidityDate.formatAsISO8601(lastFullCrl.getNextUpdate(), null) + ". Skipping download.");
                newestFullCrl = lastFullCrl;
            } else {
                final X509CRL downloadedFullCrl = getAndProcessCrl(url, caCertificate, caInfo, importCrlSession, crlPartitionIndex);
                if (downloadedFullCrl == null) {
                    newestFullCrl = lastFullCrl;
                } else {
                    newestFullCrl = downloadedFullCrl;
                }
            }
            if (newestFullCrl != null) {
                final List<String> freshestCdps = CrlExtensions.extractFreshestCrlDistributionPoints(newestFullCrl);
                if (!freshestCdps.isEmpty()) {
                    // Delta CRLs are used and we might already have a valid one stored
                    X509CRL lastDeltaCrl = getCRLFromBytes(crlStoreSession.getLastCRL(issuerDn, crlPartitionIndex, true));
                    if (lastDeltaCrl != null && lastDeltaCrl.getThisUpdate().before(newestFullCrl.getThisUpdate())) {
                        // The last known delta CRL info is already included in the latest full CRL, so treat the last delta as non-existent
                        lastDeltaCrl = null;
                    }
                    if (!ignoreNextUpdate && lastDeltaCrl != null && now.before(lastDeltaCrl.getNextUpdate())) {
                        log.info("Next delta CRL update for CA '" + caInfo.getName() + "' will be " + ValidityDate.formatAsISO8601(lastDeltaCrl.getNextUpdate(), null) + ". Skipping download.");
                    } else {
                        // Check for and process first delta CRL that can be reached over HTTP (if any)
                        for (final String freshestCdp : freshestCdps) {
                            final URL freshestCdpUrl = NetworkTools.getValidHttpUrl(freshestCdp);
                            if (freshestCdpUrl == null) {
                                log.info("Unusable Freshest CDP HTTP URL '" + freshestCdp + "' in CRL. Skipping download.");
                                continue;
                            }
                            final X509CRL newDeltaCrl = getAndProcessCrl(freshestCdpUrl, caCertificate, caInfo, importCrlSession, crlPartitionIndex);
                            if (newDeltaCrl != null) {
                                break;
                            }
                        }
                    }
                }
            }
        } catch (CRLException e) {
            log.error("Last known CRL read from the database for CA Id " + caInfo.getCAId() + " has encoding problems.", e);
        } catch (CrlStoreException e) {
            log.error("Failed to store the downloaded CRL in the database for CA Id " + caInfo.getCAId() + ".", e);
        } catch (CrlImportException e) {
            log.error("Failed to import the downloaded CRL in the database for CA Id " + caInfo.getCAId() + ".", e);
        } 
    }

    private X509CRL getCRLFromBytes(final byte[] crlBytes) throws CRLException {
        if (crlBytes != null) {
            return CertTools.getCRLfromByteArray(crlBytes);
        }
        return null;
    }

    private X509CRL getAndProcessCrl(final URL cdpUrl, final X509Certificate caCertificate, final CAInfo caInfo,
                                     final ImportCrlSessionLocal importCrlSession, final int crlPartitionIndex) throws CrlStoreException, CrlImportException, ServiceExecutionFailedException {
        final int maxSize = Integer.parseInt(properties.getProperty(PROP_MAX_DOWNLOAD_SIZE, String.valueOf(DEFAULT_MAX_DOWNLOAD_SIZE)));
        X509CRL newCrl = null;
        final byte[] crlBytesNew = NetworkTools.downloadDataFromUrl(cdpUrl, maxSize);
        if (crlBytesNew == null) {
            String msg = "Unable to download CRL for " + CertTools.getSubjectDN(caCertificate) + "  with url: " + cdpUrl;
            log.warn(msg);
            throw new ServiceExecutionFailedException(msg);
        } else {
            try {
                newCrl = CertTools.getCRLfromByteArray(crlBytesNew);
                importCrlSession.importCrl(admin, caInfo, crlBytesNew, crlPartitionIndex);
            } catch (CRLException e) {
                String msg = "Unable to decode downloaded CRL for '" + caInfo.getSubjectDN() + "'.";
                log.warn(msg, e);
                throw new ServiceExecutionFailedException(msg, e);
            } catch (AuthorizationDeniedException e) {
                log.error("Internal authentication token was deneied access to importing CRLs or revoking certificates.", e);
                return null;
            }
        }
        return newCrl;
    }


}
