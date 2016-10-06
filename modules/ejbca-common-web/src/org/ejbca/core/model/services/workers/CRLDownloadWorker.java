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
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
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

/**
 * Worker used for downloading external CRLs and populating the local database with limited CertificateData entries,
 * that can be used to service OCSP responses and stores the CRL locally, so it could be served for example through
 * the public web.
 * 
 * If the freshest CRL extension is present in a full CRL, the delta CRL will be downloaded and processed as well.
 * 
 * The worker can be configured to not respect the nextUpdate
 * 
 * @version $Id$
 */
public class CRLDownloadWorker extends BaseWorker {
    private static final Logger log = Logger.getLogger(CRLDownloadWorker.class);

    public static final String PROP_IGNORE_NEXT_UPDATE = "ignoreNextUpdate";
    public static final String PROP_MAX_DOWNLOAD_SIZE = "maxDownloadSize";
    public static final int DEFAULT_MAX_DOWNLOAD_SIZE = 1*1024*1024;

    @Override
    public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // Get references to all EJB's that will be used
        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        final CrlStoreSessionLocal crlStoreSession = (CrlStoreSessionLocal) ejbs.get(CrlStoreSessionLocal.class);
        final ImportCrlSessionLocal importCrlSession = (ImportCrlSessionLocal) ejbs.get(ImportCrlSessionLocal.class);
        // Parse worker configuration
        Collection<Integer> caIdsToCheck = getCAIdsToCheck(true);
        if (caIdsToCheck!=null && caIdsToCheck.contains(Integer.valueOf(CAConstants.ALLCAS))) {
            caIdsToCheck = caSession.getAllCaIds();
        }
        final boolean ignoreNextUpdate = Boolean.valueOf(properties.getProperty(PROP_IGNORE_NEXT_UPDATE, Boolean.FALSE.toString()));
        final int maxDownloadSize = Integer.parseInt(properties.getProperty(PROP_MAX_DOWNLOAD_SIZE, String.valueOf(DEFAULT_MAX_DOWNLOAD_SIZE)));
        // Process all the configured CAs
        for (final int caId : caIdsToCheck) {
            if (log.isTraceEnabled()) {
                log.trace("Processing CA with Id " + caId);
            }
            try {
                final CAInfo caInfo = caSession.getCAInfoInternal(caId);
                if (caInfo.getCAType() == CAInfo.CATYPE_X509 && caInfo.getStatus() == CAConstants.CA_EXTERNAL) {
                    final X509Certificate caCertificate = (X509Certificate) caInfo.getCertificateChain().iterator().next();
                    // Parse the configured external CDP into a URL
                    final String cdp = ((X509CAInfo)caInfo).getExternalCdp();
                    if (cdp==null || cdp.length()==0) {
                        log.info("No external CDP configured for CA '" + caInfo.getName() + "'. Ignoring CA.");
                        continue;
                    }
                    final URL url = NetworkTools.getValidHttpUrl(cdp);
                    if (url==null) {
                        log.info("Invalid HTTP URL '" + cdp + "' in external CDP configured for CA '" + caInfo.getName() + "'. Ignoring CA.");
                        continue;
                    }
                    final String issuerDn = CertTools.getSubjectDN(caCertificate);
                    // Get last known CRL (if any) and check when the next update will be
                    final Date now = new Date();
                    final X509CRL lastFullCrl = getCRLFromBytes(crlStoreSession.getLastCRL(issuerDn, false));
                    final X509CRL newestFullCrl;
                    if (!ignoreNextUpdate && lastFullCrl!=null && now.before(lastFullCrl.getNextUpdate())) {
                        log.info("Next full CRL update for CA '" + caInfo.getName() + "' will be " + ValidityDate.formatAsISO8601(lastFullCrl.getNextUpdate(), null) + ". Skipping download.");
                        newestFullCrl = lastFullCrl;
                    } else {
                        final X509CRL downloadedFullCrl = getAndProcessCrl(url, maxDownloadSize, caCertificate, caInfo, importCrlSession);
                        if (downloadedFullCrl==null) {
                            newestFullCrl = lastFullCrl;
                        } else {
                            newestFullCrl = downloadedFullCrl;
                        }
                    }
                    if (newestFullCrl!=null) {
                        final List<String> freshestCdps = CrlExtensions.extractFreshestCrlDistributionPoints(newestFullCrl);
                        if (!freshestCdps.isEmpty()) {
                            // Delta CRLs are used and we might already have a valid one stored
                            X509CRL lastDeltaCrl = getCRLFromBytes(crlStoreSession.getLastCRL(issuerDn, true));
                            if (lastDeltaCrl!=null && lastDeltaCrl.getThisUpdate().before(newestFullCrl.getThisUpdate())) {
                                // The last known delta CRL info is already included in the latest full CRL, so treat the last delta as non-existent
                                lastDeltaCrl = null;
                            }
                            if (!ignoreNextUpdate && lastDeltaCrl!=null && now.before(lastDeltaCrl.getNextUpdate())) {
                                log.info("Next delta CRL update for CA '" + caInfo.getName() + "' will be " + ValidityDate.formatAsISO8601(lastDeltaCrl.getNextUpdate(), null) + ". Skipping download.");
                            } else {
                                // Check for and process first delta CRL that can be reached over HTTP (if any)
                                for (final String freshestCdp : freshestCdps) {
                                    final URL freshestCdpUrl = NetworkTools.getValidHttpUrl(freshestCdp);
                                    if (freshestCdpUrl==null) {
                                        log.info("Unusable Freshest CDP HTTP URL '" + freshestCdpUrl + "' in CRL. Skipping download.");
                                        continue;
                                    }
                                    final X509CRL newDeltaCrl = getAndProcessCrl(freshestCdpUrl, maxDownloadSize, caCertificate, caInfo, importCrlSession);
                                    if (newDeltaCrl!=null) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    log.info("'" + caInfo.getName() + "' is not an external X509 CA. Ignoring.");
                }
            } catch (CADoesntExistsException e) {
                log.warn("Configured CA with id " + caId + " no longer exists and will not be processed.");
            } catch (CRLException e) {
                log.error("Last known CRL read from the database for CA Id " + caId + " has encoding problems.", e);
            } catch (CrlStoreException e) {
                log.error("Failed to store the downloaded CRL in the database for CA Id " + caId + ".", e);
            } catch (CrlImportException e) {
                log.error("Failed to import the downloaded CRL in the database for CA Id " + caId + ".", e);
            } catch (AuthorizationDeniedException e) {
                throw new ServiceExecutionFailedException("Service should always be authorized to any CA.", e);
            }
        }
    }
    
    private X509CRL getCRLFromBytes(final byte[] crlBytes) throws CRLException {
        if (crlBytes != null) {
            return CertTools.getCRLfromByteArray(crlBytes);
        }
        return null;
    }
    
    private X509CRL getAndProcessCrl(final URL cdpUrl, final int maxSize, final X509Certificate caCertificate, final CAInfo caInfo,
            final ImportCrlSessionLocal importCrlSession) throws CrlStoreException, AuthorizationDeniedException, CrlImportException, CRLException {
        X509CRL newCrl = null;
        final byte[] crlBytesNew = NetworkTools.downloadDataFromUrl(cdpUrl, maxSize);
        if (crlBytesNew==null) {
            log.warn("Unable to download CRL for " + CertTools.getSubjectDN(caCertificate));
        } else {
            newCrl = CertTools.getCRLfromByteArray(crlBytesNew);
            importCrlSession.importCrl(admin, caInfo, crlBytesNew);
        }
        return newCrl;
    }
}
