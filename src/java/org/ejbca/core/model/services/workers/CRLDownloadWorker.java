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

import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.util.CertTools;
import org.cesecore.util.NetworkTools;
import org.cesecore.util.ValidityDate;
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
        final CertificateStoreSessionLocal certificateStoreSession = (CertificateStoreSessionLocal) ejbs.get(CertificateStoreSessionLocal.class);
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
                        final X509CRL downloadedFullCrl = getAndProcessCrl(url, maxDownloadSize, caCertificate, caInfo, crlStoreSession, certificateStoreSession, lastFullCrl, lastFullCrl);
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
                                    final X509CRL newDeltaCrl = getAndProcessCrl(freshestCdpUrl, maxDownloadSize, caCertificate, caInfo, crlStoreSession, certificateStoreSession, lastFullCrl, lastDeltaCrl);
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
    
    private X509CRL getAndProcessCrl(final URL cdpUrl, final int maxSize, final X509Certificate caCertificate, final CAInfo caInfo, final CrlStoreSessionLocal crlStoreSession,
            final CertificateStoreSessionLocal certificateStoreSession, final X509CRL lastFullCrl, final X509CRL lastCrlOfSameType) throws CrlStoreException, AuthorizationDeniedException {
        X509CRL newCrl = null;
        final byte[] crlBytesNew = NetworkTools.downloadDataFromUrl(cdpUrl, maxSize);
        if (crlBytesNew==null) {
            log.warn("Unable to download CRL for " + CertTools.getSubjectDN(caCertificate));
        } else {
            final String caFingerprint = CertTools.getFingerprintAsString(caCertificate);
            final String issuerDn = CertTools.getSubjectDN(caCertificate);
            try {
                newCrl = CertTools.getCRLfromByteArray(crlBytesNew);
                // Verify signature
                newCrl.verify(caCertificate.getPublicKey(), "BC");
            } catch (CRLException e) {
                log.warn("Unable to decode downloaded CRL for '" + issuerDn + "'.");
                return null;
            } catch (SignatureException e) {
                log.warn("Signature of the downloaded CRL could not be verfied with the CA certificate of the issuer '" + issuerDn + "'.", e);
                return null;
            } catch (InvalidKeyException e) {
                log.warn("Private key that signed the downloaded CRL does not match the public key of the issuer '" + issuerDn + "'.", e);
                return null;
            } catch (NoSuchAlgorithmException e) {
                log.warn("The signature algorithm used to sign the downloaded CRL is not available in this environment.", e);
                return null;
            } catch (NoSuchProviderException e) {
                log.warn("The signature provider used to verify the downloaded CRL is not available in this environment.", e);
                return null;
            }
            // Check if the CRL is already stored locally
            final boolean isDeltaCrl = CrlExtensions.getDeltaCRLIndicator(newCrl).intValue() != -1;
            final int downloadedCrlNumber = CrlExtensions.getCrlNumber(newCrl).intValue();
            if (log.isTraceEnabled()) {
                log.trace("Delta CRL:  " + isDeltaCrl);
                log.trace("IssuerDn:   " + issuerDn);
                log.trace("CRL Number: " + downloadedCrlNumber);
            }
            if (lastFullCrl!=null && !newCrl.getThisUpdate().after(lastFullCrl.getThisUpdate())) {
                log.info((isDeltaCrl?"Delta":"Full") + " CRL number " + downloadedCrlNumber + " for CA '" + caInfo.getName() + "' is not newer than last known full CRL. Ignoring download.");
                return null;
            }
            if (isDeltaCrl && lastCrlOfSameType!=null && !newCrl.getThisUpdate().after(lastCrlOfSameType.getThisUpdate())) {
                log.info("Delta CRL number " + downloadedCrlNumber + " for CA '" + caInfo.getName() + "' is not newer than last known delta CRL. Ignoring download.");
                return null;
            }
            // If the CRL is newer than the last known or there wasn't any old one, loop through it
            if (newCrl.getRevokedCertificates()==null) {
                log.info("No revoked certificates in CRL for CA '" + caInfo.getName() + "'");
            } else {
                final Set<X509CRLEntry> crlEntries = new HashSet<X509CRLEntry>();
                crlEntries.addAll(newCrl.getRevokedCertificates());
                if (log.isTraceEnabled()) {
                    log.info("Downloaded CRL contains " + crlEntries.size() + " entries.");
                }
                if (lastCrlOfSameType != null && lastCrlOfSameType.getRevokedCertificates()!=null) {
                    if (log.isTraceEnabled()) {
                        log.info("Last known CRL contains " + lastCrlOfSameType.getRevokedCertificates().size() + " entries.");
                    }
                    // Remove all entries that were processed last time
                    crlEntries.removeAll(lastCrlOfSameType.getRevokedCertificates());
                }
                log.info("Found " + crlEntries.size() + " new entires in " + (isDeltaCrl?"delta":"full")+ " CRL number " + downloadedCrlNumber + " issued by '" + issuerDn + "' compared to previous.");
                // For each entry that was updated after the last known CRL, create/update a new database entry with the new status
                for (final X509CRLEntry crlEntry : crlEntries) {
                    final Date revocationDate = crlEntry.getRevocationDate();
                    final BigInteger serialNumber = crlEntry.getSerialNumber();
                    final int reasonCode = CrlExtensions.extractReasonCode(crlEntry);
                    if (crlEntry.getCertificateIssuer()!=null) {
                        final String entryIssuerDn = CertTools.stringToBCDNString(crlEntry.getCertificateIssuer().getName());
                        if (!issuerDn.equals(entryIssuerDn)) {
                            log.info("CA's subjectDN does not match CRL entry's issuerDn '"+entryIssuerDn+"' and entry with serialNumber " + serialNumber + " will be ignored.");
                        }
                    }
                    // Store as much as possible about what we know about the certificate and its status (which is limited) in the database
                    certificateStoreSession.updateLimitedCertificateDataStatus(getAdmin(), caInfo.getCAId(), issuerDn, serialNumber, revocationDate, reasonCode, caFingerprint);
                }
                // Calculate the CRL Number
                final int newCrlNumber;
                if (downloadedCrlNumber==0) {
                    final int lastCrlNumber = crlStoreSession.getLastCRLNumber(issuerDn, isDeltaCrl);
                    newCrlNumber = lastCrlNumber+1;
                } else {
                    newCrlNumber = downloadedCrlNumber;
                }
                // Last of all, store the CRL if the creation of database entries were successful
                crlStoreSession.storeCRL(admin, crlBytesNew, caFingerprint, newCrlNumber, issuerDn, newCrl.getThisUpdate(), newCrl.getNextUpdate(), isDeltaCrl?1:-1);
            }
        }
        return newCrl;
    }
}
