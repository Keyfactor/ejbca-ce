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
package org.ejbca.core.ejb.crl;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.LimitedCertificateEntry;
import org.cesecore.certificates.crl.CrlImportException;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;

@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ImportCrlSessionBean implements ImportCrlSessionLocal, ImportCrlSessionRemote {

    private static final Logger log = Logger.getLogger(ImportCrlSessionBean.class);

    @EJB
    private CertificateStoreSessionLocal certStoreSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private EndEntityManagementSessionLocal endentityManagementSession;
    
    @Override
    public void importCrl(final AuthenticationToken authenticationToken, final CAInfo cainfo, final byte[] crlbytes, final int crlPartitionIndex)
            throws CrlImportException, CrlStoreException, CRLException, AuthorizationDeniedException {

        X509CRL x509crl = CertTools.getCRLfromByteArray(crlbytes);
        
        X509Certificate cacert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
        final String caFingerprint = CertTools.getFingerprintAsString(cacert);
        final String issuerDn = CertTools.getSubjectDN(cacert);
        
        verifyCrlIssuer(x509crl, issuerDn, cacert);
        
        // Check if the CRL is already stored locally
        final boolean isDeltaCrl = CrlExtensions.getDeltaCRLIndicator(x509crl).intValue() != -1;
        final int downloadedCrlNumber = CrlExtensions.getCrlNumber(x509crl).intValue();
        if (log.isTraceEnabled()) {
            log.trace("Delta CRL:  " + isDeltaCrl);
            log.trace("IssuerDn:   " + issuerDn);
            log.trace("CRL Number: " + downloadedCrlNumber);
            if (crlPartitionIndex != CertificateConstants.NO_CRL_PARTITION) {
                log.trace("CRL Partition: " + crlPartitionIndex);
            }
        }
        
        X509CRL lastCrlOfSameType = getLastCrlOfSameType(x509crl, isDeltaCrl, issuerDn, crlPartitionIndex);
        if (lastCrlOfSameType != null && !x509crl.getThisUpdate().after(lastCrlOfSameType.getThisUpdate())) {
            log.info((isDeltaCrl ? "Delta" : "Full") + " CRL number " + downloadedCrlNumber + " for CA '" + cainfo.getName() +
                    "' is not newer than last known " + (isDeltaCrl ? "delta" : "full") + " CRL. Ignoring download.");
            return;
        }
        
        // If the CRL is newer than the last known or there wasn't any old one, loop through it
        if (x509crl.getRevokedCertificates()==null) {
            log.info("No revoked certificates in " + (isDeltaCrl?"delta":"full") + " CRL for CA '" + cainfo.getName() + "'");
        } else {
            final Set<X509CRLEntry> crlEntries = new HashSet<X509CRLEntry>();
            crlEntries.addAll(x509crl.getRevokedCertificates());
            if (log.isDebugEnabled()) {
                log.debug("Downloaded CRL contains " + crlEntries.size() + " entries.");
            }
            
            if(lastCrlOfSameType != null && lastCrlOfSameType.getRevokedCertificates()!=null) {
                if (log.isDebugEnabled()) {
                    log.debug("Last known CRL contains " + lastCrlOfSameType.getRevokedCertificates().size() + " entries.");
                }
                // Remove all entries that were processed last time
                crlEntries.removeAll(lastCrlOfSameType.getRevokedCertificates());
            }
        
            log.info("Found " + crlEntries.size() + " new entires in " + (isDeltaCrl?"delta":"full")+ " CRL number " + downloadedCrlNumber + " issued by '" + issuerDn + "' compared to previous.");
            
            // Parse all CRL entries and collect serial numbers for bulk pre-fetch
            final List<ParsedCrlEntry> parsedEntries = new ArrayList<>(crlEntries.size());
            final Set<BigInteger> allSerialNumbers = new HashSet<>(crlEntries.size());
            for (final X509CRLEntry crlEntry : crlEntries) {
                final BigInteger serialNumber = crlEntry.getSerialNumber();
                final Date revocationDate = crlEntry.getRevocationDate();
                final Date invalidityDate;
                final ASN1GeneralizedTime asn1GeneralizedTime = CrlExtensions.extractInvalidityDate(crlEntry);
                if (asn1GeneralizedTime != null) {
                    Date parsedDate = null;
                    try {
                        parsedDate = asn1GeneralizedTime.getDate();
                    } catch (ParseException e) {
                        log.info("Failed to parse invalidityDate for crl entry with serial number " + serialNumber);
                    }
                    invalidityDate = parsedDate;
                } else {
                    invalidityDate = null;
                }
                final int reasonCode = CrlExtensions.extractReasonCode(crlEntry);
                if (crlEntry.getCertificateIssuer()!=null) {
                    final String entryIssuerDn = DnComponents.stringToBCDNString(crlEntry.getCertificateIssuer().getName());
                    if (!issuerDn.equals(entryIssuerDn)) {
                        log.warn("CA's subjectDN does not match CRL entry's issuerDn '"+entryIssuerDn+"' and entry with serialNumber " + serialNumber + " will be ignored.");
                        continue;
                    }
                }
                parsedEntries.add(new ParsedCrlEntry(serialNumber, revocationDate, invalidityDate, reasonCode, crlEntry));
                allSerialNumbers.add(serialNumber);
            }
            
            // Bulk pre-fetch all existing certificate data for the serial numbers in this CRL
            final Map<BigInteger, CertificateDataWrapper> existingCertificates = certStoreSession.getCertificateDataByIssuerAndSernos(issuerDn, allSerialNumbers);
            if (log.isDebugEnabled()) {
                log.debug("Pre-fetched " + existingCertificates.size() + " existing certificate entries for " + allSerialNumbers.size() + " serial numbers.");
            }
            
            // Separate entries into limited (batch-processable) and non-limited (individual revocation)
            final List<LimitedCertificateEntry> limitedEntries = new ArrayList<>();
            final List<ParsedCrlEntry> nonLimitedEntries = new ArrayList<>();
            for (final ParsedCrlEntry parsed : parsedEntries) {
                final CertificateDataWrapper cdw = existingCertificates.get(parsed.getSerialNumber());
                if (isLimitedCertificate(issuerDn, parsed.getSerialNumber(), cdw)) {
                    limitedEntries.add(new LimitedCertificateEntry(parsed.getSerialNumber(), parsed.getRevocationDate(), parsed.getInvalidityDate(), parsed.getReasonCode()));
                } else {
                    nonLimitedEntries.add(parsed);
                }
            }
            
            if (log.isInfoEnabled()) {
                log.info("Processing " + limitedEntries.size() + " limited certificate entries in batch and " + nonLimitedEntries.size() + " non-limited entries individually.");
            }
            
            // Batch persist all limited certificate entries (chunked into multiple transactions)
            if (!limitedEntries.isEmpty()) {
                certStoreSession.persistLimitedCertificateDataBatch(authenticationToken, cainfo.getCAId(), issuerDn, caFingerprint, existingCertificates, limitedEntries);
            }
            
            // Process non-limited entries individually (these are real certificates that need proper revocation)
            for (final ParsedCrlEntry parsed : nonLimitedEntries) {
                final String serialHex = parsed.getSerialNumber().toString(16).toUpperCase();
                log.info("Revoking '" + serialHex + "' " + "(" + parsed.getSerialNumber().toString() + ")");
                try {
                    endentityManagementSession.revokeCert(authenticationToken, parsed.getSerialNumber(), parsed.getCrlEntry().getRevocationDate(), parsed.getInvalidityDate(), issuerDn, parsed.getReasonCode(), false);
                } catch (AlreadyRevokedException e) {
                    log.warn("Failed to revoke '" + serialHex + "'. (Status might be 'Archived'.) Error message was: " + e.getMessage());
                } catch (ApprovalException | RevokeBackDateNotAllowedForProfileException | NoSuchEndEntityException | WaitingForApprovalException e) {
                    throw new CrlImportException("Failed to revoke certificate with serial number " + serialHex, e);
                }
            }
        }
        // Calculate (make up) the CRL Number if the number was not present
        final int newCrlNumber;
        if (downloadedCrlNumber==0) {
            final int lastCrlNumber = crlStoreSession.getLastCRLNumber(issuerDn, crlPartitionIndex, isDeltaCrl);
            newCrlNumber = lastCrlNumber+1;
        } else {
            newCrlNumber = downloadedCrlNumber;
        }
        // Last of all, store the CRL if there were no errors during creation of database entries
        crlStoreSession.storeCRL(authenticationToken, x509crl.getEncoded(), caFingerprint, newCrlNumber, issuerDn, crlPartitionIndex, x509crl.getThisUpdate(), x509crl.getNextUpdate(), isDeltaCrl?1:-1);
    
    }
    
    private void verifyCrlIssuer(final X509CRL crl, final String issuerDN, final X509Certificate cacert) throws CrlImportException {
        log.info("CA: " + issuerDN);
        // Read the supplied CRL and verify that it is issued by the specified CA
        if (!crl.getIssuerX500Principal().equals(cacert.getSubjectX500Principal())) {
            throw new CrlImportException("CRL wasn't issued by " + issuerDN);
        }
        
        try {
            crl.verify(cacert.getPublicKey());
        } catch (InvalidKeyException | CRLException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            throw new CrlImportException("Failed to verify CRL signature.", e);
        }
    }
    
    private X509CRL getLastCrlOfSameType(final X509CRL crl, final boolean isDeltaCrl, final String issuerDN, final int crlPartitionIndex) {
        X509CRL lastCrlOfSameType = null;
        final byte[] lastCrl = crlStoreSession.getLastCRL(issuerDN, crlPartitionIndex, isDeltaCrl);
        if(lastCrl != null) {
            try {
                lastCrlOfSameType = CertTools.getCRLfromByteArray(lastCrl);
            } catch (CRLException e) {
                log.warn("Could not retrieve an older CRL issued by " + issuerDN, e);
            }
        }
        return lastCrlOfSameType;
    }
    
    private boolean isLimitedCertificate(final String issuerDn, final BigInteger serialNumber, final CertificateDataWrapper cdw) {
        final String limitedFingerprint = CertTools.getFingerprintAsString((issuerDn+";"+serialNumber).getBytes());
        return (cdw==null) || (limitedFingerprint.equals(cdw.getCertificateData().getFingerprint()));
    }

    /** Simple holder for parsed CRL entry data to avoid re-parsing. */
    private static final class ParsedCrlEntry {
        private final BigInteger serialNumber;
        private final Date revocationDate;
        private final Date invalidityDate;
        private final int reasonCode;
        private final X509CRLEntry crlEntry;

        ParsedCrlEntry(final BigInteger serialNumber, final Date revocationDate, final Date invalidityDate, final int reasonCode, final X509CRLEntry crlEntry) {
            this.serialNumber = serialNumber;
            this.revocationDate = revocationDate;
            this.invalidityDate = invalidityDate;
            this.reasonCode = reasonCode;
            this.crlEntry = crlEntry;
        }

        BigInteger getSerialNumber() {
            return serialNumber;
        }

        Date getRevocationDate() {
            return revocationDate;
        }

        Date getInvalidityDate() {
            return invalidityDate;
        }

        int getReasonCode() {
            return reasonCode;
        }

        X509CRLEntry getCrlEntry() {
            return crlEntry;
        }
    }

}
