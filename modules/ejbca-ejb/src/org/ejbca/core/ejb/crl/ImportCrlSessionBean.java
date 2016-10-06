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
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CrlImportException;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ImportCrlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ImportCrlSessionBean implements ImportCrlSessionLocal, ImportCrlSessionRemote {

    private static final Logger log = Logger.getLogger(ImportCrlSessionBean.class);

    @EJB
    private CertificateStoreSessionLocal certStoreSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private EndEntityManagementSessionLocal endentityManagementSession;
    
    @Override
    public void importCrl(AuthenticationToken authenticationToken, CAInfo cainfo, byte[] crlbytes)
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
        }
        
        X509CRL lastCrlOfSameType = getLastCrlOfSameType(x509crl, isDeltaCrl, issuerDn);
        
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
            // For each entry that was updated after the last known CRL, create/update a new database entry with the new status
            for (final X509CRLEntry crlEntry : crlEntries) {
                final Date revocationDate = crlEntry.getRevocationDate();
                final BigInteger serialNumber = crlEntry.getSerialNumber();
                final int reasonCode = CrlExtensions.extractReasonCode(crlEntry);
                if (crlEntry.getCertificateIssuer()!=null) {
                    final String entryIssuerDn = CertTools.stringToBCDNString(crlEntry.getCertificateIssuer().getName());
                    if (!issuerDn.equals(entryIssuerDn)) {
                        log.warn("CA's subjectDN does not match CRL entry's issuerDn '"+entryIssuerDn+"' and entry with serialNumber " + serialNumber + " will be ignored.");
                    }
                }
                
                if(isLimitedCertificate(issuerDn, serialNumber)) {
                    // Store as much as possible about what we know about the certificate and its status (which is limited) in the database
                    certStoreSession.updateLimitedCertificateDataStatus(authenticationToken, cainfo.getCAId(), issuerDn, serialNumber, revocationDate, reasonCode, caFingerprint);
                } else {
                    final String serialHex = serialNumber.toString(16).toUpperCase();
                    if (certStoreSession.isRevoked(issuerDn, serialNumber)) {
                        log.info("Certificate '" + serialHex + "' is already revoked");
                        continue;
                    }
                    log.info("Revoking '" + serialHex + "' " + "(" + serialNumber.toString() + ")");
                    try {
                        //log.info("Reason code: " + reason);
                        endentityManagementSession.revokeCert(authenticationToken, serialNumber, crlEntry.getRevocationDate(), issuerDn, reasonCode, false);
                    } catch (AlreadyRevokedException e) {
                        log.warn("Failed to revoke '" + serialHex + "'. (Status might be 'Archived'.) Error message was: " + e.getMessage());
                    } catch (ApprovalException | RevokeBackDateNotAllowedForProfileException | FinderException | WaitingForApprovalException e) {
                        throw new CrlImportException("Failed to revoke certificate with serial number " + serialHex, e);
                    }
                    
                }
            }
        }
        // Calculate (make up) the CRL Number if the number was not present
        final int newCrlNumber;
        if (downloadedCrlNumber==0) {
            final int lastCrlNumber = crlStoreSession.getLastCRLNumber(issuerDn, isDeltaCrl);
            newCrlNumber = lastCrlNumber+1;
        } else {
            newCrlNumber = downloadedCrlNumber;
        }
        // Last of all, store the CRL if there were no errors during creation of database entries
        crlStoreSession.storeCRL(authenticationToken, crlbytes, caFingerprint, newCrlNumber, issuerDn, x509crl.getThisUpdate(), x509crl.getNextUpdate(), isDeltaCrl?1:-1);
    
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
    
    private X509CRL getLastCrlOfSameType(final X509CRL crl, final boolean isDeltaCrl, final String issuerDN) {
        X509CRL lastCrlOfSameType = null;
        try {
            lastCrlOfSameType = CertTools.getCRLfromByteArray(crlStoreSession.getLastCRL(issuerDN, isDeltaCrl));
        } catch (CRLException e) {}

        if(lastCrlOfSameType!=null && !crl.getThisUpdate().after(lastCrlOfSameType.getThisUpdate())) {
            return null;
        }
        return lastCrlOfSameType;
    }
    
    private boolean isLimitedCertificate(final String issuerDn, final BigInteger serialNumber) {
        final String limitedFingerprint = CertTools.getFingerprintAsString((issuerDn+";"+serialNumber).getBytes());
        CertificateDataWrapper cdw = certStoreSession.getCertificateDataByIssuerAndSerno(issuerDn, serialNumber);
        return (cdw==null) || (limitedFingerprint.equals(cdw.getCertificateData().getFingerprint()));
    }

}
