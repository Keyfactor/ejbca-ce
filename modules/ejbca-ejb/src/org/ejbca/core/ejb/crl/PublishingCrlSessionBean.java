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

import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CompressedCollection;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;

/**
 * This session bean provides a bridge between EJBCA and CESecore by incorporating CRL creation (CESeCore) with publishing (EJBCA)
 * into a single atomic action. 
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublishingCrlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublishingCrlSessionBean implements PublishingCrlSessionLocal, PublishingCrlSessionRemote {

    private static final Logger log = Logger.getLogger(PublishingCrlSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @Resource
    private SessionContext sessionContext;
    
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CrlCreateSessionLocal crlCreateSession;
    @EJB
    private CrlStoreSessionLocal crlSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
    private PublishingCrlSessionLocal publishingCrlSession;
    
    @PostConstruct
    public void postConstruct() {
        publishingCrlSession = sessionContext.getBusinessObject(PublishingCrlSessionLocal.class);
        // Install BouncyCastle provider if not available
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Override
    public int createCRLs(AuthenticationToken admin) throws AuthorizationDeniedException {
        return createCRLs(admin, null, 0);
    }

    @Override
    public int createDeltaCRLs(AuthenticationToken admin) throws AuthorizationDeniedException {
        return createDeltaCRLs(admin, null, 0);
    }
    
    @Override
    public int createCRLs(final AuthenticationToken admin, final Collection<Integer> caids, final long addtocrloverlaptime) throws AuthorizationDeniedException {
        final Collection<Integer> caIdsToProcess;
        if (caids==null || caids.contains(Integer.valueOf(CAConstants.ALLCAS))) {
            caIdsToProcess = caSession.getAllCaIds();
        } else {
            caIdsToProcess = caids;
        }
        int createdcrls = 0;
        for (final int caid : caIdsToProcess) {
            if (log.isDebugEnabled()) {
                log.debug("createCRLs for caid: " + caid);
            }
            try {
                if (publishingCrlSession.createCRLNewTransactionConditioned(admin, caid, addtocrloverlaptime)) {
                    createdcrls++;
                }
            } catch (CryptoTokenOfflineException | CAOfflineException | CADoesntExistsException e) {
                // Don't fail all generation just because one of the CAs had token offline or similar. 
                // Continue working with the others, but log an error message in system logs, use error logging 
                // since it might be something that should call for attention of the operators, CRL generation is important.
                String msg = intres.getLocalizedMessage("createcrl.errorcreate", caid, e.getMessage());
                log.error(msg, e);
            }
        }
        return createdcrls;
    }

    @Override
    public int createDeltaCRLs(final AuthenticationToken admin, final Collection<Integer> caids, long crloverlaptime) throws AuthorizationDeniedException {
        final Collection<Integer> caIdsToProcess;
        if (caids==null || caids.contains(Integer.valueOf(CAConstants.ALLCAS))) {
            caIdsToProcess = caSession.getAllCaIds();
        } else {
            caIdsToProcess = caids;
        }
        int createddeltacrls = 0;
        for (final int caid : caIdsToProcess) {
            if (log.isDebugEnabled()) {
                log.debug("createDeltaCRLs for caid: " + caid);
            }
            try {
                if (publishingCrlSession.createDeltaCRLnewTransactionConditioned(admin, caid, crloverlaptime)) {
                    createddeltacrls++;
                }
            } catch (CesecoreException e) {
                // Don't fail all generation just because one of the CAs had token offline or similar. 
                // Continue working with the others, but log a warning message in system logs.
                final String msg = intres.getLocalizedMessage("createcrl.errorcreate", caid, e.getMessage());
                log.error(msg, e);                  
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EventTypes.CRL_CREATION, EventStatus.FAILURE, ModuleTypes.CRL, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), null, null, details);              
            }
        }
        return createddeltacrls;
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean createCRLNewTransactionConditioned(AuthenticationToken admin, int caid, long addtocrloverlaptime) throws CryptoTokenOfflineException, CADoesntExistsException, AuthorizationDeniedException, CAOfflineException {
        boolean ret = false;
        final Date now = new Date();
        // Get CA checks authorization to the CA
        final CA ca = caSession.getCA(admin, caid);
        final CAInfo cainfo = ca.getCAInfo();
        try {
            if (cainfo.getStatus() == CAConstants.CA_EXTERNAL) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate CRL for external CA "+cainfo.getName());
                }
            } else if (cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate CRL for CA "+cainfo.getName() +" awaiting certificate response.");
                }
            } else if (cainfo.getStatus() == CAConstants.CA_REVOKED) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate CRL for CA "+cainfo.getName() +" that is revoked.");
                }
            } else if (cainfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate CRL for CA "+cainfo.getName() +" that is uninitialized.");
                }
            } else {
                if (cainfo instanceof X509CAInfo) {
                    final Certificate cacert = getCaCertificate(cainfo);
                    // Don't create CRLs if the CA has expired
                    if (cacert != null && CertTools.getNotAfter(cacert).after(now)) {
                        if (cainfo.getStatus() == CAConstants.CA_OFFLINE )  {
                            // Normal event to not create CRLs for CAs that are deliberately set off line
                            String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), Integer.valueOf(cainfo.getCAId()));                                                   
                            log.info(msg);
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Checking to see if CA '"+cainfo.getName()+"' ("+cainfo.getCAId()+") needs CRL generation.");
                            }
                            final String certSubjectDN = CertTools.getSubjectDN(cacert);
                            final CRLInfo lastBaseCrlInfo = crlSession.getLastCRLInfo(certSubjectDN, false);
                            if (log.isDebugEnabled()) {
                                if (lastBaseCrlInfo == null) {
                                    log.debug("Crlinfo was null");
                                } else {
                                    log.debug("Read crlinfo for CA: "+cainfo.getName()+", lastNumber="+lastBaseCrlInfo.getLastCRLNumber()+", expireDate="+lastBaseCrlInfo.getExpireDate());
                                }                                          
                            }
                            long crlissueinterval = cainfo.getCRLIssueInterval();
                            if (log.isDebugEnabled()) {
                                log.debug("crlissueinterval="+crlissueinterval);
                                log.debug("crloverlaptime="+cainfo.getCRLOverlapTime());                                   
                            }
                            long overlap = cainfo.getCRLOverlapTime() + addtocrloverlaptime; // Overlaptime is in minutes, default if crlissueinterval == 0
                            long nextUpdate = 0; // if crlinfo == 0, we will issue a crl now
                            if (lastBaseCrlInfo != null) {
                                // CRL issueinterval in hours. If this is 0, we should only issue a CRL when
                                // the old one is about to expire, i.e. when currenttime + overlaptime > expiredate
                                // if isseuinterval is > 0 we will issue a new CRL when currenttime > createtime + issueinterval
                                nextUpdate = lastBaseCrlInfo.getExpireDate().getTime(); // Default if crlissueinterval == 0
                                if (crlissueinterval > 0) {
                                    long u = lastBaseCrlInfo.getCreateDate().getTime() + crlissueinterval;
                                    // If this period for some reason (we missed to issue some?) is larger than when the CRL expires,
                                    // we need to issue one when the CRL expires
                                    if ((u + overlap) < nextUpdate) {
                                        nextUpdate = u;
                                        // When we issue CRLs before the real expiration date we don't use overlap
                                        overlap = 0;
                                    }
                                }                                   
                                if (log.isDebugEnabled()) {
                                    log.debug("Calculated nextUpdate to "+nextUpdate);
                                }
                            } else {
                                // If crlinfo is null (no crl issued yet) nextUpdate will be 0 and a new CRL should be generated
                                String msg = intres.getLocalizedMessage("createcrl.crlinfonull", cainfo.getName());                                                
                                log.info(msg);
                            }
                            if (now.getTime() + overlap >= nextUpdate) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Creating CRL for CA, because:"+now.getTime()+overlap+" >= "+nextUpdate);                                                
                                }
                                if (internalCreateCRL(admin, ca, lastBaseCrlInfo) != null) {
                                    ret = true;                                 
                                }
                            }
                        }
                    } else if (cacert != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Not creating CRL for expired CA "+cainfo.getName()+". CA subjectDN='"+CertTools.getSubjectDN(cacert)+"', expired: "+CertTools.getNotAfter(cacert));
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Not creating CRL for CA without CA certificate: "+cainfo.getName());
                        }
                    }
                }                                                          
            }
        } catch (CryptoTokenOfflineException e) {
            log.warn("Crypto token is offline for CA "+caid+" generating CRL.");
            throw e;            
        }
        return ret;
    }
        
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean createDeltaCRLnewTransactionConditioned(AuthenticationToken admin, int caid, long crloverlaptime) throws CryptoTokenOfflineException, CAOfflineException, CADoesntExistsException, AuthorizationDeniedException {
        boolean ret = false;
        final Date now = new Date();
        final CA ca = caSession.getCA(admin, caid);
        final CAInfo cainfo = ca.getCAInfo();
        try{
            if (cainfo.getStatus() == CAConstants.CA_EXTERNAL) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate delta CRL for external CA "+cainfo.getName());
                }
            } else if (cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate delta CRL for CA "+cainfo.getName() +" awaiting certificate response.");
                }
            } else if (cainfo.getStatus() == CAConstants.CA_REVOKED) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate delta CRL for CA "+cainfo.getName() +" that is revoked.");
                }
            } else if (cainfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
                if (log.isDebugEnabled()) {
                    log.debug("Not trying to generate delta CRL for CA "+cainfo.getName() +" that is uninitialized.");
                }
            } else {
                if (cainfo instanceof X509CAInfo) {
                    final Certificate cacert = getCaCertificate(cainfo);
                    // Don't create CRLs if the CA has expired
                    if (cacert != null && CertTools.getNotAfter(cacert).after(now)) {
                        if (cainfo.getDeltaCRLPeriod() > 0) {
                            if (cainfo.getStatus() == CAConstants.CA_OFFLINE) {
                                // Normal event to not create CRLs for CAs that are deliberately set off line
                                String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), Integer.valueOf(cainfo.getCAId()));                                                   
                                log.info(msg);
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("Checking to see if CA '"+cainfo.getName()+"' needs Delta CRL generation.");
                                }
                                final String certSubjectDN = CertTools.getSubjectDN(cacert);
                                final CRLInfo lastDeltaCrlInfo = crlSession.getLastCRLInfo(certSubjectDN, true);
                                if (log.isDebugEnabled()) {
                                    if (lastDeltaCrlInfo == null) {
                                        log.debug("DeltaCrlinfo was null");
                                    } else {
                                        log.debug("Read deltacrlinfo for CA: "+cainfo.getName()+", lastNumber="+lastDeltaCrlInfo.getLastCRLNumber()+", expireDate="+lastDeltaCrlInfo.getExpireDate());
                                    }                                          
                                }
                                if (lastDeltaCrlInfo == null || (now.getTime() + crloverlaptime) >= lastDeltaCrlInfo.getExpireDate().getTime()){
                                    final CRLInfo lastBaseCrlInfo = crlSession.getLastCRLInfo(certSubjectDN, false);
                                    if (lastBaseCrlInfo != null) {
                                        if (internalCreateDeltaCRL(admin, ca, lastBaseCrlInfo) != null) {
                                            ret = true;
                                        }
                                    } else {
                                        log.info("No full CRL exists when trying to generate delta CRL for caid "+caid);
                                    }
                                }
                            }
                        }
                    } else if (cacert != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Not creating delta CRL for expired CA "+cainfo.getName()+". CA subjectDN='"+CertTools.getSubjectDN(cacert)+"', expired: "+CertTools.getNotAfter(cacert));
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Not creating delta CRL for CA without CA certificate: "+cainfo.getName());
                        }
                    }
                }                                       
            }
        } catch (CryptoTokenOfflineException e) {
            log.warn("Crypto token is offline for CA "+caid+" generating CRL.");
            throw e;            
        }
        return ret;
    }

    @Override
    public boolean forceCRL(final AuthenticationToken admin, final int caid) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CAOfflineException {
        final CA ca = caSession.getCA(admin, caid);
        final CRLInfo lastBaseCrlInfo = crlSession.getLastCRLInfo(CertTools.getSubjectDN(getCaCertificate(ca.getCAInfo())), false);
        return internalCreateCRL(admin, ca, lastBaseCrlInfo) != null;
    }
    
    @Override
    public boolean forceDeltaCRL(final AuthenticationToken admin, final int caid) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CAOfflineException {
        final CA ca = caSession.getCA(admin, caid);
        final CRLInfo lastBaseCrlInfo = crlSession.getLastCRLInfo(CertTools.getSubjectDN(getCaCertificate(ca.getCAInfo())), false);
        // if no full CRL has been generated we can't create a delta CRL
        boolean ret = false;
        if (lastBaseCrlInfo != null) {
            CAInfo cainfo = ca.getCAInfo();
            if (cainfo.getDeltaCRLPeriod() > 0) {
                byte[] crl = internalCreateDeltaCRL(admin, ca, lastBaseCrlInfo);
                ret = (crl != null);    
            }
        } else {
            log.info("No full CRL exists when trying to generate (force) delta CRL for caid "+caid);
        }
        return ret;
    }
    
    /**
     * Generates a new CRL by looking in the database for revoked certificates
     * and generating a CRL. This method also "archives" certificates when after
     * they are no longer needed in the CRL.
     * Generates the CRL and stores it in the database.
     * 
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @return fingerprint (primary key) of the generated CRL or null if
     *            generation failed
     * @throws AuthorizationDeniedException 
     * @throws javax.ejb.EJBException if a communications- or system error occurs
     */
    private String internalCreateCRL(final AuthenticationToken admin, final CA ca, final CRLInfo lastBaseCrlInfo) throws CAOfflineException, CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">internalCreateCRL()");
        }
        if (ca == null) {
            throw new EJBException("No CA specified.");
        }
        final CAInfo cainfo = ca.getCAInfo();
        String ret = null;
        Collection<RevokedCertInfo> revokedCertificates = null;
        try {
            final Certificate cacert = getCaCertificate(cainfo);
            // DN from the CA issuing the CRL to be used when searching for the CRL in the database.
            final String caCertSubjectDN = cacert==null ? null : CertTools.getSubjectDN(cacert);
            // We can not create a CRL for a CA that is waiting for certificate response
            if ( caCertSubjectDN!=null && cainfo.getStatus()==CAConstants.CA_ACTIVE )  {
                // Find all revoked certificates for a complete CRL
                if (log.isDebugEnabled()) {
                    final long freeMemory = Runtime.getRuntime().maxMemory() - Runtime.getRuntime().totalMemory() + Runtime.getRuntime().freeMemory();
                    log.debug("Listing revoked certificates. Free memory=" + freeMemory);
                }
                revokedCertificates = certificateStoreSession.listRevokedCertInfo(caCertSubjectDN, -1);
                
                //if X509 CA is marked as it has gone through Name Change add certificates revoked with old names
                if(ca.getCAType()==CAInfo.CATYPE_X509 && ((X509CA)ca).getNameChanged()){
                    log.info("The CA with SubjectDN " + ca.getSubjectDN() + " has been gone through ICAO Name Change. Collecting all revocation information published by this CA with previous names has started.");
                    Collection<Certificate> renewedCertificateChain = ca.getRenewedCertificateChain();
                    Collection<RevokedCertInfo> revokedCertificatesBeforeLastCANameChange = new ArrayList<RevokedCertInfo>();
                    if(renewedCertificateChain != null){
                        Collection<String> differentSubjectDNs = new HashSet<String>();
                        differentSubjectDNs.add(caCertSubjectDN);
                        for(Certificate renewedCertificate : renewedCertificateChain){
                            String renewedCertificateSubjectDN = CertTools.getSubjectDN(renewedCertificate);
                            if(!differentSubjectDNs.contains(renewedCertificateSubjectDN)){
                                log.info("Collecting revocation information for " + renewedCertificateSubjectDN + " and merging them with ones for " + caCertSubjectDN);
                                differentSubjectDNs.add(renewedCertificateSubjectDN);
                                Collection<RevokedCertInfo> revokedCertInfo = certificateStoreSession.listRevokedCertInfo(renewedCertificateSubjectDN, -1);
                                for(RevokedCertInfo tmp : revokedCertInfo){ //for loop is necessary because revokedCertInfo.toArray is not supported...
                                    revokedCertificatesBeforeLastCANameChange.add(tmp);
                                }
                            }
                        }
                    }    
                    //Make sure new compressed collection is created if revokedCertificatesBeforeLastCANameChange need to be added!
                    Collection<RevokedCertInfo> revokedCertificatesAfterLastCANameChange = revokedCertificates;
                    revokedCertificates = new CompressedCollection<RevokedCertInfo>();
                    if(!revokedCertificatesBeforeLastCANameChange.isEmpty()){
                        revokedCertificates.addAll(revokedCertificatesBeforeLastCANameChange);
                    }
                    revokedCertificates.addAll(revokedCertificatesAfterLastCANameChange);
                }
                               
                if (log.isDebugEnabled()) {
                    final long freeMemory = Runtime.getRuntime().maxMemory() - Runtime.getRuntime().totalMemory() + Runtime.getRuntime().freeMemory();
                    log.debug("Found "+revokedCertificates.size()+" revoked certificates. Free memory=" + freeMemory);
                }
                // Go through them and create a CRL, at the same time archive expired certificates, unless configured not to do so (keep expired certificates on CRL)
                //
                // Archiving is only done for full CRLs, not delta CRLs.
                // RFC5280, section 3.3, states that a certificate must not be removed from the CRL until it has appeared on at least one full CRL.
                // RFC5280, section 5: A full and complete CRL lists all unexpired certificates issued by a CA that have been revoked for any reason.
                // See RFC5280 section 5.2.4, specifically:
                //  If a certificate revocation notice first appears on a delta CRL, then
                //  it is possible for the certificate validity period to expire before
                //  the next complete CRL for the same scope is issued.  In this case,
                //  the revocation notice MUST be included in all subsequent delta CRLs
                //  until the revocation notice is included on at least one explicitly
                //  issued complete CRL for this scope
                final Date now = new Date();
                final Date lastCrlCreationDate = lastBaseCrlInfo==null ? now : lastBaseCrlInfo.getCreateDate();
                final AuthenticationToken archiveAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrlCreateSession.archive_expired"));
                final boolean keepexpiredcertsoncrl = cainfo.getKeepExpiredCertsOnCRL();
                if (keepexpiredcertsoncrl) {
                    log.info("KeepExpiredCertsOnCRL is enabled, we will not archive expired certificate but will keep them on the CRL (for ever growing): " + keepexpiredcertsoncrl);
                }
                for (final RevokedCertInfo revokedCertInfo : revokedCertificates) {
                    // We want to include certificates that was revoked after the last CRL was issued, but before this one
                    // so the revoked certs are included in ONE CRL at least. See RFC5280 section 3.3.
                    // If chosen to keep expired certificates on CRL, we will NOT do this but keep them (ISO 9594-8 par. 8.5.2.12)
                    if ( !keepexpiredcertsoncrl && revokedCertInfo.getExpireDate().before(lastCrlCreationDate) ) {
                        // Certificate has expired, set status to archived in the database
                        if (log.isDebugEnabled()) {
                            final long freeMemory = Runtime.getRuntime().maxMemory() - Runtime.getRuntime().totalMemory() + Runtime.getRuntime().freeMemory();
                            log.debug("Archiving certificate with fp="+revokedCertInfo.getCertificateFingerprint()+". Free memory=" + freeMemory);
                        }
                        certificateStoreSession.setStatus(archiveAdmin, revokedCertInfo.getCertificateFingerprint(), CertificateConstants.CERT_ARCHIVED);
                    } else {
                        if (!revokedCertInfo.isRevocationDateSet()) {
                            revokedCertInfo.setRevocationDate(now);
                            CertificateData certdata = CertificateData.findByFingerprint(entityManager, revokedCertInfo.getCertificateFingerprint());
                            if (certdata == null) {
                                throw new FinderException("No certificate with fingerprint " + revokedCertInfo.getCertificateFingerprint());
                            }
                            // Set revocation date in the database
                            certdata.setRevocationDate(now);
                        }
                    }
                }
                // a full CRL
                final byte[] crlBytes = generateAndStoreCRL(admin, ca, revokedCertificates, lastBaseCrlInfo, false);
                if (crlBytes != null) {
                    ret = CertTools.getFingerprintAsString(crlBytes);                       
                }
                // This debug logging is very very heavy if you have large CRLs. Please don't use it :-)
                //              if (log.isDebugEnabled()) {
                //              X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
                //              debug("Created CRL with expire date: "+crl.getNextUpdate());
                //              FileOutputStream fos = new FileOutputStream("c:\\java\\srvtestcrl.der");
                //              fos.write(crl.getEncoded());
                //              fos.close();
                //              }
            } else {
                String msg = intres.getLocalizedMessage("createcrl.errornotactive", cainfo.getName(), Integer.valueOf(cainfo.getCAId()), cainfo.getStatus());                                                      
                log.info(msg);
                throw new CAOfflineException(msg);
            }
        } catch (FinderException e) {
            // Should really not happen
            log.error(e);
            throw new EJBException(e);
        } finally {
            // Special treatment of our CompressedCollection to ensure that we release all resources
            if (revokedCertificates!=null) {
                revokedCertificates.clear();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<internalCreateCRL()");
        }
        return ret;
    }

    /**
     * Generates a new Delta CRL by looking in the database for revoked
     * certificates since the last complete CRL issued and generating a CRL with
     * the difference. If either of baseCrlNumber or baseCrlCreateTime is -1
     * this method will try to query the database for the last complete CRL.
     * Generates the CRL and stores it in the database.
     * 
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param lastBaseCrlInfo
     *            base crl number to be put in the delta CRL, this is the CRL
     *            number of the previous complete CRL. If value is -1 the value
     *            is fetched by querying the database looking for the last
     *            complete CRL. And the time the base CRL was issued. If value is -1 the value is
     *            fetched by querying the database looking for the last complete
     *            CRL.
     * @return the bytes of the Delta CRL generated or null of no delta CRL was
     *         generated.
     * @throws AuthorizationDeniedException 
     * @throws javax.ejb.EJBException if a communications- or system error occurs
     */
    private byte[] internalCreateDeltaCRL(final AuthenticationToken admin, final CA ca, final CRLInfo lastBaseCrlInfo) throws CryptoTokenOfflineException, CAOfflineException, AuthorizationDeniedException {
        if (ca == null) {
            throw new EJBException("No CA specified.");
        }
        final CAInfo cainfo = ca.getCAInfo();
        if (log.isTraceEnabled()) {
                log.trace(">internalCreateDeltaCRL: "+cainfo.getSubjectDN());
        }
        byte[] crlBytes = null;
        Collection<RevokedCertInfo> revcertinfos = null;
        CompressedCollection<RevokedCertInfo> certs = null;
        try {
            final Certificate cacert = getCaCertificate(cainfo);
            final String caCertSubjectDN = cacert==null ? null : CertTools.getSubjectDN(cacert);
            // We can not create a CRL for a CA that is waiting for certificate response
            if ( caCertSubjectDN!=null && cainfo.getStatus()==CAConstants.CA_ACTIVE ) {
                // Find all revoked certificates
                revcertinfos = certificateStoreSession.listRevokedCertInfo(caCertSubjectDN, lastBaseCrlInfo.getCreateDate().getTime());
                
                // if X509 CA is marked as it has gone through Name Change add certificates revoked with old names
                if(ca.getCAType()==CAInfo.CATYPE_X509 && ((X509CA)ca).getNameChanged()){
                    if (log.isDebugEnabled()) {
                        log.debug("Gathering all revocation information published by this CA since its beggining. Important only if CA has gone undergone name change");
                    }
                    Collection<Certificate> renewedCertificateChain = ca.getRenewedCertificateChain();
                    Collection<RevokedCertInfo> revokedCertificatesBeforeLastCANameChange = new ArrayList<RevokedCertInfo>();
                    if(renewedCertificateChain != null){
                        Collection<String> differentSubjectDNs = new HashSet<String>();
                        differentSubjectDNs.add(caCertSubjectDN);
                        for(Certificate renewedCertificate : renewedCertificateChain){
                            String renewedCertificateSubjectDN = CertTools.getSubjectDN(renewedCertificate);
                            
                            if(!differentSubjectDNs.contains(renewedCertificateSubjectDN)){
                                if (log.isDebugEnabled()) {
                                    log.debug("Collecting revocation information for " + renewedCertificateSubjectDN + " and merging them with ones for " + caCertSubjectDN);
                                }
                                differentSubjectDNs.add(renewedCertificateSubjectDN);
                                Collection<RevokedCertInfo> revokedCertInfo = certificateStoreSession.listRevokedCertInfo(renewedCertificateSubjectDN, -1);
                                for(RevokedCertInfo tmp : revokedCertInfo){ //for loop is necessary because revokedCertInfo.toArray is not supported...
                                    revokedCertificatesBeforeLastCANameChange.add(tmp);
                                }
                            }
                        }
                    }    
                    //Make sure new compressed collection is created if revokedCertificatesBeforeLastCANameChange need to be added!
                    Collection<RevokedCertInfo> revokedCertificatesAfterLastCANameChange = revcertinfos;
                    revcertinfos = new CompressedCollection<RevokedCertInfo>();
                    if(!revokedCertificatesBeforeLastCANameChange.isEmpty()){
                        revcertinfos.addAll(revokedCertificatesBeforeLastCANameChange);
                    }
                    revcertinfos.addAll(revokedCertificatesAfterLastCANameChange);
                }
                
                if (log.isDebugEnabled()) {
                    log.debug("Found "+revcertinfos.size()+" revoked certificates.");
                }
                // Go through them and create a CRL, i.e. add to cert list to be included in CRL
                certs = new CompressedCollection<RevokedCertInfo>();
                for (final RevokedCertInfo ci : revcertinfos) {
                    if (ci.getRevocationDate() == null) {
                        ci.setRevocationDate(new Date());
                    }
                    certs.add(ci);
                }
                revcertinfos.clear();  // Release unused resources
                // create a delta CRL
                crlBytes = generateAndStoreCRL(admin, ca, certs, lastBaseCrlInfo, true);
                if (log.isDebugEnabled()) {
                    X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
                    log.debug("Created delta CRL with expire date: "+crl.getNextUpdate());
                }
            } else {
                String msg = intres.getLocalizedMessage("createcrl.errornotactive", cainfo.getName(), Integer.valueOf(cainfo.getCAId()), cainfo.getStatus());                                                      
                log.info(msg);   
                throw new CAOfflineException(msg);
            }
        } catch (CRLException e) {
            // Should really not happen
            log.error(e);
            throw new EJBException(e);
        } finally {
            // Special treatment of our CompressedCollections to ensure that we release all resources
            if (revcertinfos!=null) {
                revcertinfos.clear();  
            }
            if (certs!=null) {
                certs.clear();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<internalCreateDeltaCRL: "+cainfo.getSubjectDN());
        }
        return crlBytes;
    }

    private byte[] generateAndStoreCRL(final AuthenticationToken admin, final CA ca, final Collection<RevokedCertInfo> certs, final CRLInfo lastBaseCrlInfo, final boolean delta) throws CryptoTokenOfflineException, AuthorizationDeniedException {
         // Hard and error-prone to do that.
        if (log.isDebugEnabled()) {
            log.debug("Storing CRL in publishers");
        }
        final String cafp = CertTools.getFingerprintAsString(ca.getCACertificate());
        String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate()); 
        
        int fullcrlnumber = lastBaseCrlInfo==null ? 0 : lastBaseCrlInfo.getLastCRLNumber();
        //If this is the first time to create CRL for CA that has gone through Name Change process make sure
        //that first CRL will continue CRL numbering where CA left before the last Name Change process
        if (ca.getCAType()==CAInfo.CATYPE_X509 && ((X509CA)ca).getNameChanged()) {
            if (lastBaseCrlInfo == null) {
                Certificate lastRenewedCACertificate = null;
                ArrayList<Certificate> renewedCertificateChain = ca.getRenewedCertificateChain();
                if(renewedCertificateChain == null){
                    throw new IllegalStateException("Was not able to retrieve renewed certificate chain for CA = " + ca.getName() + ". Could not proceed with generating and storing CRL");
                }
                lastRenewedCACertificate = renewedCertificateChain.get(renewedCertificateChain.size()-1);
                String lastRenewedCACertificateSubjectDN = CertTools.getSubjectDN(lastRenewedCACertificate);
                if(!lastRenewedCACertificateSubjectDN.equalsIgnoreCase(certSubjectDN)){
                    if (log.isDebugEnabled()) {
                        log.debug("First creation of CRL detected for CA "+ca.getName()+" after CA has gone through Name Change process. Continuing CRL number left with old CA name " + lastRenewedCACertificateSubjectDN);
                    }
                    certSubjectDN = lastRenewedCACertificateSubjectDN;
                    // Since we don't have a fullcrlnumber from the renewed CA, use the full crlnumber from the old CA that we are changing from
                    fullcrlnumber = crlSession.getLastCRLNumber(certSubjectDN, false);
                }else{
                    throw new IllegalStateException("CA " + ca.getName() + " is marked as it has gone through CA Name Change process but old name seems the same as new one! Could not proceed with generating and storing CRL");
                }
            } else {
                log.debug("CA "+ca.getName()+" has gone through CA Name Change process, but this is not the first CRL to be generated. Not getting CRL number from old CA name.");
            }
        }
        
        final int deltacrlnumber = crlSession.getLastCRLNumber(certSubjectDN, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        final int nextCrlNumber = ( fullcrlnumber > deltacrlnumber ? fullcrlnumber : deltacrlnumber ) +1; 
        final byte[] crlBytes = crlCreateSession.generateAndStoreCRL(admin, ca, certs, delta?fullcrlnumber:-1, nextCrlNumber);
        this.publisherSession.storeCRL(admin, ca.getCRLPublishers(), crlBytes, cafp, nextCrlNumber, certSubjectDN);
        return crlBytes;
    }

    private Certificate getCaCertificate(final CAInfo caInfo) {
        final Collection<Certificate> certificateChain = caInfo.getCertificateChain();
        return certificateChain.isEmpty() ? null : certificateChain.iterator().next();
    }
}
