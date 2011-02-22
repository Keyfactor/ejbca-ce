/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.core.ejb.ca.crl;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

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
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.caadmin.CaSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateData;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.util.CertTools;

/**
 * Business class for CRL actions, i.e. running CRLs. CRUD operations can be found in CrlSession.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CrlCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlCreateSessionBean implements CrlCreateSessionLocal, CrlCreateSessionRemote {

    private static final Logger log = Logger.getLogger(CrlCreateSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;
    @Resource
    private SessionContext sessionContext;
    @EJB
    private LogSessionLocal logSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CrlSessionLocal crlSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    private CrlCreateSessionLocal crlCreateSession;	// Used to run methods using different transaction attributes

    @PostConstruct
    public void postConstruct() {
    	crlCreateSession = sessionContext.getBusinessObject(CrlCreateSessionLocal.class);
    }

    @Override
    public byte[] createCRL(Admin admin, CA ca, Collection<RevokedCertInfo> certs, int basecrlnumber) throws CATokenOfflineException {
        if (log.isTraceEnabled()) {
                log.trace(">createCRL(Collection)");
        }
        byte[] crlBytes = null; // return value
        try {
            if ( (ca.getStatus() != SecConst.CA_ACTIVE) && (ca.getStatus() != SecConst.CA_WAITING_CERTIFICATE_RESPONSE) ) {
                String msg = intres.getLocalizedMessage("signsession.canotactive", ca.getSubjectDN());
                logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new CATokenOfflineException(msg);
            }
            final X509CRL crl;
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            int fullnumber = crlSession.getLastCRLNumber(admin, certSubjectDN, false);
            int deltanumber = crlSession.getLastCRLNumber(admin, certSubjectDN, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
            int nextCrlNumber = ( (fullnumber > deltanumber) ? fullnumber : deltanumber ) +1; 
            boolean deltaCRL = (basecrlnumber > -1);
            if (deltaCRL) {
                // Workaround if transaction handling fails so that crlNumber for deltaCRL would happen to be the same
                if (nextCrlNumber == basecrlnumber) {
                        nextCrlNumber++;
                }
                crl = (X509CRL) ca.generateDeltaCRL(certs, nextCrlNumber, basecrlnumber);       
            } else {
                crl = (X509CRL) ca.generateCRL(certs, nextCrlNumber);
            }
            if (crl != null) {
                String msg = intres.getLocalizedMessage("signsession.createdcrl", Integer.valueOf(nextCrlNumber), ca.getName(), ca.getSubjectDN());
                logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CREATECRL, msg);

                // Store CRL in the database
                String fingerprint = CertTools.getFingerprintAsString(ca.getCACertificate());
                crlBytes = crl.getEncoded();                    
                if (log.isDebugEnabled()) {
                        log.debug("Storing CRL in certificate store.");
                }
                crlSession.storeCRL(admin, crlBytes, fingerprint, nextCrlNumber, crl.getIssuerDN().getName(), crl.getThisUpdate(), crl.getNextUpdate(), (deltaCRL ? 1 : -1));
                // Store crl in ca CRL publishers.
                log.debug("Storing CRL in publishers");
                this.publisherSession.storeCRL(admin, ca.getCRLPublishers(), crlBytes, fingerprint, nextCrlNumber, ca.getSubjectDN());
            }
        } catch (CATokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.error(msg, ctoe);
            logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, ctoe);
            throw ctoe;
        } catch (Exception e) {
                logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, intres.getLocalizedMessage("signsession.errorcreatecrl"), e);
            throw new EJBException(intres.getLocalizedMessage("signsession.errorcreatecrl"), e);
        }
        if (log.isTraceEnabled()) {
                log.trace("<createCRL(Collection)");
        }
        return crlBytes;
    }

    @Override
    public int createCRLs(Admin admin) {
        return createCRLs(admin, null, 0);
    }

    @Override
    public void createCRLs(Admin admin, CA ca, CAInfo cainfo) throws CATokenOfflineException {
        final String fp = run(admin, ca);
        // If we could not create a full CRL (for example CVC CAs does not even
        // support CRLs), don't try to create a delta CRL.
        if (fp != null) {
            final CRLInfo crlInfo = crlSession.getCRLInfo(admin, fp);
            if (cainfo.getDeltaCRLPeriod() > 0) {
                runDeltaCRL(admin, ca, crlInfo.getLastCRLNumber(), crlInfo.getCreateDate().getTime());
            }
        }
    }

    @Override
    public int createCRLs(Admin admin, Collection<Integer> caids, long addtocrloverlaptime) {
        int createdcrls = 0;
        try {
            Iterator<Integer> iter = null;
            if (caids != null) {
                iter = caids.iterator();
            }
            if ((iter == null) || (caids.contains(Integer.valueOf(SecConst.ALLCAS)))) {
                iter = caSession.getAvailableCAs().iterator();
            }
            while (iter.hasNext()) {
                int caid = ((Integer) iter.next()).intValue();
                log.debug("createCRLs for caid: " + caid);
                CA ca = caSession.getCA(admin, caid);
                if (crlCreateSession.runNewTransactionConditioned(admin, ca, addtocrloverlaptime)) {
                    createdcrls++;
                }
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("createcrl.erroravailcas");
            log.error(msg, e);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, e);
            if (e instanceof EJBException) {
                throw (EJBException) e;
            }
            throw new EJBException(e);
        }
        return createdcrls;
    }

    @Override
    public int createDeltaCRLs(Admin admin) {
        return createDeltaCRLs(admin, null, 0);
    }

    @Override
    public int createDeltaCRLs(Admin admin, Collection<Integer> caids, long crloverlaptime) {
        int createddeltacrls = 0;
        try {
            Iterator<Integer> iter = null;
            if (caids != null) {
                iter = caids.iterator();
            }
            if ((iter == null) || (caids.contains(Integer.valueOf(SecConst.ALLCAS)))) {
                iter = caSession.getAvailableCAs().iterator();
            }
            while (iter.hasNext()) {
                int caid = iter.next().intValue();
                log.debug("createDeltaCRLs for caid: " + caid);
                CA ca = caSession.getCA(admin, caid);
                if (crlCreateSession.runDeltaCRLnewTransactionConditioned(admin, ca, crloverlaptime)) {
                    createddeltacrls++;
                }
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("createcrl.erroravailcas");
            log.error(msg, e);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, e);
            if (e instanceof EJBException) {
                throw (EJBException) e;
            }
            throw new EJBException(e);
        }
        return createddeltacrls;
    }

    @Override
    public void publishCRL(Admin admin, Certificate caCert, Collection<Integer> usedpublishers, String caDataDN, boolean doPublishDeltaCRL) {
        if ( usedpublishers==null ) {
                return;
        }
        // Store crl in ca CRL publishers.
        if (log.isDebugEnabled()) {
                log.debug("Storing CRL in publishers");
        }
        final String issuerDN = CertTools.getSubjectDN(caCert);
        final String caCertFingerprint = CertTools.getFingerprintAsString(caCert);
        final byte crl[] = crlSession.getLastCRL(admin, issuerDN, false);
        if ( crl!=null ) {
                final int nr = crlSession.getLastCRLInfo(admin, issuerDN, false).getLastCRLNumber();
                publisherSession.storeCRL(admin, usedpublishers, crl, caCertFingerprint, nr, caDataDN);
        }
        if ( !doPublishDeltaCRL ) {
                return;
        }
        final byte deltaCrl[] = crlSession.getLastCRL(admin, issuerDN, true);
        if ( deltaCrl!=null ) {
                final int nr = crlSession.getLastCRLInfo(admin, issuerDN, true).getLastCRLNumber();
                publisherSession.storeCRL(admin, usedpublishers, deltaCrl, caCertFingerprint, nr, caDataDN);
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean runNewTransactionConditioned(Admin admin, CA ca, long addtocrloverlaptime) throws CATokenOfflineException {
        boolean ret = false;
        Date currenttime = new Date();
        CAInfo cainfo = ca.getCAInfo();
        try {
                if (cainfo.getStatus() == SecConst.CA_EXTERNAL) {
                                if (log.isDebugEnabled()) {
                                        log.debug("Not trying to generate CRL for external CA "+cainfo.getName());
                                }
                } else if (cainfo.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) {
                                if (log.isDebugEnabled()) {
                                        log.debug("Not trying to generate CRL for CA "+cainfo.getName() +" awaiting certificate response.");
                                }
                } else {
                        if (cainfo instanceof X509CAInfo) {
                                Collection<Certificate> certs = cainfo.getCertificateChain();
                                final Certificate cacert;
                                if (!certs.isEmpty()) {
                                        cacert = certs.iterator().next();   
                                } else {
                                        cacert = null;
                                }
                                // Don't create CRLs if the CA has expired
                                if ( (cacert != null) && (CertTools.getNotAfter(cacert).after(new Date())) ) {
                                        if (cainfo.getStatus() == SecConst.CA_OFFLINE )  {
                                                String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), Integer.valueOf(cainfo.getCAId()));                                                   
                                                log.info(msg);
                                                logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_CREATECRL, msg);
                                        } else {
                                                try {
                                                        if (log.isDebugEnabled()) {
                                                                log.debug("Checking to see if CA '"+cainfo.getName()+"' ("+cainfo.getCAId()+") needs CRL generation.");
                                                        }
                                                        final String certSubjectDN = CertTools.getSubjectDN(cacert);
                                                        CRLInfo crlinfo = crlSession.getLastCRLInfo(admin,certSubjectDN,false);
                                                        if (log.isDebugEnabled()) {
                                                                if (crlinfo == null) {
                                                                        log.debug("Crlinfo was null");
                                                                } else {
                                                                        log.debug("Read crlinfo for CA: "+cainfo.getName()+", lastNumber="+crlinfo.getLastCRLNumber()+", expireDate="+crlinfo.getExpireDate());
                                                                }                                          
                                                        }
                                                        long crlissueinterval = cainfo.getCRLIssueInterval();
                                                        if (log.isDebugEnabled()) {
                                                                log.debug("crlissueinterval="+crlissueinterval);
                                                                log.debug("crloverlaptime="+cainfo.getCRLOverlapTime());                                   
                                                        }
                                                        long overlap = cainfo.getCRLOverlapTime() + addtocrloverlaptime; // Overlaptime is in minutes, default if crlissueinterval == 0
                                                        long nextUpdate = 0; // if crlinfo == 0, we will issue a crl now
                                                        if (crlinfo != null) {
                                                                // CRL issueinterval in hours. If this is 0, we should only issue a CRL when
                                                                // the old one is about to expire, i.e. when currenttime + overlaptime > expiredate
                                                                // if isseuinterval is > 0 we will issue a new CRL when currenttime > createtime + issueinterval
                                                                nextUpdate = crlinfo.getExpireDate().getTime(); // Default if crlissueinterval == 0
                                                                if (crlissueinterval > 0) {
                                                                        long u = crlinfo.getCreateDate().getTime() + crlissueinterval;
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
                                                                String msg = intres.getLocalizedMessage("createcrl.crlinfonull", cainfo.getName());                                                
                                                                log.info(msg);
                                                        }
                                                        if ((currenttime.getTime() + overlap) >= nextUpdate) {
                                                                if (log.isDebugEnabled()) {
                                                                        log.debug("Creating CRL for CA, because:"+currenttime.getTime()+overlap+" >= "+nextUpdate);                                                
                                                                }
                                                                run(admin, ca);
                                                                //this.runNewTransaction(admin, cainfo.getSubjectDN());
                                                                ret = true;
                                                                //createdcrls++;
                                                        }

                                                } catch (CATokenOfflineException e) {
                                                        String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), Integer.valueOf(cainfo.getCAId()));                                                   
                                                        log.error(msg);
                                                        logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL, msg);
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
        } catch(Exception e) {
                String msg = intres.getLocalizedMessage("createcrl.generalerror", Integer.valueOf(cainfo.getCAId()));                                                  
                log.error(msg, e);
                logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
                if (e instanceof EJBException) {
                        throw (EJBException)e;
                }
                throw new EJBException(e);
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean runDeltaCRLnewTransactionConditioned(Admin admin, CA ca, long crloverlaptime) throws CATokenOfflineException {
        boolean ret = false;
                Date currenttime = new Date();
                CAInfo cainfo = ca.getCAInfo();
                try{
                        if (cainfo.getStatus() == SecConst.CA_EXTERNAL) {
                                if (log.isDebugEnabled()) {
                                        log.debug("Not trying to generate delta CRL for external CA "+cainfo.getName());
                                }
                        } else if (cainfo.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) {
                                if (log.isDebugEnabled()) {
                                        log.debug("Not trying to generate delta CRL for CA "+cainfo.getName() +" awaiting certificate response.");
                                }
                        } else {
                                if (cainfo instanceof X509CAInfo) {
                                        Collection<Certificate> certs = cainfo.getCertificateChain();
                                        final Certificate cacert;
                                        if (!certs.isEmpty()) {
                                                cacert = certs.iterator().next();   
                                        } else {
                                            cacert = null;
                                        }
                                        // Don't create CRLs if the CA has expired
                                        if ( (cacert != null) && (CertTools.getNotAfter(cacert).after(new Date())) ) {
                                        if(cainfo.getDeltaCRLPeriod() > 0) {
                                                if (cainfo.getStatus() == SecConst.CA_OFFLINE) {
                                                        String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), Integer.valueOf(cainfo.getCAId()));                                                   
                                                        log.error(msg);
                                                        logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL, msg);
                                                } else {
                                                        if (log.isDebugEnabled()) {
                                                                log.debug("Checking to see if CA '"+cainfo.getName()+"' needs Delta CRL generation.");
                                                        }
                                                        final String certSubjectDN = CertTools.getSubjectDN(cacert);
                                                        CRLInfo deltacrlinfo = crlSession.getLastCRLInfo(admin, certSubjectDN, true);
                                                        if (log.isDebugEnabled()) {
                                                                if (deltacrlinfo == null) {
                                                                        log.debug("DeltaCrlinfo was null");
                                                                } else {
                                                                        log.debug("Read deltacrlinfo for CA: "+cainfo.getName()+", lastNumber="+deltacrlinfo.getLastCRLNumber()+", expireDate="+deltacrlinfo.getExpireDate());
                                                                }                                          
                                                        }
                                                        if((deltacrlinfo == null) || ((currenttime.getTime() + crloverlaptime) >= deltacrlinfo.getExpireDate().getTime())){
                                                                runDeltaCRL(admin, ca, -1, -1);
                                                                ret = true;
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
        } catch (CATokenOfflineException e) {
            throw e;            
                }catch(Exception e) {
                String msg = intres.getLocalizedMessage("createcrl.generalerror", Integer.valueOf(cainfo.getCAId()));                                                  
                log.error(msg, e);
                logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
                if (e instanceof EJBException) {
                        throw (EJBException)e;
                }
                throw new EJBException(e);
                }
                return ret;
    }

    @Override
    public String run(Admin admin, CA ca) throws CATokenOfflineException {
        if (log.isTraceEnabled()) {
                log.trace(">run()");
        }
        if (ca == null) {
            throw new EJBException("No CA specified.");
        }
        CAInfo cainfo = ca.getCAInfo();
        int caid = cainfo.getCAId();
        String ret = null;
        try {
            final String caCertSubjectDN; // DN from the CA issuing the CRL to be used when searching for the CRL in the database.
            {
                final Collection<Certificate> certs = cainfo.getCertificateChain();
                final Certificate cacert = !certs.isEmpty() ? certs.iterator().next(): null;
                caCertSubjectDN = cacert!=null ? CertTools.getSubjectDN(cacert) : null;
            }
            // We can not create a CRL for a CA that is waiting for certificate response
            if ( caCertSubjectDN!=null && cainfo.getStatus()==SecConst.CA_ACTIVE )  {
                long crlperiod = cainfo.getCRLPeriod();
                // Find all revoked certificates for a complete CRL
                Collection<RevokedCertInfo> revcerts = certificateStoreSession.listRevokedCertInfo(admin, caCertSubjectDN, -1);
                if (log.isDebugEnabled()) {
                        log.debug("Found "+revcerts.size()+" revoked certificates.");
                }
                // Go through them and create a CRL, at the same time archive expired certificates
                Date now = new Date();
                Date check = new Date(now.getTime() - crlperiod);
                Iterator<RevokedCertInfo> iter = revcerts.iterator();
                while (iter.hasNext()) {
                        RevokedCertInfo data = iter.next();
                        // We want to include certificates that was revoked after the last CRL was issued, but before this one
                        // so the revoked certs are included in ONE CRL at least. See RFC5280 section 3.3.
                        if ( data.getExpireDate().before(check) ) {
                                // Certificate has expired, set status to archived in the database
                                certificateStoreSession.setArchivedStatus(new Admin(Admin.TYPE_INTERNALUSER), data.getCertificateFingerprint());
                        } else {
                                Date revDate = data.getRevocationDate();
                                if (revDate == null) {
                                        data.setRevocationDate(now);
                                        CertificateData certdata = CertificateData.findByFingerprint(entityManager, data.getCertificateFingerprint());
                                        if (certdata == null) {
                                                throw new FinderException("No certificate with fingerprint " + data.getCertificateFingerprint());
                                        }
                                        // Set revocation date in the database
                                        certdata.setRevocationDate(now);
                                }
                        }
                }
                // a full CRL
                byte[] crlBytes = createCRL(admin, ca, revcerts, -1);
                if (crlBytes != null) {
                        ret = CertTools.getFingerprintAsString(crlBytes);                       
                }
                // This is logged in the database by SignSession 
                String msg = intres.getLocalizedMessage("createcrl.createdcrl", cainfo.getName(), cainfo.getSubjectDN());               
                log.info(msg);
                // This debug logging is very very heavy if you have large CRLs. Please don't use it :-)
//              if (log.isDebugEnabled()) {
//              X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
//              debug("Created CRL with expire date: "+crl.getNextUpdate());
//              FileOutputStream fos = new FileOutputStream("c:\\java\\srvtestcrl.der");
//              fos.write(crl.getEncoded());
//              fos.close();
//              }
            } else {
                String msg = intres.getLocalizedMessage("createcrl.errornotactive", cainfo.getName(), Integer.valueOf(caid), cainfo.getStatus());                                                      
                log.info(msg);                  
            }
        } catch (CATokenOfflineException e) {
            throw e;            
        } catch (Exception e) {
                String msg = intres.getLocalizedMessage("createcrl.errorcreate", Integer.valueOf(caid));                    
            log.error(msg, e);
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, e);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
                log.trace("<run()");
        }
        return ret;
    }

    @Override
    public byte[] runDeltaCRL(Admin admin, CA ca, int baseCrlNumber, long baseCrlCreateTime) throws CATokenOfflineException {
                if (ca == null) {
                        throw new EJBException("No CA specified.");
                }
                CAInfo cainfo = ca.getCAInfo();
        if (log.isTraceEnabled()) {
                log.trace(">runDeltaCRL: "+cainfo.getSubjectDN());
        }
        byte[] crlBytes = null;
        final int caid = cainfo.getCAId();
        try {
                final String caCertSubjectDN; {
                    final Collection<Certificate> certs = cainfo.getCertificateChain();
                    final Certificate cacert = !certs.isEmpty() ? certs.iterator().next(): null;
                caCertSubjectDN = cacert!=null ? CertTools.getSubjectDN(cacert) : null;
            }
                if (caCertSubjectDN!=null && cainfo instanceof X509CAInfo) { // Only create CRLs for X509 CAs
                        if ( (baseCrlNumber == -1) && (baseCrlCreateTime == -1) ) {
                                CRLInfo basecrlinfo = crlSession.getLastCRLInfo(admin, caCertSubjectDN, false);
                                baseCrlCreateTime = basecrlinfo.getCreateDate().getTime();
                                baseCrlNumber = basecrlinfo.getLastCRLNumber();                                 
                        }
                        // Find all revoked certificates
                        Collection<RevokedCertInfo> revcertinfos = certificateStoreSession.listRevokedCertInfo(admin, caCertSubjectDN, baseCrlCreateTime);
                                if (log.isDebugEnabled()) {
                                        log.debug("Found "+revcertinfos.size()+" revoked certificates.");
                                }
                        // Go through them and create a CRL, at the same time archive expired certificates
                        ArrayList<RevokedCertInfo> certs = new ArrayList<RevokedCertInfo>();
                        Iterator<RevokedCertInfo> iter = revcertinfos.iterator();
                        while (iter.hasNext()) {
                                RevokedCertInfo ci = iter.next();
                                if (ci.getRevocationDate() == null) {
                                        ci.setRevocationDate(new Date());
                                }
                                certs.add(ci);
                        }
                        // create a delta CRL
                        crlBytes = createCRL(admin, ca, certs, baseCrlNumber);
                        X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
                                if (log.isDebugEnabled()) {
                                        log.debug("Created delta CRL with expire date: "+crl.getNextUpdate());
                                }
                }
        } catch (CATokenOfflineException e) {
            throw e;            
        } catch (Exception e) {
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,e.getMessage());
                throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
                log.trace("<runDeltaCRL: "+cainfo.getSubjectDN());
        }
                return crlBytes;
    }
}
