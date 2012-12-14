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
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalCertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCertificateStoreSessionBean implements InternalCertificateStoreSessionRemote {

    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    private static final Logger log = Logger.getLogger(InternalCertificateStoreSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    CertificateStoreSessionLocal certStore;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @Override
    public void removeCertificate(BigInteger serno) {
        if (serno != null) {
            Collection<CertificateData> coll = CertificateData.findBySerialNumber(entityManager, serno.toString());
            for (CertificateData certificateData : coll) {
                entityManager.remove(certificateData);
            }
        }
    }

    @Override
    public void removeCertificate(String fingerprint) {
        if (fingerprint != null) {
            CertificateData cert = CertificateData.findByFingerprint(entityManager, fingerprint);
            if (cert != null) {
                entityManager.remove(cert);
            }
        }
    }

    @Override
    public void removeCertificate(Certificate certificate) {
        if (certificate != null) {
            // Do this as a native query because we do not want to be depending on rowProtection validating
            // correctly, since some systemtests may insert directly in the database with null rowProtection (publisher tests)
            String fingerprint = CertTools.getFingerprintAsString(certificate);
            final Query query = entityManager.createNativeQuery("DELETE from CertificateData where fingerprint=:fingerprint");
            query.setParameter("fingerprint", fingerprint);
            query.executeUpdate();
        }
    }

    @Override
    public List<Object[]> findExpirationInfo(Collection<String> cas, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax,
            long activeExpireDateMin) {
        return certStore.findExpirationInfo(cas, new ArrayList<Integer>(), activeNotifiedExpireDateMin, activeNotifiedExpireDateMax,
                activeExpireDateMin);
    }

	@Override
    public Collection<Certificate> findCertificatesByIssuer(String issuerDN) {
        final List<Certificate> certificateList = new ArrayList<Certificate>();
        if (null == issuerDN || issuerDN.length() <= 0) {
            return certificateList;
        } else {
            final Query query = entityManager.createQuery("SELECT a.base64Cert FROM CertificateData a WHERE a.issuerDN=:issuerDN");
            query.setParameter("issuerDN", issuerDN);
            @SuppressWarnings("unchecked")
            final List<String> base64CertificateList = query.getResultList();
            for (String base64Certificate : base64CertificateList) {
                try {
                    certificateList.add(CertTools.getCertfromByteArray(Base64.decode(base64Certificate.getBytes())));
                } catch (CertificateException ce) {

                }
            }
            return certificateList;
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCRL(final AuthenticationToken admin, final String fingerprint) throws AuthorizationDeniedException {
        final CRLData crld = CRLData.findByFingerprint(entityManager, fingerprint);
        if (crld == null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to remove a CRL that does not exist: " + fingerprint);
            }
        } else {
            entityManager.remove(crld);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws IllegalArgumentException, AuthorizationDeniedException {

        CertificateData data = CertificateData.findByFingerprint(entityManager, fingerprint);
        if (data != null) {
            if (log.isDebugEnabled()) {
                log.debug("Set status " + status + " for certificate with fp: " + fingerprint);
            }
            
            // Must be authorized to CA in order to change status is certificates issued by the CA
            String bcdn = CertTools.stringToBCDNString(data.getIssuerDN());
            int caid = bcdn.hashCode();
            authorizedToCA(admin, caid);

            data.setStatus(status);
            final String serialNo = CertTools.getSerialNumberAsString(data.getCertificate());
            final String msg = INTRES.getLocalizedMessage("store.setstatus", data.getUsername(), fingerprint, status, data.getSubjectDN(), data.getIssuerDN(), serialNo);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CERT_CHANGEDSTATUS, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNo, data.getUsername(), details);            
        } else {
            if (log.isDebugEnabled()) {
                final String msg = INTRES.getLocalizedMessage("store.setstatusfailed", fingerprint, status);
                log.debug(msg);
            }           
        }
        return (data != null);
    }
    
    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = INTRES.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
    }
}
