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
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.certificates.crl.CrlStoreSessionBean;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalCertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCertificateStoreSessionBean implements InternalCertificateStoreSessionRemote {

    private static final Logger log = Logger.getLogger(CrlStoreSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    CertificateStoreSessionLocal certStore;

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
            CertificateData certificateData = CertificateData.findByFingerprint(entityManager, CertTools.getFingerprintAsString(certificate));
            if (certificateData != null) {
                entityManager.remove(certificateData);
            }
        }
    }

    @Override
    public List<Object[]> findExpirationInfo(Collection<String> cas, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax,
            long activeExpireDateMin) {
        return certStore.findExpirationInfo(cas, activeNotifiedExpireDateMin, activeNotifiedExpireDateMax, activeExpireDateMin);
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

}
