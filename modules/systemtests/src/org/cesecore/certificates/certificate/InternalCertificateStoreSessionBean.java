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
import java.util.Collection;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;

/**
 * @version $Id: InternalCertificateStoreSessionBean.java 988 2011-08-10 14:33:46Z tomas $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalCertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCertificateStoreSessionBean implements InternalCertificateStoreSessionRemote {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

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
}
