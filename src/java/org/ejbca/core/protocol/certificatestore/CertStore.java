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
package org.ejbca.core.protocol.certificatestore;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;

import javax.ejb.EJBException;

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * DB store of data to be used by the CA
 * 
 * @author primelars
 * @version $Id$
 *
 */
public class CertStore implements ICertStore {

    private CertificateStoreSession m_certStore = null;
    private synchronized CertificateStoreSession getStoreSession(){
    	if(m_certStore == null){	
    		try {
    			EjbLocalHelper ejb = new EjbLocalHelper();
    			m_certStore = ejb.getCertStoreSession();
    		}catch(Exception e){
    			throw new EJBException(e);
    		}
    	}
    	return m_certStore;
    }
    /* (non-Javadoc)
     * @see org.ejbca.core.protocol.ocsp.ICertStore#findCertificatesByType(org.ejbca.core.model.log.Admin, int, java.lang.String)
     */
    public Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
        return getStoreSession().findCertificatesByType(adm, type, issuerDN);           
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.ICertStore#findCertificateByIssuerAndSerno(org.ejbca.core.model.log.Admin, java.lang.String, java.math.BigInteger)
     */
    public Certificate findCertificateByIssuerAndSerno(Admin adm,
                                                       String issuerDN,
                                                       BigInteger serno) {
        return getStoreSession().findCertificateByIssuerAndSerno(adm, issuerDN, serno);
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.ICertStore#getStatus(java.lang.String, java.math.BigInteger)
     */
    public CertificateStatus getStatus(String issuerDN, BigInteger serialNumber) {
        return getStoreSession().getStatus(issuerDN, serialNumber);
    }

}
