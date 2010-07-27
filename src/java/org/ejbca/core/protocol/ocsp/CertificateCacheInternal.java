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

package org.ejbca.core.protocol.ocsp;

import java.util.Collection;

import javax.ejb.EJBException;

import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.util.EjbLocalHelper;


/**
 * Class managing a cache of Certificates. This class should be optimized for quick lookups of CA certificates that the 
 * OCSP responder needs to fetch.
 * 
 * @version $Id$
 * 
 */
public class CertificateCacheInternal extends CertificateCache {
	
	private static CertificateCacheInternal instance = null;
	
    private CertificateCacheInternal() {
    	super(null);
    }
    
    /**
     * Returns a new CertificateCache for EJBCA's internal OCSP responder  
     */
    public static synchronized CertificateCacheInternal getInstance() {
    	if (instance == null) {
    		instance = new CertificateCacheInternal();
    	}
    	return instance;
    }
    
    /**
     * 
     * @param adm
     * @param type
     * @param issuerDN
     * @return Collection of Certificate never null
     */
    protected Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
    	return getStoreSession().findCertificatesByType(adm, type, issuerDN);    		
    }

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

}
