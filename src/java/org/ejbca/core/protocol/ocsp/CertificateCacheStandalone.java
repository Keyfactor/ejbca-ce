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

import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.store.CertificateStoreOnlyDataSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreOnlyDataSessionRemote;
import org.ejbca.core.model.log.Admin;


/**
 * Class managing a cache of Certificates. This class should be optimized for quick lookups of CA certificates that the 
 * OCSP responder needs to fetch.
 * 
 * @version $Id$
 * 
 */
public class CertificateCacheStandalone extends CertificateCache {
	
	private static CertificateCacheStandalone instance = null;
	
    private CertificateCacheStandalone() {
    	super(null);
    }
    
    /**  
     * Returns a new CertificateCache for the external OCSP responder  
     */
    public static synchronized CertificateCacheStandalone getInstance() {
    	if (instance == null) {
    		instance = new CertificateCacheStandalone();
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
    	return getStoreSessionOnlyData().findCertificatesByType(adm, type, issuerDN);    		
    }

    private CertificateStoreOnlyDataSession m_certStoreOnly = null;
    private synchronized CertificateStoreOnlyDataSession getStoreSessionOnlyData(){
    	if(m_certStoreOnly == null){	
    		try {
                m_certStoreOnly = JndiHelper.getRemoteSession(CertificateStoreOnlyDataSessionRemote.class);	// TODO: Use a local EJB stub instead
    		}catch(Exception e){
    			throw new EJBException(e);      	  	    	  	
    		}
    	}
    	return m_certStoreOnly;
    }

}
