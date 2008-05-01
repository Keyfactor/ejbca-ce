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

package org.ejbca.core.model.ca.caadmin;

import java.util.Date;
import java.util.Hashtable;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.caadmin.CADataBean;


/**
 * Class managing a cache of CAs. It is not really a cache, just an object registry.
 * 
 * @version $Id$
 * 
 */
public class CACacheManager {
	
    /** Log4j instance for Base */
    private static transient Logger log = Logger.getLogger(CACacheManager.class);

    /** Registry of CAs, kept so CA */
    private Hashtable caRegistry = new Hashtable();

    /** Implementing the Singleton pattern */
    private static CACacheManager instance = null;

    /** Don't allow external creation of this class, implementing the Singleton pattern. 
     */
    private CACacheManager() {}
    
    /** Get the instance of this singleton
     * 
     */
    public synchronized static CACacheManager instance() {
        if (instance == null) {
            instance = new CACacheManager();
        }
        return instance;
    }
    
    /** Returns a previously registered (using addCAToken) CA, or null.
     * 
     * @param caid the id of the CA whose CA object you want to fetch.
     * @return The previously added CA or null if the CA does not exist in the registry.
     */
    public CA getCA(int caid, CADataBean caData) {
        CA ret = (CA)caRegistry.get(new Integer(caid));
        if (ret != null) {
        	// We mainly cache the xml data, some of the other values may change slightly at will...
        	ret.setStatus(caData.getStatus());
        	ret.setExpireTime(new Date(caData.getExpireTime()));
        	ret.setName(caData.getName());
        	ret.setSubjectDN(caData.getSubjectDN());
        	ret.setCAId(caid);
        }
        return ret;
    }
    
    /** Adds a CA to the registry. If a CA already exists for the given CAid, 
     * the old one is removed and replaced with the new. If the CA passed is null, an existing CA is removed.
     * 
     * @param caid the id of the CA you want to fetch.
     * @param ca the CA to be added
     */
    public synchronized void addCA(int caid, CA ca) {
    	removeCA(caid);
        if (ca != null) {
            caRegistry.put(new Integer(caid), ca);            
            log.debug("Added CA to registry: "+caid);
        }
    }    
    
    /** Removes a CA from the cache to force an update the next time the CA is read
     * 
     */
    public synchronized void removeCA(int caid) {
        if (caRegistry.containsKey(new Integer(caid))) {
            caRegistry.remove(new Integer(caid));
            log.debug("Removed old CA from registry: "+caid);
        }
    }
}
