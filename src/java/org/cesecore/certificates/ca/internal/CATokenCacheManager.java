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
package org.cesecore.certificates.ca.internal;

import java.util.Hashtable;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.catoken.CAToken;


/**
 * Class managing a cache of CA Crypto Tokens. It is not really a cache, just an object registry.
 * 
 * Based on EJBCA version: CATokenManager.java 10174 2010-10-12 08:25:40Z mikekushner $
 * 
 * @version $Id: CATokenCacheManager.java 253 2011-02-14 13:33:59Z tomas $
 * 
 */
public class CATokenCacheManager {
    private static final Logger log = Logger.getLogger(CATokenCacheManager.class);

    /** Registry (cache) of CATokens associated with a specific CA, kept so CATokens will not
     * be destroyed when a bean is passivated for example. */
    private Hashtable<Integer, CAToken> tokenRegistry = new Hashtable<Integer, CAToken>();

    /** Implementing the Singleton pattern */
    private static CATokenCacheManager instance = null;

    /** Don't allow external creation of this class, implementing the Singleton pattern. 
     */
    private CATokenCacheManager() {}
    
    /** Get the instance of this singleton
     * 
     */
    public synchronized static CATokenCacheManager instance() {
        if (instance == null) {
            instance = new CATokenCacheManager();
        }
        return instance;
    }
    
    /** Returns a previously registered (using addCAToken) CAToken, or null.
     * 
     * @param caid the id of the CA whose CAToken you want to fetch.
     * @return The previously added CAToken or null if the token does not exist in the registry.
     */
    public CAToken getCAToken(int caid) {
        return tokenRegistry.get(caid);
    }
    
    /** Adds a CA token to the token registry. If a token already exists for the given CAid, 
     * the old one is removed and replaced with the new. If the token passed is null, an existing token is removed.
     * 
     * @param caid the id of the CA whose CAToken you want to fetch.
     * @param token the token to be added
     */
    public synchronized void addCAToken(int caid, CAToken token) {
        if (tokenRegistry.containsKey(caid)) {
            tokenRegistry.remove(caid);
            log.debug("Removed old CA token for CA: "+caid);
        }
        if (token != null) {
            tokenRegistry.put(Integer.valueOf(caid), token);            
            log.debug("Added CA token for CA: "+caid);
        }
    }

    /** Removes a CA token from the cache to force an update the next time the CA is read
     * 
     */
    public synchronized void removeCAToken(int caid) {
        if (tokenRegistry.containsKey(caid)) {
        	tokenRegistry.remove(caid);
            log.debug("Removed old CA token from registry: "+caid);
        }
    }

    /** Remove all CA tokens
     */
    public synchronized void removeAll() {
    	tokenRegistry = new Hashtable<Integer, CAToken>();
	}
    
}
