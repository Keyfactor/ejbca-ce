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

package org.ejbca.core.ejb.ra.raadmin;

import java.util.Map;
import java.util.HashMap;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.EJB;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.RaStyleInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Global cache of RaStyleInfos fetched via Peers. Each entry is mapped to an administrator, containing its available custom RA Styles (CSS files and logo).
 * This cache prevents multiple requests over the Peers protocol when an administrator loads the RA page and style resources are requested by the servlet filter
 * (RaStyleRequestFilter). Since style archives may be very heavy to transfer, a check for changes is sent via Peers before reloading the styles.
 * 
 * @version $Id$
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
@TransactionManagement(TransactionManagementType.BEAN)
public class RaStyleCacheBean {

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    
    private final Logger log = Logger.getLogger(RaStyleCacheBean.class);
    
    private Map<AuthenticationToken, List<RaStyleInfo>> raStyleCache;
    private Map<AuthenticationToken, Long> lastUpdateMap;
    
    @PostConstruct
    public void initialize() {
        raStyleCache = new HashMap<>();
        lastUpdateMap = new HashMap<>();
        if (log.isDebugEnabled()) {
            log.info(this.getClass().getName() + " initialized");
        }
    }
    
    public RaStyleCacheBean() {}
    
    public void invalidateCache() {
        raStyleCache = new HashMap<>();
        lastUpdateMap = new HashMap<>();
    }
    
    /**
     * Checks if administrators actual available RA Styles differentiate from the cached styles
     * @param authenticationToken of the requesting administrator
     * @return true if cache is invalid and requires update
     */
    public boolean needsUpdate(AuthenticationToken authenticationToken) {
        List<RaStyleInfo> cachedStyle = raStyleCache.get(authenticationToken);
        if (cachedStyle != null) {
            return raMasterApiProxyBean.getAvailableCustomRaStyles(authenticationToken, cachedStyle.hashCode()) != null;
        }
        return true;
    }
    
    /**
     * Returns custom RA Styles associated with the role of the requesting administrator. If the administrator has requested
     * styles very recently, the same content will be returned to prevent requests via Peers for for every resource request
     * e.g. in a page load in the RA web.
     * @param authenticationToken of the requesting administrator
     * @return List of custom RA styles available for the requesting administrator
     */
    public List<RaStyleInfo> getAvailableRaStyles(AuthenticationToken authenticationToken) {
        List<RaStyleInfo> availableRaStyles;
        long now = System.currentTimeMillis();
        if (raStyleCache.containsKey(authenticationToken)) {
            List<RaStyleInfo> cachedStyles = raStyleCache.get(authenticationToken);
            // This prevents lookup over Peers for every requested resource in a page load.
            if (now - getLastUpdate(authenticationToken) < 1000) {
                return cachedStyles;
            }
            // Check for changes
            availableRaStyles = raMasterApiProxyBean.getAvailableCustomRaStyles(authenticationToken, cachedStyles.hashCode());
            if (availableRaStyles == null) {
                // No changes, use cached styles
                availableRaStyles = cachedStyles;
            } else {
                raStyleCache.put(authenticationToken, availableRaStyles);
            }
        } else {
            // Full reload of styles
            availableRaStyles = raMasterApiProxyBean.getAvailableCustomRaStyles(authenticationToken, 0);
            raStyleCache.put(authenticationToken, availableRaStyles);
        }
        lastUpdateMap.put(authenticationToken, now);
        return availableRaStyles;
    }
    
    /** @return returns Map of all cached RA Styles*/
    public Map<AuthenticationToken, List<RaStyleInfo>> getCachedAdminStylesMap() {
        return raStyleCache;
    }
    
    /** @return last time the administrator requested styles from this cache */
    public long getLastUpdate(AuthenticationToken authenticationToken) {
        Long lastUpdate = lastUpdateMap.get(authenticationToken);
        return lastUpdate == null ? -1 : lastUpdate;
    }
}
