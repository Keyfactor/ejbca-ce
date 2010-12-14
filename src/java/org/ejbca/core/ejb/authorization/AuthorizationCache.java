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
package org.ejbca.core.ejb.authorization;

import java.util.Collection;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.Authorizer;

/**
 * Class Holding cache variable. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, or when the cache must be updated. The using class must ensure that it does not try to use a null value 
 * (by calling setAuthorizer before any cache is used), and that the cache is updated when 
 * the method "needsUpdate" returns true. 
 * 
 * An example of this is by using internal methods in the calling class like:
 * <pre>
 *   private Authorizer getAuthorizer() {
 *       if (authCache.getAuthorizer() == null) {
 *           authCache.setAuthorizer(new Authorizer(getAdminGroups(), logSession, LogConstants.MODULE_AUTHORIZATION));
 *       }
 *       return authCache.getAuthorizer();
 *   }
 * </pre>
 * @version $Id$
 */
public final class AuthorizationCache {

    private static final Logger LOG = Logger.getLogger(AuthorizationCache.class);


    /**
     * Cache of authorization data. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile Authorizer authorizer = null;
    /**
     * help variable used to check that authorization trees are updated.
     */
    private volatile int authorizationtreeupdatenumber = -1;
    /** help variable used to control that cache update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

	public AuthorizationCache() {
		// Do nothing
	}

	public void updateAuthorizationCache(Collection<AdminGroup> adminGroups, int authorizationTreeUpdateNumber) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateAuthorizationCache");
        }
        authorizer.buildAccessTree(adminGroups);
        this.authorizationtreeupdatenumber = authorizationTreeUpdateNumber;
        lastupdatetime = System.currentTimeMillis();
        if (LOG.isTraceEnabled()) {
            LOG.trace("<updateAuthorizationCache");
        }
	}

	public boolean needsUpdate() {
        if ((authorizer == null)
                || (lastupdatetime + EjbcaConfiguration.getCacheAuthorizationTime() < System.currentTimeMillis())) {
        	return true;
        }
        return false;
	}

    public Authorizer getAuthorizer() {
        return authorizer;
    }

    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

	public int getAuthorizationTreeUpdateNumber() {
		return authorizationtreeupdatenumber;
	}

	
}
