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
package org.cesecore.authorization.cache;

import java.util.Collection;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.access.AccessSets;
import org.cesecore.authorization.access.AccessTree;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.roles.RoleData;

/**
 * Class Holding cache variable. Needed because EJB spec does not allow volatile, non-final fields in session beans.
 * 
 * This file is based on AuthorizationCache (updated 2010-12-14) and Authorizer (probably r10794) from EJBCA
 * 
 * TODO: This class requires some minor unit tests.
 * 
 * @version $Id$
 * 
 */
public class AccessTreeCache {

    /*
     * Cache of authorization data. This cache may be unsynchronized between multiple instances of EJBCA, but is common to all threads in the same VM.
     * Set volatile to make it thread friendly.
     */
    private volatile AccessTree accessTree = null;
    private volatile AccessSets accessSets = null;
    /*
     * Help variable used to check that authorization trees are updated.
     */
    private volatile int accessTreeUpdatenumber = -1;
    /* help variable used to control that cache update isn't performed to often. */
    private volatile long lastUpdateTime = -1;

    /**
     * Updates the access tree with the roles (and associated resources) specified in the first parameter. 
     * 
     * 
     * @param roles A collection of RoleData objects.
     * @param authorizationTreeUpdateNumber FIXME: Document me.
     */
    public synchronized void updateAccessTree(Collection<RoleData> roles, int authorizationTreeUpdateNumber) {
        if (accessTree == null) {
            accessTree = new AccessTree();
            accessSets = new AccessSets();
        }
        accessTree.buildTree(roles);
        accessSets.buildAccessSets(roles);
        this.accessTreeUpdatenumber = authorizationTreeUpdateNumber;
        setLastUpdateToNow();
    }

    /**
     * Answers whether the access tree needs to be updated.
     * 
     * @return <code>true</code> if the access tree hasn't been instantiated, <i>or</i> if the time interval has passed that specified in the cesecore
     *         configuration file. Return <code>false</code> otherwise.
     */
    public boolean needsUpdate() {
        if ((accessTree == null) || (lastUpdateTime + CesecoreConfiguration.getCacheAuthorizationTime() < System.currentTimeMillis())) {
            return true;
        }
        return false;
    }

    public void forceCacheExpire() {
    	lastUpdateTime = -1;
    	accessTreeUpdatenumber = -1;
    }
    
    public void setLastUpdateToNow() {
        lastUpdateTime = System.currentTimeMillis();
    }
    
    public AccessTree getAccessTree() {
        return accessTree;
    }

    /** Returns all local access sets */
    public AccessSets getAccessSets() {
        return accessSets;
    }
    
    /** Returns the local access rules for the given authentication token. */
    public AccessSet getAccessSetForAuthToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        return accessSets.getAccessSetForAuthToken(authenticationToken);
    }

    public int getAccessTreeUpdateNumber() {
        return accessTreeUpdatenumber;
    }
}
