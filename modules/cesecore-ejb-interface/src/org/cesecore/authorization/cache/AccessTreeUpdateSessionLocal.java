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

import javax.ejb.Local;

import org.cesecore.authorization.access.AuthorizationCacheReloadListener;

/**
 * @version $Id$
 */
@Local
public interface AccessTreeUpdateSessionLocal {

    /**
     * Method incrementing the authorization tree update number and thereby
     * signaling to other beans that they should reconstruct their access trees.
     */
    void signalForAccessTreeUpdate();
    
    /**
     * Method returning the newest authorizationtreeupdatenumber.
     * Should be checked when the access tree cache has expired to avoid rebuilding the tree if there are no database changes. 
     */
    int getAccessTreeUpdateNumber();

    /**
     * Adds a method to be triggered when the authorization cache should be reloaded.
     * The event is called synchronously.
     * <p>
     * This is a workaround until we can use JEE Events.
     */
    void addReloadEvent(AuthorizationCacheReloadListener listener);

}
