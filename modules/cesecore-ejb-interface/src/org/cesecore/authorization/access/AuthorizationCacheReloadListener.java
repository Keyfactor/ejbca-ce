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
package org.cesecore.authorization.access;

/**
 * Workaround until we can use JEE Events. See the comments in AccessTreeUpdateSessionBean
 * 
 * @version $Id$
 */
public interface AuthorizationCacheReloadListener {

    /** Invoked when the authorization system has been modified. */
    void onReload(AuthorizationCacheReload event);

    /** @return a human readable name for logging of who is subscribing to events. */
    String getListenerName();
}
