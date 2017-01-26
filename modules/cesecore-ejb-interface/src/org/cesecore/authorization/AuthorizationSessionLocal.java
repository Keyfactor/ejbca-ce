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
package org.cesecore.authorization;

import javax.ejb.Local;

/**
 * 
 * @version $Id$
 */
@Local
public interface AuthorizationSessionLocal extends AuthorizationSession {

    /**
     * Helper method to clear the local access control rule cache. Normally the cache expires after configured time, but when modifying access rules
     * on the local node we can force cache clearing so we don't have to wait. Other nodes in a cluster will still wait until expire though.
     */
    void forceCacheExpire();
}
