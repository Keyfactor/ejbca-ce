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
package org.ejbca.core.ejb.authorization;

import java.util.Map;
import java.util.Set;

import javax.ejb.Local;

/**
 * @see AuthorizationSystemSession
 * @version $Id$
 */
@Local
public interface AuthorizationSystemSessionLocal extends AuthorizationSystemSession {

    /** @return a Map<category name, Map<resource,resourceName>> */
    Map<String, Map<String, String>> getAllResourceAndResourceNamesByCategory();

    /** @return a Set of all resources on this installation (optionally ignoring if certain resources is not in use) */
    Set<String> getAllResources(boolean ignoreLimitations);

    boolean initializeAuthorizationModule();
}
