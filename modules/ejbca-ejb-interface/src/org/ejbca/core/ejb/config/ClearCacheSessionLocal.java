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
package org.ejbca.core.ejb.config;

import jakarta.ejb.Local;

/**
 * Functionality for clearing all caches of the local EJBCA instance.
 * 
 * @version $Id$
 */
@Local
public interface ClearCacheSessionLocal {

    /**
     * Clear all caches of the local instance.
     * @param excludeActiveCryptoTokens when true the active and auto-activated CryptoTokens will be excluded from the clear operation. 
     */
    void clearCaches(boolean excludeActiveCryptoTokens);
}
