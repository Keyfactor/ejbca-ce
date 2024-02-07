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
package org.ejbca.core.protocol.msae;

import javax.ejb.Local;

import org.ejbca.config.MSAutoEnrollmentConfiguration;

@Local
public interface MsaeRaConfigCacheLocal {

    /**
     * 
     * @param alias msae alias which we are looking for its configuration in the cache
     * @return associated msae configuration given the alias
     */
    default MSAutoEnrollmentConfiguration getMsaeRaConfigCached(final String alias) {
        throw new UnsupportedOperationException("MSAE is an EJBCA Enterprise only feature");
    }

    /**
     * Clears the cache, called from {@link #ClearCacheSessionBean}
     */
    default void flushMsaeRaConfigCache() {
        throw new UnsupportedOperationException("MSAE is an EJBCA Enterprise only feature");
    }
}
