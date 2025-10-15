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

import java.util.List;
import jakarta.ejb.Local;

/**
 * Interface for the Certificate Template Cache.
 * Provides methods to store and retrieve certificate templates from Active Directory.
 */
@Local
public interface CertificateTemplateCacheLocal {

    /**
     * Loader used to fetch template records when the cache is empty or expired.
     */
    @FunctionalInterface
    interface TemplateLoader {
        List<TemplateRecord> load();
    }

    /**
     * Gets template records from cache if available and not expired, otherwise returns null
     * 
     * @param alias the alias to get templates for
     * @return list of TemplateRecord entries, or null if not in cache or expired
     */
    default List<TemplateRecord> getTemplateRecords(String alias) {
        throw new UnsupportedOperationException("Certificate template cache methods are only supported in EJBCA Enterprise");
    }

    /**
     * Gets template records from cache or loads them using the provided loader if absent/expired.
     * Implementations must ensure that only one loader runs per alias at a time.
     *
     * @param alias the alias to get templates for
     * @param timeToLive the time to live in seconds for the loaded entry
     * @param loader a function that returns the list of TemplateRecord when a load is needed
     * @return the list of TemplateRecord entries for the alias
     */
    default List<TemplateRecord> getOrLoadTemplateRecords(String alias, int timeToLive, TemplateLoader loader) {
        throw new UnsupportedOperationException("Certificate template cache methods are only supported in EJBCA Enterprise");
    }

    /**
     * Clears cache for a specific alias
     * 
     * @param alias the alias to clear cache for
     */
    default void clearCache(String alias) {
        // Do nothing on systems that do not have a certificate template cache
    }

    /**
     * Clears all caches, called from ClearCacheSessionBean
     */
    default void clearAllCaches() {
        // Do nothing on systems that do not have a certificate template cache
    }
}
