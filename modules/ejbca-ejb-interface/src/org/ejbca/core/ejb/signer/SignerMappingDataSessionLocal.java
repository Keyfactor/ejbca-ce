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
package org.ejbca.core.ejb.signer;

import java.util.List;
import java.util.Map;

import javax.ejb.Local;

/**
 * Create Read Update Delete (CRUD) interface for SignerMappingData.
 * 
 * @version $Id$
 */
@Local
public interface SignerMappingDataSessionLocal {

    /** @return the specified Signer */
    SignerMapping getSignerMapping(int signerMappingId);

    /** Add the specified Signer to the database and return the id used to store it */
    int mergeSignerMapping(SignerMapping signerMapping) throws SignerMappingNameInUseException;

    /** Remove the specified Signer from the database. */
    void removeSignerMapping(final int signerMappingId);

    /** @return a list of all Signer identifiers in the database. */
    List<Integer> getSignerMappingIds();

    /** @return a (copy of a) name to id lookup table */
    Map<String, Integer> getCachedNameToIdMap();

    /** Clears the Signer cache. */
    void flushCache();

    /** @return true if the specified name is already in use by another SignerMapping (checks the database, not the cache) */
    boolean isSignerMappingNameUsed(String signerName);

    /** @return true if the specified name is used by exactly one SignerMapping and that object has the same id (checks the database, not the cache) */
    boolean isSignerMappingNameUsedByIdOnly(String signerMappingName, int signerMappingId);

}
