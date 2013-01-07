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
package org.cesecore.keys.token;

import java.util.List;
import java.util.Map;

import javax.ejb.Local;

/**
 * 
 * @version $Id$
 */
@Local
public interface CryptoTokenSessionLocal {

    /** @return the specified CryptoToken */
    CryptoToken getCryptoToken(int cryptoTokenId);

    /** Add the specified CryptoToken to the database and return the id used to store it */
    int mergeCryptoToken(CryptoToken cryptoToken);

    /** Remove the specified CryptoToken from the database. */
    void removeCryptoToken(final int cryptoTokenId);

    /** @return a list of all CryptoToken identifiers in the database. */
    List<Integer> getCryptoTokenIds();

    /** @return a (copy of a) name to id lookup table */
    Map<String, Integer> getCachedNameToIdMap();

    /** Clears the CryptoToken cache. */
    void flushCache();
}
