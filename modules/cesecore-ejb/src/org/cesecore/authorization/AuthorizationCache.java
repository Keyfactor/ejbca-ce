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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Extremely basic implementation that assumes that AuthenticationToken generate non-colliding hashCodes.
 * 
 * TODO: Require AuthenticationToken to generate globally unique identifiers (that takes nesting into account) and use this as key
 * TODO: Base this on org.cesecore.util.ConcurrentCache and expire older entries
 * TODO: Expire old tokens to prevent every growing structure consuming memory
 * 
 * @version $Id$
 */
public enum AuthorizationCache {
    INSTANCE;

    private Map<AuthenticationToken, HashMap<String, Boolean>> map = new ConcurrentHashMap<>();
    
    public void flush() {
        map.clear();
    }

    public HashMap<String, Boolean> get(final AuthenticationToken authenticationToken) {
        return map.get(authenticationToken);
    }

    public void put(final AuthenticationToken authenticationToken, final HashMap<String, Boolean> accessRules) {
        map.put(authenticationToken, accessRules);
    }

}
