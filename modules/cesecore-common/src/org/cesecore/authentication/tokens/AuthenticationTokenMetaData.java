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
package org.cesecore.authentication.tokens;

import java.util.List;
import java.util.Map;

import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * Meta data definition and marker interface used by the ServiceLoader that all AuthenticationToken types must have to be usable.
 * 
 * @version $Id$
 */
public interface AuthenticationTokenMetaData {
    
    /** @return the type identifier of the AuthenticationToken */
    String getTokenType();

    /** @return true if the this type of AuthenticationToken should be UI configurable. */
    boolean isUserConfigurable();
    
    /** @return a List of all available AccessMatchValue for this type of AuthenctionToken */
    List<? extends AccessMatchValue> getAccessMatchValues();

    /** @return a Map of all available database values mapped to the AccessMatchValue in the context of this type of AuthenticationToken */
    Map<Integer,AccessMatchValue> getAccessMatchValueIdMap();

    /** @return a Map of all available names mapped to the AccessMatchValue in the context of this type of AuthenticationToken */
    Map<String, AccessMatchValue> getAccessMatchValueNameMap();

    /** @return the default AccessMatchValue for this type of AuthenticationToken */
    AccessMatchValue getAccessMatchValueDefault();

    /** @return true if the token is a super token (granting access to any rule) */
    boolean isSuperToken();
}
