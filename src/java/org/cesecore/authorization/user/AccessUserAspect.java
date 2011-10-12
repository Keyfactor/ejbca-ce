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

package org.cesecore.authorization.user;

import java.io.Serializable;

/**
 * Interface for AccessUserAspectData.  
 * 
 * Based on cesecore:
 *      AccessUserAspect.java 948 2011-07-18 09:04:26Z mikek
 * 
 * @version $Id$
 *
 */

public interface AccessUserAspect extends Serializable {

    int getMatchWith();

    X500PrincipalAccessMatchValue getMatchWithByValue();

    void setMatchWith(Integer matchWith);

    void setMatchWithAsValue(X500PrincipalAccessMatchValue matchWith);

    int getMatchType();

    void setMatchType(Integer matchType);

    void setMatchTypeAsValue(AccessMatchType matchType);

    AccessMatchType getMatchTypeAsType();

    String getMatchValue();

    void setMatchValue(String matchValue);

    Integer getCaId();

    void setCaId(Integer caId);

    /**
     * Method used by the access tree to determine the priority. The priority is the same as match with value.
     * 
     * @return the matchWith value for the AccessUserData instance.
     */
    X500PrincipalAccessMatchValue getPriority();

}