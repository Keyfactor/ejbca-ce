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

package org.cesecore.authorization.user.matchvalues;

/**
 * Interface for all AccessMatchValue implementations.
 * 
 * @version $Id$
 *
 */
public interface AccessMatchValue {

    /**
     * 
     * @return the numeric value of this AccessMatchValue, i.e. its database value. 
     */
    int getNumericValue();
    
    /**
     * A string value inherent to the implementing AccessMatchValue. This value should be unique, but independent of code 
     * (i.e do not use Class.getSimpleName()) to avoid upgrade issues in case of future refactorization.
     * 
     * @return a name for the implementation of this match value. 
     */
    String getTokenType();
    
    /**
     * 
     * @return the name of the implementing enumeration.
     */
    String name();
}