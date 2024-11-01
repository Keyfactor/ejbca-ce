/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

/**
 * Provides callback methods UI objects to be able to populate grouped lists
 */

public interface UiCallBackList {
    
    /**
     * Provides a callback interface to the MBean to be able to populate a grouped list
     * 
     * @return a map of profiles, mapped to the group
     */
    LinterProfileList getProfileList();

}
