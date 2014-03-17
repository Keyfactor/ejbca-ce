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
package org.cesecore.authorization.user.matchvalues;

/**
 * Marker interface for AccessMatchValue plugins
 * 
 * @version $Id$
 *
 */
public interface AccessMatchValuePlugin extends AccessMatchValue {

    /**
     * @return all the types defined by this implementation. 
     */
    AccessMatchValue[] getValues();
}
