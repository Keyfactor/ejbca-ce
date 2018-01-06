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

package org.cesecore.util;

import org.json.simple.JSONObject;

/**
 * Interface implemented by classes which can be converted into JSON.
 * @version $Id$
 */
public interface JsonSerializable {
    /**
     * Get the JSON representation of this object which can be saved to persistent
     * storage, such as a database, file or network resource.
     * @return the JSON representation of this object
     */
    JSONObject toJson();
}
