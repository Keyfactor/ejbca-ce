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

package org.cesecore.repository.dto;

import java.io.Serializable;

/**
 * An interface that represents an entity in the cache.
 * @param <Id> The class that is used as a primary key
 */
public interface Dto<Id> extends Serializable {

    Id id();
    String index();
    Dto withId(Id id);
    Dto withIndex(String index);

}
