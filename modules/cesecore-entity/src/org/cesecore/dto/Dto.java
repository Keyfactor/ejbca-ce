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

package org.cesecore.dto;

import java.io.Serializable;

/**
 * An interface that represents an entity in the cache.
 * @param <Id> The class that is used as a primary key
 */
public interface Dto<Id> extends Serializable {

    Id id();

    default boolean isIdUnassigned() { return id() == null; }

    Dto<Id> withId(Id id);

    default String[] indexNames() { return new String[0]; }

    default Object[] indexValues() { return new Object[0]; }

}
