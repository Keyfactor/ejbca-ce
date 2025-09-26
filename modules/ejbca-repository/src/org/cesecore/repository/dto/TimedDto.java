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

/**
 * A record stored in the Cache to keep track of how when an object was stored.
 * @param created The epoch time in milliseconds when the object was created.
 * @param dto The object to store in the cache.
 * @param <T> The class of the object in the cache.
 */
public record TimedDto<T extends Dto>(long created, T dto) {

    /**
     * Creates a TimedDto with the current time as timestamp.
     * @param dto The object to store in the cache.
     */
    public TimedDto(T dto) {
        this(System.currentTimeMillis(), dto);
    }

}
