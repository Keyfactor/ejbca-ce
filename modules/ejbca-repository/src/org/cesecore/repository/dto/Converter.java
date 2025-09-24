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
 * Converter that converts a database bean into a record and vice versa.
 * @param <T> The record class.
 * @param <Bean> The database bean class.
 */
public interface Converter<T extends Dto, Bean> {

    Bean toBean(T dto);

    T toDto(Bean bean);

}
