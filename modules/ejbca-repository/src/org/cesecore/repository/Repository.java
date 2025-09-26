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

package org.cesecore.repository;

import org.cesecore.repository.dto.Dto;

import java.util.List;

public interface Repository <T extends Dto<Id>, Id> {

    T add(final T dto);

    T findById(final Id id);

    T findByIndex(final String index);

    List<T> findAll();

    T addOrUpdate(final T dto);

    void update(final T dto);

    T removeById(final Id id);

    T removeByIndex(final String index);

}
