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

package org.ejbca.dto;

import org.cesecore.repository.dto.Dto;

import java.util.Map;

public interface DummyCert extends Dto<Long>, Comparable<DummyCert> {

    Long id();
    String name();
    Map<Object, Object> data();

    DummyCertBean toBean();
    DummyCertBuilder toBuilder();
    DummyCert withId(final Long id);
    DummyCert withName(final String name);
    DummyCert withData(final Map<Object, Object> data);

}
