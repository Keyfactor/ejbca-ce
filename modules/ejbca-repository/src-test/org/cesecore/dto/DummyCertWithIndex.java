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

package org.cesecore.dto;

import java.util.Map;
import org.cesecore.dto.Dto;

public interface DummyCertWithIndex extends Dto<Long>, Comparable<DummyCertWithIndex> {

    Long id();
    default Long getId() { return id(); } // Needed for ConfigDump

    String commonName();
    default String getCommonName() { return commonName(); } // Needed for ConfigDump

    String name();
    default String getName() { return name(); } // Needed for ConfigDump

    Map<Object, Object> data();
    default Map<Object, Object> getData() { return data(); } // Needed for ConfigDump

    DummyCertWithIndexBuilder toBuilder();
    DummyCertWithIndex withId(final Long id);
    DummyCertWithIndex withCommonName(final String commonName);
    DummyCertWithIndex withName(final String name);
    DummyCertWithIndex withData(final Map<Object, Object> data);

    String[] indexNames();

    Object[] indexValues();

}
