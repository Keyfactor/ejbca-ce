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

public interface DummyCertWithoutIndex extends Dto<Long>, Comparable<DummyCertWithoutIndex> {

    Long id();
    default Long getId() { return id(); } // Needed for ConfigDump

    String name();
    default String getName() { return name(); } // Needed for ConfigDump

    Map<Object, Object> data();
    default Map<Object, Object> getData() { return data(); } // Needed for ConfigDump

    DummyCertWithoutIndexBuilder toBuilder();
    DummyCertWithoutIndex withId(final Long id);
    DummyCertWithoutIndex withName(final String name);
    DummyCertWithoutIndex withData(final Map<Object, Object> data);

}
