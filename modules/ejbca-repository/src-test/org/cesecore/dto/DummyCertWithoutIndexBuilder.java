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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DummyCertWithoutIndexBuilder {

    private Long id;
    private String name;
    private Map<Object, Object> data;

    public DummyCertWithoutIndexBuilder() {
    }

    public DummyCertWithoutIndexBuilder(DummyCertWithoutIndex dummyCertWithoutIndex) {
        setId(dummyCertWithoutIndex.id());
        setName(dummyCertWithoutIndex.name());
        setData(dummyCertWithoutIndex.getData());
    }

    public DummyCertWithoutIndexBuilder setId(final Long id) {
        this.id = id;
        return this;
    }

    public DummyCertWithoutIndexBuilder setName(final String name) {
        this.name = name;
        return this;
    }

    public DummyCertWithoutIndexBuilder setData(final Map<Object, Object> data) {
        this.data = data;
        return this;
    }

    public DummyCertWithoutIndex build() {
        return new DummyCertWithoutIndexRecord(id,
                           name,
                           Collections.unmodifiableMap(data == null ? new HashMap<>() : data));

    }
}
