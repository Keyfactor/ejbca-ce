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

public class DummyCertWithIndexBuilder {

    private Long id;
    private String commonName;
    private String name;
    private Map<Object, Object> data;

    public DummyCertWithIndexBuilder() {
    }

    public DummyCertWithIndexBuilder(DummyCertWithIndex dummyCertWithIndex) {
        setId(dummyCertWithIndex.id());
        setCommonName(dummyCertWithIndex.commonName());
        setName(dummyCertWithIndex.name());
        setData(dummyCertWithIndex.getData());
    }

    public DummyCertWithIndexBuilder setId(final Long id) {
        this.id = id;
        return this;
    }

    public DummyCertWithIndexBuilder setCommonName(final String commonName) {
        this.commonName = commonName;
        return this;
    }

    public DummyCertWithIndexBuilder setName(final String name) {
        this.name = name;
        return this;
    }

    public DummyCertWithIndexBuilder setData(final Map<Object, Object> data) {
        this.data = data;
        return this;
    }

    public DummyCertWithIndex build() {
        return new DummyCertWithIndexRecord(id,
                           commonName,
                           name,
                           Collections.unmodifiableMap(data == null ? new HashMap<>() : data));

    }
}
