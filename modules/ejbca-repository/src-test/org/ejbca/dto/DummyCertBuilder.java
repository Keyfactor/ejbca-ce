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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DummyCertBuilder {

    private Long id;
    private String name;
    private Map<Object, Object> data;

    public DummyCertBuilder() {
    }

    public DummyCertBuilder(DummyCert dummyCert) {
        setId(dummyCert.id());
        setName(dummyCert.name());
        setData(dummyCert.data());
    }

    public DummyCertBuilder setId(final Long id) {
        this.id = id;
        return this;
    }

    public DummyCertBuilder setName(final String name) {
        this.name = name;
        return this;
    }

    public DummyCertBuilder setData(final Map<Object, Object> data) {
        this.data = data;
        return this;
    }

    public DummyCert build() {
        return new DummyCertRecord(id,
                           name,
                           Collections.unmodifiableMap(data == null ? new HashMap<Object, Object>() : data));

    }
}
