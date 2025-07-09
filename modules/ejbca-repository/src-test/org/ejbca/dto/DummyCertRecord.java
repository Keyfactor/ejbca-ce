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

import org.cesecore.repository.util.CompareUtil;
import java.util.Map;

public record DummyCertRecord(
                       Long id,
                       String name,
                       Map<Object, Object> data) implements DummyCert {

    @Override
    public Long id() {
        return id;
    }

    @Override
    public String index() {
        return null;
    }

    @Override
    public DummyCert withIndex(final String index) {
        return this;
    }

    @Override
    public DummyCertBean toBean() {
        return new DummyCertConverter().toBean(this);
    }

    @Override
    public DummyCertBuilder toBuilder() {
        return new DummyCertBuilder(this);
    }

    @Override
    public DummyCert withId(final Long id) {
        return new DummyCertRecord(
                id,
                name(),
                data);
    }

    @Override
    public DummyCert withName(final String name) {
        return new DummyCertRecord(
                id(),
                name,
                data);
    }

    public DummyCert withData(final Map<Object, Object> data) {
        return new DummyCertRecord(
            id(),
            name(),
            data);
    }

    @Override
    public int compareTo(final DummyCert dummyCert) {
        int c;
        c = CompareUtil.compare(this.id, dummyCert.id());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.name, dummyCert.name());
        if (c != 0) {
            return c;
        }
        return 0;
    }

}
