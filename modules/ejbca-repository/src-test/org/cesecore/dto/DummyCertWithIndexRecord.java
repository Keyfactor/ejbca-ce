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

import org.cesecore.util.CompareUtil;
import java.util.Map;

public record DummyCertWithIndexRecord(
                       Long id,
                       String commonName,
                       String name,
                       Map<Object, Object> data) implements DummyCertWithIndex {

    @Override
    public Long id() {
        return id;
    }

    @Override
    public String[] indexNames() {
        return new String[] { "commonName", "name" };
    }

    @Override
    public Object[] indexValues() {
        return new Object[] { commonName, name };
    }


    @Override
    public DummyCertWithIndexBuilder toBuilder() {
        return new DummyCertWithIndexBuilder(this);
    }

    @Override
    public DummyCertWithIndex withId(final Long id) {
        return new DummyCertWithIndexRecord(
                id,
                commonName,
                name,
                data);
    }

    @Override
    public DummyCertWithIndex withCommonName(final String commonName) {
        return new DummyCertWithIndexRecord(
                id,
                commonName,
                name,
                data);
    }

    @Override
    public DummyCertWithIndex withName(final String name) {
        return new DummyCertWithIndexRecord(
                id,
                commonName,
                name,
                data);
    }

    public DummyCertWithIndex withData(final Map<Object, Object> data) {
        return new DummyCertWithIndexRecord(
            id,
            commonName,
            name,
            data);
    }

    @Override
    public int compareTo(final DummyCertWithIndex dummyCertWithIndex) {
        int c;
        c = CompareUtil.compare(this.id, dummyCertWithIndex.id());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.commonName, dummyCertWithIndex.commonName());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.name, dummyCertWithIndex.name());
        if (c != 0) {
            return c;
        }
        return 0;
    }

}
