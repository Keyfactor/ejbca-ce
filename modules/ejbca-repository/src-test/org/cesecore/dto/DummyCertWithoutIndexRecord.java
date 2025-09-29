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

public record DummyCertWithoutIndexRecord(
                       Long id,
                       String name,
                       Map<Object, Object> data) implements DummyCertWithoutIndex {

    @Override
    public Long id() {
        return id;
    }


    @Override
    public DummyCertWithoutIndexBuilder toBuilder() {
        return new DummyCertWithoutIndexBuilder(this);
    }

    @Override
    public DummyCertWithoutIndex withId(final Long id) {
        return new DummyCertWithoutIndexRecord(
                id,
                name,
                data);
    }

    @Override
    public DummyCertWithoutIndex withName(final String name) {
        return new DummyCertWithoutIndexRecord(
                id,
                name,
                data);
    }

    public DummyCertWithoutIndex withData(final Map<Object, Object> data) {
        return new DummyCertWithoutIndexRecord(
            id,
            name,
            data);
    }

    @Override
    public int compareTo(final DummyCertWithoutIndex dummyCertWithoutIndex) {
        int c;
        c = CompareUtil.compare(this.id, dummyCertWithoutIndex.id());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.name, dummyCertWithoutIndex.name());
        if (c != 0) {
            return c;
        }
        return 0;
    }

}
