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

package org.ejbca.dto;

import org.cesecore.repository.util.CompareUtil;

import java.util.Map;

public record PublisherDataRecord(
                       Integer id,
                       String name,
                       Integer updateCounter,
                       Map<Object, Object> data) implements PublisherData {

    @Override
    public Integer id() {
        return id;
    }

    @Override
    public String index() {
        return name;
    }

    @Override
    public PublisherData withIndex(final String index) {
        return new PublisherDataBuilder(this)
                .setName(name)
                .build();
    }

    @Override
    public PublisherDataBean toBean() {
        return new PublisherDataConverter().toBean(this);
    }

    @Override
    public PublisherDataBuilder toBuilder() {
        return new PublisherDataBuilder(this);
    }

    @Override
    public PublisherData withId(final Integer id) {
        return new PublisherDataRecord(
                id,
                name(),
                updateCounter(),
                data);
    }

    @Override
    public PublisherData withName(final String name) {
        return new PublisherDataRecord(
                id(),
                name,
                updateCounter(),
                data);
    }

    @Override
    public PublisherData withUpdateCounter(final Integer updateCounter) {
        return new PublisherDataRecord(
                id(),
                name(),
                updateCounter,
                data);
    }

    public PublisherData withData(final Map<Object, Object> data) {
        return new PublisherDataRecord(
            id(),
            name(),
            updateCounter(),
            data);
    }

    @Override
    public int compareTo(final PublisherData publisherData) {
        int c;
        c = CompareUtil.compare(this.id, publisherData.id());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.name, publisherData.name());
        if (c != 0) {
            return c;
        }
        c = CompareUtil.compare(this.updateCounter, publisherData.updateCounter());
        if (c != 0) {
            return c;
        }
        return 0;
    }

}
