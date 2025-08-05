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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class PublisherDataBuilder {

    private Integer id;
    private String name;
    private Integer updateCounter;
    private Map<Object, Object> data;

    public PublisherDataBuilder() {
    }

    public PublisherDataBuilder(PublisherData publisherData) {
        setId(publisherData.id());
        setName(publisherData.name());
        setUpdateCounter(publisherData.updateCounter());
        setData(publisherData.data());
    }

    public PublisherDataBuilder setId(final Integer id) {
        this.id = id;
        return this;
    }

    public PublisherDataBuilder setName(final String name) {
        this.name = name;
        return this;
    }

    public PublisherDataBuilder setUpdateCounter(final Integer updateCounter) {
        this.updateCounter = updateCounter;
        return this;
    }

    public PublisherDataBuilder setData(final Map<Object, Object> data) {
        this.data = data;
        return this;
    }

    public PublisherData build() {
        return new PublisherDataRecord(id,
                           name,
                           updateCounter,
                           Collections.unmodifiableMap(data == null ? new HashMap<Object, Object>() : data));

    }
}
