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

import org.cesecore.repository.dto.Dto;

import java.util.Map;

public interface PublisherData extends Dto<Integer>, Comparable<PublisherData> {

    Integer id();
    String name();
    Integer updateCounter();
    Map<Object, Object> data();

    PublisherDataBean toBean();
    PublisherDataBuilder toBuilder();
    PublisherData withId(final Integer id);
    PublisherData withName(final String name);
    PublisherData withUpdateCounter(final Integer updateCounter);
    PublisherData withData(final Map<Object, Object> data);

}
