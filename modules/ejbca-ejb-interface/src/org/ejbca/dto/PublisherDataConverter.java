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

import org.cesecore.repository.dto.Converter;
import org.cesecore.repository.util.XmlUtil;

import java.util.Collections;

public final class PublisherDataConverter implements Converter<PublisherData, PublisherDataBean> {

    public PublisherDataBean toBean(PublisherData dto) {
        if (dto == null) {
            return null;
        }
        else {
            final var bean = new PublisherDataBean();
            bean.setId(dto.id());
            bean.setName(dto.name());
            bean.setUpdateCounter(dto.updateCounter());
            bean.setData(XmlUtil.toXml(dto.data()));
            return bean;
        }
    }

    public PublisherData toDto(PublisherDataBean bean) {
        if (bean == null) {
            return null;
        }
        else {
            return new PublisherDataRecord(bean.getId(),
                               bean.getName(),
                               bean.getUpdateCounter(),
                               Collections.unmodifiableMap(XmlUtil.fromXml(bean.getData())));
        }
    }

}
