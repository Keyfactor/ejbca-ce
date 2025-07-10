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

import org.cesecore.repository.dto.Converter;
import org.cesecore.repository.util.XmlUtil;

public final class DummyCertConverter implements Converter<DummyCert, DummyCertBean> {

    public DummyCertBean toBean(DummyCert dto) {
        if (dto == null) {
            return null;
        }
        else {
            final var bean = new DummyCertBean();
            bean.setId(dto.id());
            bean.setName(dto.name());
            bean.setData(XmlUtil.toXml(dto.data()));
            return bean;
        }
    }

    public DummyCert toDto(DummyCertBean bean) {
        if (bean == null) {
            return null;
        }
        else {
            return new DummyCertRecord(bean.getId(),
                               bean.getName(),
                               Collections.unmodifiableMap(XmlUtil.fromXml(bean.getData())));
        }
    }

}
