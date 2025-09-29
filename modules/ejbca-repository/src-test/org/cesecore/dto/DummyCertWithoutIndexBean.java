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

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.cesecore.dto.DummyCertWithoutIndex;
import org.cesecore.dto.DummyCertWithoutIndexRecord;
import org.cesecore.util.XmlUtil;
import org.ejbca.dto.EntityManagerBean;

import java.util.Collections;
import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "DummyCertWithoutIndex")
public final class DummyCertWithoutIndexBean implements Serializable, EntityManagerBean<DummyCertWithoutIndex> {

    private Long id;
    private String name;
    private String data;
    private Integer rowVersion;
    private String rowProtection;

    public DummyCertWithoutIndexBean() {
        rowVersion = 0;
    }

    @Id
    public Long getId() {
       return this.id;
    }

    public void setId(Long id) {
       this.id = id;
    }

    public String getName() {
       return this.name;
    }

    public void setName(String name) {
       this.name = name;
    }

    public String getData() {
       return data;
    }

    public void setData(String data) {
       this.data = data;
    }

    public int getRowVersion() {
        return this.rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    public String getRowProtection() {
        return this.rowProtection;
    }

    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    @Override
    public DummyCertWithoutIndex toDto() {
        return new DummyCertWithoutIndexRecord(
                    getId(),
                    getName(),
                    Collections.unmodifiableMap(XmlUtil.fromXml(getData())));
    }

    @Override
    public void init(DummyCertWithoutIndex dto) {
        setId(dto.id());
        setName(dto.name());
        setData(XmlUtil.toXml(dto.data()));
    }

    @Transient
    @Override
    public int getProtectVersion() {
        return 1;
    }

    @Transient
    @Override
    public String getProtectString(final int version) {
        return null;
    }

    @PrePersist
    @PreUpdate
    protected void protectData() {
    }

    @PostLoad
    protected void verifyData() {
    }

    @Override
    public String toString() {
       StringBuilder stringBuilder = new StringBuilder();
       stringBuilder.append("id: " + id + "\n");
       stringBuilder.append("name: " + name + "\n");
       stringBuilder.append("data: \n");
       stringBuilder.append(data);
       stringBuilder.append("rowVersion: " + rowVersion + "\n");
       stringBuilder.append("rowProtection: " + rowProtection + "\n");
       return stringBuilder.toString();
    }

    @Override
    public boolean equals(Object o) {
       if (this == o) {
          return true;
       }
       if (o == null || getClass() != o.getClass()) {
          return false;
       }
       DummyCertWithoutIndexBean dummyCertWithoutIndexBean = (DummyCertWithoutIndexBean) o;
       return
          Objects.equals(id, dummyCertWithoutIndexBean.id) &&
          Objects.equals(name, dummyCertWithoutIndexBean.name) &&
          Objects.equals(data, dummyCertWithoutIndexBean.data) &&
          Objects.equals(rowVersion, dummyCertWithoutIndexBean.rowVersion) &&
          Objects.equals(rowProtection, dummyCertWithoutIndexBean.rowProtection);
    }

    @Override
    public int hashCode() {
       return Objects.hash(
                 id,
                 name,
                 data,
                 rowVersion,
                 rowProtection);
    }

}
