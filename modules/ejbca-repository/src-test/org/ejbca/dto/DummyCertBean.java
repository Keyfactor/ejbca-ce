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

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "DummyCert")
public final class DummyCertBean implements Serializable, EntityManagerBean {

    private Long id;
    private String name;
    private String data;
    private Integer rowVersion;
    private String rowProtection;
    private boolean valid;

    public DummyCertBean() {
        rowVersion = 0;
        valid = true;
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

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
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
        if (!valid) {
            throw new IllegalStateException("Not valid entity");
        }
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
       DummyCertBean dummyCertBean = (DummyCertBean) o;
       return
          Objects.equals(id, dummyCertBean.id) &&
          Objects.equals(name, dummyCertBean.name) &&
          Objects.equals(data, dummyCertBean.data) &&
          Objects.equals(rowVersion, dummyCertBean.rowVersion) &&
          Objects.equals(rowProtection, dummyCertBean.rowProtection);
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
