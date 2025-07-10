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

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedDataImpl;
import org.cesecore.dbprotection.ProtectedDataIntegrityImpl;
import org.cesecore.dbprotection.ProtectionStringBuilder;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "PublisherData")
public final class PublisherDataBean implements Serializable, EntityManagerBean {

    private static ProtectedDataImpl protectedDataImpl;

    static {
        protectedDataImpl = new ProtectedDataIntegrityImpl();
        protectedDataImpl.setTableName("PublisherDataBean");
    }

    public static ProtectedDataImpl getProtectedDataImpl() {
        return protectedDataImpl;
    }

    public static void setProtectedDataImpl(final ProtectedDataImpl protectedDataImpl) {
        PublisherDataBean.protectedDataImpl = protectedDataImpl;
    }

    private Integer id;
    private String name;
    private Integer updateCounter;
    private String data;
    private Integer rowVersion;
    private String rowProtection;

    public PublisherDataBean() {
        rowVersion = 0;
    }

    @Id
    public Integer getId() {
       return this.id;
    }

    public void setId(Integer id) {
       this.id = id;
    }

    public String getName() {
       return this.name;
    }

    public void setName(String name) {
       this.name = name;
    }

    public Integer getUpdateCounter() {
       return this.updateCounter;
    }

    public void setUpdateCounter(Integer updateCounter) {
       this.updateCounter = updateCounter;
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

    @Transient
    @Override
    public int getProtectVersion() {
        return 1;
    }

    @Transient
    @Override
    public String getProtectString(final int version) {
        ProtectionStringBuilder builder = new ProtectionStringBuilder();
        builder.append(getId());
        builder.append(getName());
        builder.append(getUpdateCounter());
        builder.append(getData());
        return builder.toString();
    }

    @PrePersist
    @PreUpdate
    protected void protectData() throws DatabaseProtectionException {
        final var unProtectedData = getProtectString(getProtectVersion());
        final var protectedData = protectedDataImpl.getProtectedData(getProtectVersion(), unProtectedData);
        if (protectedData != null) {
            setRowProtection(protectedData);
        }
    }

    @PostLoad
    protected void verifyData() throws DatabaseProtectionException {
        try {
            final var unProtectedData = getProtectString(getProtectVersion());
            protectedDataImpl.verifyData(unProtectedData, rowProtection, "PublisherDataBean", String.valueOf(id));
        } catch (final DatabaseProtectionException e) {
            protectedDataImpl.onDataVerificationError(e);
        }
    }

    @Override
    public String toString() {
       StringBuilder stringBuilder = new StringBuilder();
       stringBuilder.append("id: " + id + "\n");
       stringBuilder.append("name: " + name + "\n");
       stringBuilder.append("updateCounter: " + updateCounter + "\n");
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
       PublisherDataBean publisherDataBean = (PublisherDataBean) o;
       return
          Objects.equals(id, publisherDataBean.id) &&
          Objects.equals(name, publisherDataBean.name) &&
          Objects.equals(updateCounter, publisherDataBean.updateCounter) &&
          Objects.equals(data, publisherDataBean.data) &&
          Objects.equals(rowVersion, publisherDataBean.rowVersion) &&
          Objects.equals(rowProtection, publisherDataBean.rowProtection);
    }

    @Override
    public int hashCode() {
       return Objects.hash(
                 id,
                 name,
                 updateCounter,
                 data,
                 rowVersion,
                 rowProtection);
    }

}
