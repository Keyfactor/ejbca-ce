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

package ${packageName}.dto;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
<#if !test>
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedDataImpl;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.dto.${name?cap_first}Dto;
</#if>
import org.ejbca.dto.EntityManagerBean;
<#if xmlName??>
import org.cesecore.util.XmlUtil;
import java.util.Collections;
</#if>
import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "${name?cap_first}")
public final class ${name?cap_first} implements Serializable, EntityManagerBean<${name?cap_first}Dto> {
<#if !test>

    private static ProtectedDataImpl protectedDataImpl;

    static {
        protectedDataImpl = ProtectedData.initializeProtectedDataImpl("${name?cap_first}");
    }

    public static ProtectedDataImpl getProtectedDataImpl() {
        return protectedDataImpl;
    }

    public static void setProtectedDataImpl(final ProtectedDataImpl protectedDataImpl) {
        ${name?cap_first}.protectedDataImpl = protectedDataImpl;
    }
</#if>

<#list fields as field>
    private ${field.javaType} ${field.javaName};
</#list>
<#if xmlName??>
    private String ${xmlName};
</#if>
    private Integer rowVersion;
    private String rowProtection;

    public ${name?cap_first}() {
        rowVersion = 0;
    }

<#list fields as field>
    <#if field.javaName==idName>
    @Id
    </#if>
    public ${field.javaType} get${field.javaName?cap_first}() {
       return this.${field.javaName};
    }

    public void set${field.javaName?cap_first}(${field.javaType} ${field.javaName}) {
       this.${field.javaName} = ${field.javaName};
    }

</#list>
<#if xmlName??>
    public String get${xmlName?cap_first}() {
       return ${xmlName};
    }

    public void set${xmlName?cap_first}(String ${xmlName}) {
       this.${xmlName} = ${xmlName};
    }

</#if>
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
    public ${name?cap_first}Dto toDto() {
        return new ${name?cap_first}Dto(
<#list fields as field>
                    get${field.javaName?cap_first}(),
</#list>
<#if xmlName??>
                    Collections.unmodifiableMap(XmlUtil.fromXml(get${xmlName?cap_first}())));
</#if>
    }

    @Override
    public void init(${name?cap_first}Dto dto) {
<#list fields as field>
        set${field.javaName?cap_first}(dto.${field.javaName}());
</#list>
<#if xmlName??>
        setData(XmlUtil.toXml(dto.${xmlName}()));
</#if>
    }

    @Transient
    @Override
    public int getProtectVersion() {
        return 1;
    }

    @Transient
    @Override
    public String getProtectString(final int version) {
<#if test>
    return null;
<#else>
        ProtectionStringBuilder builder = new ProtectionStringBuilder();
    <#list fields as field>
        builder.append(get${field.javaName?cap_first}());
    </#list>
        return builder.toString();
</#if>
    }

<#if test>
    @PrePersist
    @PreUpdate
    protected void protectData() {
    }
<#else>
    @PrePersist
    @PreUpdate
    protected void protectData() throws DatabaseProtectionException {
        final var unProtectedData = getProtectString(getProtectVersion());
        final var protectedData = protectedDataImpl.getProtectedData(rowVersion, unProtectedData);
        if (protectedData != null) {
            setRowProtection(protectedData);
        }
    }
</#if>

<#if test>
    @PostLoad
    protected void verifyData() {
    }
<#else>
    @PostLoad
    protected void verifyData() throws DatabaseProtectionException {
        try {
            final var unProtectedData = getProtectString(getProtectVersion());
            protectedDataImpl.verifyData(unProtectedData, rowProtection, "${name?cap_first}", String.valueOf(${idName}));
        } catch (final DatabaseProtectionException e) {
            protectedDataImpl.onDataVerificationError(e);
        }
    }
</#if>

    @Override
    public String toString() {
       StringBuilder stringBuilder = new StringBuilder();
<#list fields as field>
       stringBuilder.append("${field.javaName}: " + ${field.javaName} + "\n");
</#list>
<#if xmlName??>
       stringBuilder.append("${xmlName}: \n");
       stringBuilder.append(${xmlName});
</#if>
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
       ${name?cap_first} ${name} = (${name?cap_first}) o;
       return
    <#list fields as field>
          Objects.equals(${field.javaName}, ${name}.${field.javaName}) &&
    </#list>
<#if xmlName??>
          Objects.equals(${xmlName}, ${name}.${xmlName}) &&
</#if>
          Objects.equals(rowVersion, ${name}.rowVersion) &&
          Objects.equals(rowProtection, ${name}.rowProtection);
    }

    @Override
    public int hashCode() {
       return Objects.hash(
    <#list fields as field>
                 ${field.javaName},
    </#list>
<#if xmlName??>
                 ${xmlName},
</#if>
                 rowVersion,
                 rowProtection);
    }

}
