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

import org.cesecore.repository.util.CompareUtil;
<#if xmlName??>
import java.util.Map;

public record ${name?cap_first}Record(
<#list fields as field>
    <#if field.javaEnum??>
                       ${field.javaEnum} ${field.javaName},
    <#else>
                       ${field.javaType} ${field.javaName},
    </#if>
</#list>
                       Map<Object, Object> ${xmlName}) implements ${name?cap_first} {
<#else>

public record ${name?cap_first}Record(
<#list fields as field>
    <#if field.javaEnum??>
                       ${field.javaEnum} ${field.javaName}<#if field?is_last>) implements ${name?cap_first} {<#else>,</#if>
    <#else>
                       ${field.javaType} ${field.javaName}<#if field?is_last>) implements ${name?cap_first} {<#else>,</#if>
    </#if>
</#list>
</#if>

    @Override
    public ${idType} id() {
        return ${idName};
    }

    @Override
    public String index() {
<#if indexName??>
        return ${indexName};
<#else>
        return null;
</#if>
    }

    @Override
    public ${name?cap_first} withIndex(final String index) {
<#if indexName??>
        return new ${name?cap_first}Builder(this)
                .set${indexName?cap_first}(${indexName})
                .build();
<#else>
        return this;
</#if>
    }

    @Override
    public ${name?cap_first}Bean toBean() {
        return new ${name?cap_first}Converter().toBean(this);
    }

    @Override
    public ${name?cap_first}Builder toBuilder() {
        return new ${name?cap_first}Builder(this);
    }

<#if idName != "id">
    @Override
    public ${name?cap_first} withId(final ${idType} id) {
        return with${idName?cap_first}(id);
    }

</#if>
<#list fields as field>
    @Override
    <#if field.javaEnum??>
    public ${name?cap_first} with${field.javaName?cap_first}(final ${field.javaEnum} ${field.javaName}) {
    <#else>
    public ${name?cap_first} with${field.javaName?cap_first}(final ${field.javaType} ${field.javaName}) {
    </#if>
        return new ${name?cap_first}Record(
<#if xmlName??>
<#list fields as f>
    <#if field.javaName == f.javaName>
                ${f.javaName},
    <#else>
                ${f.javaName}(),
    </#if>
</#list>
                ${xmlName});
<#else>
<#list fields as f>
    <#if field.javaName == f.javaName>
                ${f.javaName}<#if f?is_last>);<#else>,</#if>
    <#else>
                ${f.javaName}()<#if f?is_last>);<#else>,</#if>
    </#if>
</#list>
</#if>
    }

</#list>
<#if xmlName??>
    public ${name?cap_first} with${xmlName?cap_first}(final Map<Object, Object> ${xmlName}) {
        return new ${name?cap_first}Record(
<#list fields as field>
            ${field.javaName}(),
</#list>
            ${xmlName});
    }

</#if>
    @Override
    public int compareTo(final ${name?cap_first} ${name}) {
        int c;
<#list fields as field>
        c = CompareUtil.compare(this.${field.javaName}, ${name}.${field.javaName}());
        if (c != 0) {
            return c;
        }
</#list>
        return 0;
    }

}
