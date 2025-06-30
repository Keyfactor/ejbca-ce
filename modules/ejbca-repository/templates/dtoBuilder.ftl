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

<#if xmlName??>
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
</#if>

public class ${name?cap_first}Builder {

<#list fields as field>
<#if field.javaEnum??>
    private ${field.javaEnum} ${field.javaName};
<#else>
    private ${field.javaType} ${field.javaName};
</#if>
</#list>
<#if xmlName??>
    private Map<Object, Object> ${xmlName};
</#if>

    public ${name?cap_first}Builder() {
    }

    public ${name?cap_first}Builder(${name?cap_first} ${name}) {
<#list fields as field>
        set${field.javaName?cap_first}(${name}.${field.javaName}());
</#list>
<#if xmlName??>
        set${xmlName?cap_first}(${name}.${xmlName}());
</#if>
    }

<#list fields as field>
<#if field.javaEnum??>
    public ${name?cap_first}Builder set${field.javaName?cap_first}(final ${field.javaEnum} ${field.javaName}) {
<#else>
    public ${name?cap_first}Builder set${field.javaName?cap_first}(final ${field.javaType} ${field.javaName}) {
</#if>
        this.${field.javaName} = ${field.javaName};
        return this;
    }

</#list>
<#if xmlName??>
    public ${name?cap_first}Builder set${xmlName?cap_first}(final Map<Object, Object> ${xmlName}) {
        this.${xmlName} = ${xmlName};
        return this;
    }

</#if>
    public ${name?cap_first} build() {
<#if xmlName??>
    <#list fields as field>
        <#if field?is_first>return new ${name?cap_first}Record(<#else>                   </#if>${field.javaName},
    </#list>
                           Collections.unmodifiableMap(${xmlName} == null ? new HashMap<Object, Object>() : ${xmlName}));
<#else>
    <#list fields as field>
        <#if field?is_first>return new ${name?cap_first}Record(<#else>                   </#if>${field.javaName}<#if field?is_last>);<#else>,</#if>
    </#list>
</#if>

    }
}
