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
import org.cesecore.repository.util.XmlUtil;
</#if>
import org.cesecore.repository.dto.Converter;

public final class ${name?cap_first}Converter implements Converter<${name?cap_first}, ${name?cap_first}Bean> {

    public ${name?cap_first}Bean toBean(${name?cap_first} dto) {
        if (dto == null) {
            return null;
        }
        else {
            final var bean = new ${name?cap_first}Bean();
<#list fields as field>
    <#if field.javaEnum??>
            bean.set${field.javaName?cap_first}(dto.${field.javaName}() == null ? null : dto.${field.javaName}().get());
    <#else>
            bean.set${field.javaName?cap_first}(dto.${field.javaName}());
    </#if>
</#list>
<#if xmlName??>
            bean.set${xmlName?cap_first}(XmlUtil.toXml(dto.${xmlName}()));
</#if>
            return bean;
        }
    }

    public ${name?cap_first} toDto(${name?cap_first}Bean bean) {
        if (bean == null) {
            return null;
        }
        else {
<#if xmlName??>
    <#list fields as field>
<#if field.javaEnum??>
            <#if field?is_first>return new ${name?cap_first}Record(<#else>                   </#if>${field.javaEnum}.valueOf(bean.get${field.javaName?cap_first}()),
<#else>
            <#if field?is_first>return new ${name?cap_first}Record(<#else>                   </#if>bean.get${field.javaName?cap_first}(),
</#if>
    </#list>
                               Collections.unmodifiableMap(XmlUtil.fromXml(bean.get${xmlName?cap_first}())));
<#else>
    <#list fields as field>
        <#if field.javaEnum??>
        <#if field?is_first>return new ${name?cap_first}Record(<#else>                   </#if>${field.javaEnum}.valueOf(bean.get${field.javaName?cap_first}())<#if field?is_last>);<#else>,</#if>
        <#else>
        <#if field?is_first>return new ${name?cap_first}Record(<#else>                   </#if>bean.get${field.javaName?cap_first}()<#if field?is_last>);<#else>,</#if>
        </#if>
    </#list>
</#if>
        }
    }

}
