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
package org.ejbca.util;

import java.util.Locale;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Translates field types from EndEntityProfile to subject DN field names
 * and human-readable names.
 * 
 * @version $Id$
 */
public final class DNFieldDescriber {

    private final int fieldType;
    private final String name, defaultValue;
    
    public DNFieldDescriber(int fieldType, EndEntityProfile eeprofile) {
        this.fieldType = fieldType;
        this.name = fieldTypeToString(fieldType).toLowerCase(Locale.ROOT);
        this.defaultValue = eeprofile.getValue(fieldType, 0).trim();
    }
    
    private String fieldTypeToString(int fieldType) {
        return DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldType), DNFieldExtractor.TYPE_SUBJECTDN).replaceAll("=", "");
    }
    
    public String getName() {
        return name;
    }
    
    public String getHumanReadableName() {
        if (name.equalsIgnoreCase("cn")) { return "Name"; }
        if (name.equalsIgnoreCase("o")) { return "Organization"; }
        if (name.equalsIgnoreCase("c")) { return "Country"; }
        else { return DnComponents.getLanguageConstantFromProfileId(fieldType).replaceAll("DN_PKIX_", "").toLowerCase(Locale.ROOT); }
    }
    
    public String getDescription() {
        return getHumanReadableName()+" ("+name.toUpperCase(Locale.ROOT)+")";
    }
    
    public String getDefaultValue() {
        return defaultValue;
    }
    
}
