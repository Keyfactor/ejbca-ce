/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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
    
    /** Index in dn fields array */
    private final int index;
    private final int[] fielddata;
    private final boolean fieldModifiable, fieldRequired, fieldUse;
    /** DN codes, e.g. CN, C, O */
    private final String name;
    private final String defaultValue;
    
    private final Map<String,Boolean> allowedValuesMap; // maps to true. Used from .jsp
    private final List<String> allowedValuesList;
    
    public DNFieldDescriber(int index, int[] fielddata, EndEntityProfile eeprofile, int dnAltType) {
        this.index = index;
        this.fielddata = fielddata;
        final int fieldType = fielddata[EndEntityProfile.FIELDTYPE];
        final int fieldNumber = fielddata[EndEntityProfile.NUMBER];
        this.fieldModifiable = eeprofile.isModifyable(fieldType, fieldNumber);
        this.fieldRequired = eeprofile.isRequired(fieldType, fieldNumber);
        this.fieldUse = eeprofile.getUse(fieldType, fieldNumber);
        this.name = fieldTypeToString(fieldType, dnAltType);
        
        String value = eeprofile.getValue(fieldType, fieldNumber);
        if (fieldModifiable) {
            // A text entry is used in this case
            this.defaultValue = value.trim();
            this.allowedValuesMap = null;
            this.allowedValuesList = null;
        } else {
            // A select field with restricted choices
            this.defaultValue = null;
            this.allowedValuesMap = new HashMap<String,Boolean>();
            this.allowedValuesList = new ArrayList<String>();
            
            if (!eeprofile.isRequired(fieldType, fieldNumber)) {
                allowedValuesMap.put("", true);
                allowedValuesList.add("");
            }
            
            for (String allowed : value.split(";")) {
                allowed = allowed.trim();
                allowedValuesMap.put(allowed, true);
                allowedValuesList.add(allowed);
            }
        }
    }
    
    private static String fieldTypeToString(int fieldType, int dnAltType) {
        String name = DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldType), dnAltType);
        return (name != null ? name.replaceAll("=", "").toLowerCase(Locale.ROOT) : null);
    }
    
    public boolean isModifiable() {
        return fieldModifiable;
    }
    
    public boolean isRequired() {
        return fieldRequired;
    }
    
    public boolean isUse() {
        return fieldUse;
    }
    
    public String getRequiredMarker() {
        return fieldRequired ? " *" : "";
    }
    
    public Map<String,Boolean> getAllowedValuesMap() {
        return allowedValuesMap;
    }
    
    public List<String> getAllowedValuesList() {
        return allowedValuesList;
    }
    
    public String getName() {
        return name;
    }
    
    public String getId() {
        return String.valueOf(index);
    }
    
    public static int extractIndexFromId(String id) {
        return Integer.parseInt(id.split(":")[0]);
    }
    
    public static String extractSubjectDnNameFromId(EndEntityProfile eeprofile, String id) {
        int i = extractIndexFromId(id);
        return fieldTypeToString(eeprofile.getSubjectDNFieldsInOrder(i)[EndEntityProfile.FIELDTYPE], DNFieldExtractor.TYPE_SUBJECTDN);
    }
    
    public static String extractSubjectAltNameFromId(EndEntityProfile eeprofile, String id) {
        int i = extractIndexFromId(id);
        return fieldTypeToString(eeprofile.getSubjectAltNameFieldsInOrder(i)[EndEntityProfile.FIELDTYPE], DNFieldExtractor.TYPE_SUBJECTALTNAME);
    }
    
    public static String extractSubjectDirAttrFromId(EndEntityProfile eeprofile, String id) {
        int i = extractIndexFromId(id);
        return fieldTypeToString(eeprofile.getSubjectDirAttrFieldsInOrder(i)[EndEntityProfile.FIELDTYPE], DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    }
    
    public String removePrefixes(String s, String... prefixes) {
        for (String prefix : prefixes) {
            if (s.startsWith(prefix)) s = s.substring(prefix.length());
        }
        return s;
    }
    
    public String getHumanReadableName() {
        String langconst = DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE]);
        if (langconst.equals("DN_PKIX_COMMONNAME")) { return "Name"; }
        if (langconst.equals("DN_PKIX_ORGANIZATION")) { return "Organization"; }
        if (langconst.equals("DN_PKIX_COUNTRY")) { return "Country"; }
        if (langconst.equals("DN_PKIX_EMAILADDRESS")) { return "E-mail"; }
        if (langconst.equals("ALT_PKIX_DNSNAME")) { return "DNS Name"; }
        if (langconst.equals("ALT_PKIX_IPADDRESS")) { return "IP Address"; }
        if (langconst.equals("ALT_PKIX_RFC822NAME")) { return "RFC822 Name (e-mail)"; }
        else { return removePrefixes(langconst, "DN_PKIX_", "ALT_PKIX_", "DN_", "ALT_", "SDA_").toLowerCase(Locale.ROOT); }
    }
    
    public String getDescription() {
        if (name != null) {
            return getHumanReadableName()+" ("+name.toUpperCase(Locale.ROOT)+")";
        } else {
            return getHumanReadableName();
        }
    }
    
    public String getDefaultValue() {
        return defaultValue;
    }
    
}
