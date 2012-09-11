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
    
    /** Index in fielddata array */
    private final int index;
    /** EndEntityProfile.FIELDTYPE from fielddata arrays */
    private final int fieldType;
    /** DN codes, e.g. CN, C, O */
    private final String name;
    private final String defaultValue;
    /** DNFieldExtractor.TYPE_ constants. E.g. subjectdn or altname */
    private final int dnAltType;
    
    public DNFieldDescriber(int index, int fieldType, EndEntityProfile eeprofile, int dnAltType) {
        this.index = index;
        this.fieldType = fieldType;
        this.name = fieldTypeToString(fieldType, dnAltType);
        this.defaultValue = eeprofile.getValue(fieldType, 0).trim();
        this.dnAltType = dnAltType;
    }
    
    private static String fieldTypeToString(int fieldType, int dnAltType) {
        String name = DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldType), dnAltType);
        return (name != null ? name.replaceAll("=", "").toLowerCase(Locale.ROOT) : null);
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
    
    public String getHumanReadableName() {
        String langconst = DnComponents.getLanguageConstantFromProfileId(fieldType);
        if (langconst.equals("DN_PKIX_COMMONNAME")) { return "Name"; }
        if (langconst.equals("DN_PKIX_ORGANIZATION")) { return "Organization"; }
        if (langconst.equals("DN_PKIX_COUNTRY")) { return "Country"; } 
        if (langconst.equals("ALT_PKIX_DNSNAME")) { return "DNS Name"; }
        if (langconst.equals("ALT_PKIX_IPADDRESS")) { return "IP Address"; }
        else { return langconst.replaceAll("DN_PKIX_", "").replaceAll("ALT_PKIX_", "").toLowerCase(Locale.ROOT); }
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
