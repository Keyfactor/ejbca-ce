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
package org.ejbca.ra;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile.Field;

/**
 * Represents two "interfaces": list (needed for JSF) and map interface
 * for the subject DN fields of the specified end entity profile.
 * 
 * @version $Id$
 *
 */
public class SubjectDn {

    private static final Logger log = Logger.getLogger(SubjectDn.class);
    private Collection<EndEntityProfile.FieldInstance> fieldInstances;
    private Map<String, Map<Integer, EndEntityProfile.FieldInstance>> fieldInstancesMap;
    public final static List<String> COMPONENTS;
    static{
        COMPONENTS = new ArrayList<>();
        COMPONENTS.add(DnComponents.DNEMAILADDRESS);
        COMPONENTS.add(DnComponents.DNQUALIFIER);
        COMPONENTS.add(DnComponents.UID);
        COMPONENTS.add(DnComponents.COMMONNAME);
        COMPONENTS.add(DnComponents.DNSERIALNUMBER);
        COMPONENTS.add(DnComponents.GIVENNAME);
        COMPONENTS.add(DnComponents.INITIALS);
        COMPONENTS.add(DnComponents.SURNAME);
        COMPONENTS.add(DnComponents.TITLE);
        COMPONENTS.add(DnComponents.ORGANIZATIONALUNIT);
        COMPONENTS.add(DnComponents.ORGANIZATION);
        COMPONENTS.add(DnComponents.LOCALITY);
        COMPONENTS.add(DnComponents.STATEORPROVINCE);
        COMPONENTS.add(DnComponents.DOMAINCOMPONENT);
        COMPONENTS.add(DnComponents.COUNTRY);
        COMPONENTS.add(DnComponents.UNSTRUCTUREDADDRESS);
        COMPONENTS.add(DnComponents.UNSTRUCTUREDNAME);
        COMPONENTS.add(DnComponents.POSTALCODE);
        COMPONENTS.add(DnComponents.BUSINESSCATEGORY);
        COMPONENTS.add(DnComponents.POSTALADDRESS);
        COMPONENTS.add(DnComponents.TELEPHONENUMBER);
        COMPONENTS.add(DnComponents.PSEUDONYM);
        COMPONENTS.add(DnComponents.STREETADDRESS);
        COMPONENTS.add(DnComponents.NAME);
    }
    
    private String value;

    public SubjectDn(EndEntityProfile endEntityProfile) {
        fieldInstances = new ArrayList<EndEntityProfile.FieldInstance>();
        fieldInstancesMap = new HashMap<String, Map<Integer, EndEntityProfile.FieldInstance>>();
        for (String key : COMPONENTS) {
            Field field = endEntityProfile.new Field(key);
            fieldInstancesMap.put(key, new HashMap<Integer, EndEntityProfile.FieldInstance>());
            for (EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                fieldInstances.add(fieldInstance);
                fieldInstancesMap.get(key).put(fieldInstance.getNumber(), fieldInstance);
            }
        }
    }
    
    /**
     * @return the list interface for the subject DN fields
     */
    public Collection<EndEntityProfile.FieldInstance> getFieldInstances() {
        return fieldInstances;
    }

    /**
     * @return the map interface for the subject DN fields.
     */
    public Map<String, Map<Integer, EndEntityProfile.FieldInstance>> getFieldInstancesMap() {
        return fieldInstancesMap;
    }

    /**
     * Updates the the result string value of Subject DN.
     */
    public void update() {
        StringBuilder subjectDn = new StringBuilder();
        for (EndEntityProfile.FieldInstance fieldInstance : fieldInstances) {
            if (!fieldInstance.getValue().isEmpty()) {
                int dnId = DnComponents.profileIdToDnId(fieldInstance.getProfileId());
                String nameValueDnPart = DNFieldExtractor.getFieldComponent(dnId, DNFieldExtractor.TYPE_SUBJECTDN) + fieldInstance.getValue().trim();
                //TODO nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart);
                if (subjectDn.length() != 0) {
                    subjectDn.append(", ");
                }
                subjectDn.append(nameValueDnPart);
            }
        }
        //TODO DNEMAILADDRESS copying from UserAccountData
        value = subjectDn.toString();
    }

    @Override
    public String toString() {
        return getUpdatedValue();
    }

    /**
     * Returns non-updated string value of subject DN.
     * @return subject DN as String
     * @see SubjectDn.update()
     */
    public String getValue() {
        if(value == null){
            update();
        }
        return value;
    }
    
    /**
     * Updates the string value of subject DN and then returns it.
     * @return subject DN as String
     */
    public String getUpdatedValue() {
        update();
        return value;
    }

    @SuppressWarnings("unused")
    private void setValue(String value) {
        this.value = value;
    }

}
