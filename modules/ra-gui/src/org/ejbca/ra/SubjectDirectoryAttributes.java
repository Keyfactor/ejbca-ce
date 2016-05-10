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
import java.util.List;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile.Field;

/**
 * Contains Subject Directory attributes
 * @version $Id$
 *
 */
public class SubjectDirectoryAttributes {
    private List<EndEntityProfile.FieldInstance> fieldInstances;
    public final static List<String> COMPONENTS;
    static{
        COMPONENTS = new ArrayList<>();
        COMPONENTS.add(DnComponents.DATEOFBIRTH);
        COMPONENTS.add(DnComponents.PLACEOFBIRTH);
        COMPONENTS.add(DnComponents.GENDER);
        COMPONENTS.add(DnComponents.COUNTRYOFCITIZENSHIP);
        COMPONENTS.add(DnComponents.COUNTRYOFRESIDENCE);
    }
    
    private String value;

    public SubjectDirectoryAttributes(EndEntityProfile endEntityProfile) {
        fieldInstances = new ArrayList<EndEntityProfile.FieldInstance>();
        for (String key : COMPONENTS) {
            Field field = endEntityProfile.new Field(key);
            for (EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                fieldInstances.add(fieldInstance);
            }
        }
    }

    public List<EndEntityProfile.FieldInstance> getFieldInstances() {
        return fieldInstances;
    }

    public void setFieldInstances(List<EndEntityProfile.FieldInstance> fieldInstances) {
        this.fieldInstances = fieldInstances;
    }

    public void updateValue(){
        StringBuilder subjectDn = new StringBuilder();
        for(EndEntityProfile.FieldInstance fieldInstance : fieldInstances){
            if(!fieldInstance.getValue().isEmpty()){
                int dnId = DnComponents.profileIdToDnId(fieldInstance.getProfileId());
                String nameValueDnPart = DNFieldExtractor.getFieldComponent(dnId, DNFieldExtractor.TYPE_SUBJECTDIRATTR) + fieldInstance.getValue().trim();
                //nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart); TODO
                if(subjectDn.length() != 0){
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
        return getValue();
    }

    /**
     * @return the value
     */
    public String getValue() {
        if(value == null){
            updateValue();
        }
        return value;
    }

    @SuppressWarnings("unused")
    private void setValue(String value) {
        this.value = value;
    }
}
