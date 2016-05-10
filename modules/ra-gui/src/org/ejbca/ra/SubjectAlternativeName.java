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
 * Contains Subject Alternative Name attributes
 * @version $Id$
 *
 */
public class SubjectAlternativeName {
    private List<EndEntityProfile.FieldInstance> fieldInstances;
    public final static List<String> COMPONENTS;
    static{
        COMPONENTS = new ArrayList<>();
        COMPONENTS.add(DnComponents.RFC822NAME);
        COMPONENTS.add(DnComponents.DNSNAME);
        COMPONENTS.add(DnComponents.IPADDRESS);
        COMPONENTS.add(DnComponents.UNIFORMRESOURCEID);
        COMPONENTS.add(DnComponents.DIRECTORYNAME);
        COMPONENTS.add(DnComponents.UPN);
        COMPONENTS.add(DnComponents.GUID);
        COMPONENTS.add(DnComponents.KRB5PRINCIPAL);
        COMPONENTS.add(DnComponents.PERMANENTIDENTIFIER);
        // Below are altNames that are not implemented yet
        COMPONENTS.add(DnComponents.OTHERNAME);
        COMPONENTS.add(DnComponents.X400ADDRESS);
        COMPONENTS.add(DnComponents.EDIPARTYNAME);
        COMPONENTS.add(DnComponents.REGISTEREDID);
    }
    
    private String value;

    public SubjectAlternativeName(EndEntityProfile endEntityProfile) {
        fieldInstances = new ArrayList<EndEntityProfile.FieldInstance>();
        for (String key : COMPONENTS) {
            Field field = endEntityProfile.new Field(key);
            for (EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                fieldInstances.add(fieldInstance);
            }
        }
    }
    
    public void updateValue(){
        StringBuilder subjectAlternativeName = new StringBuilder();
        for(EndEntityProfile.FieldInstance fieldInstance : fieldInstances){
            if(!fieldInstance.getValue().isEmpty()){
                int dnId = DnComponents.profileIdToDnId(fieldInstance.getProfileId());
                String nameValueDnPart = DNFieldExtractor.getFieldComponent(dnId, DNFieldExtractor.TYPE_SUBJECTALTNAME) + fieldInstance.getValue().trim();
                //TODO nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart);
                if(subjectAlternativeName.length() != 0){
                    subjectAlternativeName.append(", ");
                }
                subjectAlternativeName.append(nameValueDnPart);
            }
        }
        value = subjectAlternativeName.toString();
    }

    public List<EndEntityProfile.FieldInstance> getFieldInstances() {
        return fieldInstances;
    }

    public void setFieldInstances(List<EndEntityProfile.FieldInstance> fieldInstances) {
        this.fieldInstances = fieldInstances;
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
