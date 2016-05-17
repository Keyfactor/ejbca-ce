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
 * Contains SubjectDN attributes
 * @version $Id$
 *
 */
public class SubjectDn {

    private static final Logger log = Logger.getLogger(SubjectDn.class);
    private Collection<EndEntityProfile.FieldInstance> fieldInstances;
    private Map<String, EndEntityProfile.FieldInstance> fieldInstancesMap;
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
        fieldInstances = new ArrayList<>(COMPONENTS.size());
        fieldInstancesMap = new HashMap<String, EndEntityProfile.FieldInstance>(COMPONENTS.size());
        for (String key : COMPONENTS) {
            Field field = endEntityProfile.new Field(key);
            for (EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                fieldInstancesMap.put(key, fieldInstance);
            }
        }
        
        update();
    }
    
    public Collection<EndEntityProfile.FieldInstance> getFieldInstances() {
        return fieldInstances;
    }
    
    private void setFieldInstances(){
        fieldInstances.clear();
        fieldInstances.addAll(fieldInstancesMap.values());
    }
    
    public Map<String, EndEntityProfile.FieldInstance> getFieldInstancesMap() {
        return fieldInstancesMap;
    }

    /**
     * Set the field instances map. Make sure you invoke update() after you have been using this method to change some entries.
     * This method is useful when SubjectDN values should be set from CSR.
     * @param fieldInstancesMap
     * @see SubjectDn.update()
     * @see EnrollMakeNewRequestBean.initCertificateData()
     */
    public void setFieldInstancesMap(Map<String, EndEntityProfile.FieldInstance> fieldInstancesMap) {
        this.fieldInstancesMap = fieldInstancesMap;
        
    }

    /**
     * Updates the field instances arraylist and string value.
     */
    public void update(){
        setFieldInstances();
        
        StringBuilder subjectDn = new StringBuilder();
        for(EndEntityProfile.FieldInstance fieldInstance : fieldInstances){
            if(!fieldInstance.getValue().isEmpty()){
                int dnId = DnComponents.profileIdToDnId(fieldInstance.getProfileId());
                String nameValueDnPart = DNFieldExtractor.getFieldComponent(dnId, DNFieldExtractor.TYPE_SUBJECTDN) + fieldInstance.getValue().trim();
                //TODO nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart);
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
            update();
        }
        return value;
    }

    @SuppressWarnings("unused")
    private void setValue(String value) {
        this.value = value;
    }

}
