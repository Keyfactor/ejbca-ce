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

    //private static final Logger log = Logger.getLogger(SubjectAlternativeName.class);

    private List<EndEntityProfile.FieldInstance> fieldInstances = new ArrayList<>();
    private String value;

    public SubjectAlternativeName(final EndEntityProfile endEntityProfile) {
        this(endEntityProfile, null);
    }

    public SubjectAlternativeName(final EndEntityProfile endEntityProfile, final String subjectAlternativeName) {
        DNFieldExtractor dnFieldExtractor = null;
        if (subjectAlternativeName!=null) {
            dnFieldExtractor = new DNFieldExtractor(subjectAlternativeName, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        }
        for (final String key : DnComponents.getAltNameFields()) {
            final Field field = endEntityProfile.new Field(key);
            for (final EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                if (dnFieldExtractor!=null) {
                    fieldInstance.setValue(dnFieldExtractor.getField(DnComponents.profileIdToDnId(fieldInstance.getProfileId()), fieldInstance.getNumber()));
                }
                fieldInstances.add(fieldInstance);
            }
        }
    }
    
    public void update(){
        StringBuilder subjectAlternativeName = new StringBuilder();
        for(EndEntityProfile.FieldInstance fieldInstance : fieldInstances){
            if(!fieldInstance.getValue().isEmpty()){
                int dnId = DnComponents.profileIdToDnId(fieldInstance.getProfileId());
                String nameValueDnPart = DNFieldExtractor.getFieldComponent(dnId, DNFieldExtractor.TYPE_SUBJECTALTNAME) + fieldInstance.getValue().trim();
                nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart);
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
            update();
        }
        return value;
    }
    
    public String getUpdatedValue() {
        update();
        return value;
    }

    @SuppressWarnings("unused")
    private void setValue(String value) {
        this.value = value;
    }
}
