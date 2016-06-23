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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    //private static final Logger log = Logger.getLogger(SubjectDn.class);

    public static final List<String> COMPONENTS = Arrays.asList(
            DnComponents.DNEMAILADDRESS,
            DnComponents.DNQUALIFIER,
            DnComponents.UID,
            DnComponents.COMMONNAME,
            DnComponents.DNSERIALNUMBER,
            DnComponents.GIVENNAME,
            DnComponents.INITIALS,
            DnComponents.SURNAME,
            DnComponents.TITLE,
            DnComponents.ORGANIZATIONALUNIT,
            DnComponents.ORGANIZATION,
            DnComponents.LOCALITY,
            DnComponents.STATEORPROVINCE,
            DnComponents.DOMAINCOMPONENT,
            DnComponents.COUNTRY,
            DnComponents.UNSTRUCTUREDADDRESS,
            DnComponents.UNSTRUCTUREDNAME,
            DnComponents.POSTALCODE,
            DnComponents.BUSINESSCATEGORY,
            DnComponents.POSTALADDRESS,
            DnComponents.TELEPHONENUMBER,
            DnComponents.PSEUDONYM,
            DnComponents.STREETADDRESS,
            DnComponents.NAME
            );
    
    private final Collection<EndEntityProfile.FieldInstance> fieldInstances = new ArrayList<>();
    private final Map<String, Map<Integer, EndEntityProfile.FieldInstance>> fieldInstancesMap = new HashMap<>();
    private String value;

    public SubjectDn(final EndEntityProfile endEntityProfile) {
        this(endEntityProfile, null);
    }

    public SubjectDn(final EndEntityProfile endEntityProfile, final String subjectDistinguishedName) {
        DNFieldExtractor dnFieldExtractor = null;
        if (subjectDistinguishedName!=null) {
            dnFieldExtractor = new DNFieldExtractor(subjectDistinguishedName, DNFieldExtractor.TYPE_SUBJECTDN);
        }
        for (final String key : COMPONENTS) {
            final Field field = endEntityProfile.new Field(key);
            fieldInstancesMap.put(key, new HashMap<Integer, EndEntityProfile.FieldInstance>());
            for (final EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                if (dnFieldExtractor!=null) {
                    fieldInstance.setValue(dnFieldExtractor.getField(DnComponents.profileIdToDnId(fieldInstance.getProfileId()), fieldInstance.getNumber()));
                }
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
                nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart);
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
