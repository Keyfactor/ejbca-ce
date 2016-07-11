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
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
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
    
    private final Collection<EndEntityProfile.FieldInstance> fieldInstances = new ArrayList<>();
    private final Map<String, Map<Integer, EndEntityProfile.FieldInstance>> fieldInstancesMap = new HashMap<>();
    private String value;
    private X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
    private boolean ldapOrder = true;

    public SubjectDn(final EndEntityProfile endEntityProfile) {
        this(endEntityProfile, null);
    }

    public SubjectDn(final EndEntityProfile endEntityProfile, final String subjectDistinguishedName) {
        DNFieldExtractor dnFieldExtractor = null;
        if (subjectDistinguishedName!=null) {
            dnFieldExtractor = new DNFieldExtractor(subjectDistinguishedName, DNFieldExtractor.TYPE_SUBJECTDN);
        }
        for (final String key : DnComponents.getDnProfileFields()) {
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
        X500Name x500name = CertTools.stringToBcX500Name(subjectDn.toString(), nameStyle, ldapOrder);
        //TODO DNEMAILADDRESS copying from UserAccountData
        value = x500name.toString();
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

    /**
     * @return the ldapOrder
     */
    public boolean isLdapOrder() {
        return ldapOrder;
    }

    /**
     * @param ldapOrder the ldapOrder to set
     */
    public void setLdapOrder(boolean ldapOrder) {
        this.ldapOrder = ldapOrder;
    }

    /**
     * @return the nameStyle
     */
    public X500NameStyle getNameStyle() {
        return nameStyle;
    }

    /**
     * @param nameStyle the nameStyle to set
     */
    public void setNameStyle(X500NameStyle nameStyle) {
        this.nameStyle = nameStyle;
    }

}
