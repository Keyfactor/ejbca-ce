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

import org.bouncycastle.asn1.x500.X500NameStyle;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.util.CeSecoreNameStyle;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile.Field;

/**
 * Represents two APIs: list (needed for JSF) and map
 * for the DN fields of the specified end entity profile. It is
 * extended by Subject DN, SubjectAlternateName and Subject Directory Attributes
 * 
 * @version $Id: RaAbstractDn.java 23866 2016-07-11 16:11:45Z jeklund $
 *
 */
public abstract class RaAbstractDn {

    //private static final Logger log = Logger.getLogger(RaAbstractDn.class);
    
    private final Collection<EndEntityProfile.FieldInstance> fieldInstances = new ArrayList<>();
    private final Map<String, Map<Integer, EndEntityProfile.FieldInstance>> fieldInstancesMap = new HashMap<>();
    protected String value;
    protected X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
    protected boolean ldapOrder = true;

    /**
     * @return one of the DNFieldExtractor.TYPE_*
     */
    protected abstract int getAbstractDnFieldExtractorType();
    
    /**
     * @return one of the DnComponents.getDnProfileFields, DnComponents.getAltNameFields() or DnComponents.getDirAttrFields
     */
    protected abstract ArrayList<String> getAbstractDnFields();
    
    /**
     * Intended to be used for Subject DN: ;
     * @return reordered dn value
     */
    protected abstract String reorder(String dnBeforeReordering);
    
    public RaAbstractDn(final EndEntityProfile endEntityProfile) {
        this(endEntityProfile, null);
    }

    public RaAbstractDn(final EndEntityProfile endEntityProfile, final String dn) {
        DNFieldExtractor dnFieldExtractor = null;
        if (dn!=null) {
            dnFieldExtractor = new DNFieldExtractor(dn, getAbstractDnFieldExtractorType());
        }
        for (final String key : getAbstractDnFields()) {
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
        StringBuilder dn = new StringBuilder();
        for (EndEntityProfile.FieldInstance fieldInstance : fieldInstances) {
            final String value = fieldInstance.getValue().trim();
            if (!value.isEmpty()) {
                int dnId = DnComponents.profileIdToDnId(fieldInstance.getProfileId());
                String nameValueDnPart = DNFieldExtractor.getFieldComponent(dnId, getAbstractDnFieldExtractorType()) + value;
                nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart);
                if (dn.length() != 0) {
                    dn.append(", ");
                }
                dn.append(nameValueDnPart);
            }
        }
        value = reorder(dn.toString());
    }

    @Override
    public String toString() {
        return getUpdatedValue();
    }

    /**
     * Returns non-updated string value of abstract DN.
     * @return DN as String
     * @see RaAbstractDn.update()
     */
    public String getValue() {
        if(value == null){
            update();
        }
        return value;
    }
    
    /**
     * Updates the string value of abstract DN and then returns it.
     * @return DN as String
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

