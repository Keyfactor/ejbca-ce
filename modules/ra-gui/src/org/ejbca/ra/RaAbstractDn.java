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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
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
 */
public abstract class RaAbstractDn {

    private static final Logger log = Logger.getLogger(RaAbstractDn.class);
    
    private final Collection<EndEntityProfile.FieldInstance> requiredFieldInstances = new ArrayList<>();
    private final Collection<EndEntityProfile.FieldInstance> optionalFieldInstances = new ArrayList<>();

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
    
    protected RaAbstractDn(final EndEntityProfile endEntityProfile) {
        this(endEntityProfile, null);
    }

    protected RaAbstractDn(final EndEntityProfile endEntityProfile, final String dn) {
        DNFieldExtractor dnFieldExtractor = null;
        if (dn!=null) {
            dnFieldExtractor = new DNFieldExtractor(dn, getAbstractDnFieldExtractorType());
        }
        if (endEntityProfile == null) {
            log.debug("End Entity Profile is missing. Fields will not be displayed correctly.");
            return;
        }
        for (final String key : getAbstractDnFields()) {
            final Field field = endEntityProfile.new Field(key);
            fieldInstancesMap.put(key, new HashMap<Integer, EndEntityProfile.FieldInstance>());
            for (final EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                if (dnFieldExtractor!=null) {
                    fieldInstance.setValue(dnFieldExtractor.getField(DnComponents.profileIdToDnId(fieldInstance.getProfileId()), fieldInstance.getNumber()));
                }
                if (fieldInstance.isRequired()) {
                    requiredFieldInstances.add(fieldInstance);
                } else {
                    optionalFieldInstances.add(fieldInstance);
                }
                fieldInstancesMap.get(key).put(fieldInstance.getNumber(), fieldInstance);
            }
        }
    }
    
    /**
     * @return the list interface for the required subject DN fields
     */
    public Collection<EndEntityProfile.FieldInstance> getRequiredFieldInstances() {
        return requiredFieldInstances;
    }
    
    /**
     * @return the list interface for the optional subject DN fields
     */
    public Collection<EndEntityProfile.FieldInstance> getOptionalFieldInstances() {
        return optionalFieldInstances;
    }
    
    /**
     * @return the list interface for the required and optional subject DN fields
     */
    public Collection<EndEntityProfile.FieldInstance> getFieldInstances() {
        Collection<EndEntityProfile.FieldInstance> allFieldInstances = new ArrayList<>();
        allFieldInstances.addAll(requiredFieldInstances);
        allFieldInstances.addAll(optionalFieldInstances);
        
        return allFieldInstances;
    }

    /**
     * @return the map interface for the subject DN fields.
     */
    public Map<String, Map<Integer, EndEntityProfile.FieldInstance>> getFieldInstancesMap() {
        return fieldInstancesMap;
    }

    /**
     * Updates the result string value of Subject DN.
     */
    public void update() {
        StringBuilder dn = new StringBuilder();
        Collection<EndEntityProfile.FieldInstance> fullListOfInstances = new ArrayList<>();
        fullListOfInstances.addAll(requiredFieldInstances);
        fullListOfInstances.addAll(optionalFieldInstances);
        
        for (EndEntityProfile.FieldInstance fieldInstance : fullListOfInstances) {
            if (fieldInstance != null) {
                String instanceValue = fieldInstance.getValue();
                if (!StringUtils.isBlank(instanceValue)) {
                    instanceValue = instanceValue.trim();
                    int dnId = DnComponents.profileIdToDnId(fieldInstance.getProfileId());
                    String nameValueDnPart = DNFieldExtractor.getFieldComponent(dnId, getAbstractDnFieldExtractorType()) + instanceValue;
                    nameValueDnPart = org.ietf.ldap.LDAPDN.escapeRDN(nameValueDnPart);
                    if (dn.length() != 0) {
                        dn.append(", ");
                    }
                    dn.append(nameValueDnPart);
                }
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

