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
package org.ejbca.core.model.approval.profile;

import java.io.Serializable;
import java.util.LinkedHashMap;

import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Represents a partition of an approval sequence. Each sequence consists of one or more partitions, which have to all be evaluated before the sequence can pass. 
 * 
 * @version $Id$
 *
 */
public class ApprovalPartition implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> properties = new LinkedHashMap<>();
    private final int partitionIdentifier;
    

    public ApprovalPartition(int partitionIdentifier) {
        this.partitionIdentifier = partitionIdentifier;
    }
    
    /**
     * Copy constructor 
     * @param partition the original 
     */
    public ApprovalPartition(ApprovalPartition original) {
        for(DynamicUiProperty<? extends Serializable> property : original.getPropertyList().values()) {
            properties.put(property.getName(), new DynamicUiProperty<>(property));
        }
        this.partitionIdentifier = original.getPartitionIdentifier();
    }
    
    // In a PartionedApprovalProfile the partition has a name with property PartitionedApprovalProfile.PROPERTY_NAME
    public DynamicUiProperty<? extends Serializable> getProperty(final String name) {
        return properties.get(name);
    }

    public LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> getPropertyList() {
        final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> ret = new LinkedHashMap<String, DynamicUiProperty<? extends Serializable>>();
        for (String key : properties.keySet()) {
            DynamicUiProperty<? extends Serializable> current = properties.get(key);
            final DynamicUiProperty<? extends Serializable> clone = current.clone();
            if (clone.getHasMultipleValues()) {
                clone.setValuesGeneric(getProperty(clone.getName()).getValues());
            } else {
                clone.setValueGeneric(getProperty(clone.getName()).getValue());
            }
            ret.put(key, clone);
        }
        return ret;
    }
    
    public void addProperty(DynamicUiProperty<? extends Serializable> value) {
        properties.put(value.getName(), value);
    }
    
    public void removeProperty(final String propertyName) {
        properties.remove(propertyName);
    }
    
    public int getPartitionIdentifier() {
        return partitionIdentifier;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + partitionIdentifier;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ApprovalPartition other = (ApprovalPartition) obj;
        if (partitionIdentifier != other.partitionIdentifier)
            return false;
        return true;
    }
}
