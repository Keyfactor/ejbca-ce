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
package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * 
 * A display POJO for approval partitions.
 * 
 * @version $Id$
 *
 */
public class ApprovalPartitionProfileGuiObject implements Serializable {

    private static final long serialVersionUID = 2L;

    private ListDataModel<DynamicUiProperty<? extends Serializable>> profilePropertyList = null;

    private final String approvalProfileIdentifier;
    private final int partitionId;
    private final String partitionName;

    public ApprovalPartitionProfileGuiObject(final String approvalProfileIdentifier, final int partitionId, final String partitionName,
            List<DynamicUiProperty<? extends Serializable>> propertyValues) {
        //Pass property values as a parameter because it may need some outside poking
        setProfilePropertyList(new ListDataModel<>(propertyValues));
        this.approvalProfileIdentifier = approvalProfileIdentifier;
        this.partitionId = partitionId;
        this.partitionName = partitionName;
    }

    public ListDataModel<DynamicUiProperty<? extends Serializable>> getProfilePropertyList() {
        return profilePropertyList;
    }
    
    public void setProfilePropertyList(ListDataModel<DynamicUiProperty<? extends Serializable>> profilePropertyList) {
        this.profilePropertyList = profilePropertyList;
    }

    /** @return the current multi-valued property's possible values as JSF friendly SelectItems. */
    public List<SelectItem/*<String,String>*/> getPropertyPossibleValues() {
        final List<SelectItem> propertyPossibleValues = new ArrayList<>();
        if (profilePropertyList != null) {
            final DynamicUiProperty<? extends Serializable> property = profilePropertyList.getRowData();
            if (property != null && property.getPossibleValues() != null) {
                for (final Serializable possibleValue : property.getPossibleValues()) {
                    propertyPossibleValues
                            .add(new SelectItem(property.getAsEncodedValue(property.getType().cast(possibleValue)), possibleValue.toString()));
                }
            }
        }
        return propertyPossibleValues;
    }

    /** @return the lookup result of message key "APPROVAL_PROFILE_<TYPE>_<property-name>" or property-name if no key exists. */
    public String getPropertyNameLocalized() {
        final String name = profilePropertyList.getRowData().getName();
        final String msgKeyCommon = "APPROVAL_PROFILE_COMMON_" + name.toUpperCase();
        final String translatedNameCommon = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(msgKeyCommon);
        if (!translatedNameCommon.equals(msgKeyCommon)) {
            return translatedNameCommon;
        }
        final String msgKey = "APPROVAL_PROFILE_" + approvalProfileIdentifier.toUpperCase() + "_" + name.toUpperCase();
        final String translatedName = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(msgKey);
        return translatedName.equals(msgKey) ? name : translatedName;
    }
    
    public String getPropertyName() {
        return profilePropertyList.getRowData().getName();
    }

    public int getPartitionId() {
        return partitionId;
    }

    public String getPartitionName() {
        return partitionName;
    }

}
