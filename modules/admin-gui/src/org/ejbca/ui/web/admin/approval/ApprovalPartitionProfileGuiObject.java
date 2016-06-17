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
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * 
 * A display POJO for approval sequences.
 * 
 * @version $Id$
 *
 */
public class ApprovalPartitionProfileGuiObject {

    private ListDataModel<DynamicUiProperty<? extends Serializable>> profilePropertyList = null;

    private final String approvalProfileIdentifier;
    private final int partitionId;

    public ApprovalPartitionProfileGuiObject(final String approvalProfileIdentifier, final int partitionId,
            List<DynamicUiProperty<? extends Serializable>> propertyValues) {
        //Pass property values as a parameter because it may need some outside poking
        setProfilePropertyList(new ListDataModel<>(propertyValues));
        this.approvalProfileIdentifier = approvalProfileIdentifier;
        this.partitionId = partitionId;
    }

    public ListDataModel<DynamicUiProperty<? extends Serializable>> getProfilePropertyList() {
        return profilePropertyList;
    }
    
    public void setProfilePropertyList(ListDataModel<DynamicUiProperty<? extends Serializable>> profilePropertyList) {
        this.profilePropertyList = profilePropertyList;
    }

    /** @return the current multi-valued property's possible values as JSF friendly SelectItems. */
    public List<SelectItem/*<String,String>*/> getPropertyPossibleValues() {
        final List<SelectItem> propertyPossibleValues = new ArrayList<SelectItem>();
        if (profilePropertyList != null) {
            final DynamicUiProperty<? extends Serializable> property = profilePropertyList.getRowData();
            for (final Serializable possibleValue : property.getPossibleValues()) {
                propertyPossibleValues
                        .add(new SelectItem(property.getAsEncodedValue(property.getType().cast(possibleValue)), possibleValue.toString()));
            }
        }
        return propertyPossibleValues;
    }

    /** @return the lookup result of message key "APPROVAL_PROFILE_<TYPE>_<property-name>" or property-name if no key exists. */
    public String getPropertyNameLocalized() {
        final String name = profilePropertyList.getRowData().getName();
        final String msgKey = "APPROVAL_PROFILE_" + approvalProfileIdentifier.toUpperCase() + "_" + name.toUpperCase();
        final String translatedName = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(msgKey);
        return translatedName.equals(msgKey) ? name : translatedName;
    }

    public int getPartitionId() {
        return partitionId;
    }

}
