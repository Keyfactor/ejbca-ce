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
package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.cesecore.internal.UpgradeableDataHashMap;

public class ApprovalProfile extends UpgradeableDataHashMap implements Serializable, Cloneable{

    public static final String TYPE = "APPROVAL_PROFILE";
    
    private static final long serialVersionUID = 250315209409187525L;
    
    public static final float LATEST_VERSION = 1;
    
    public static final String PROFILENAME      = "profileName";
    public static final String PROFILETYPE      = "ProfileType";
    public static final String APPROVALPROFILETYPE    = "ApprovalProfileType";
    
    public ApprovalProfile() {
        super();
    }
    
    public ApprovalProfile(final String name) {
        super();
        init(name, null, null);
    }
    
    public ApprovalProfile(final String name, final ApprovalProfileType type, final Map<String, Object> fields) {
        super();
        init(name, type, fields);
    }
    
    private void init(final String name, final ApprovalProfileType type, final Map<String, Object> fields) {
        data.put(PROFILENAME, name);
        data.put(PROFILETYPE, TYPE);

        
        ApprovalProfileType profileType = type;
        if(profileType==null) {
            profileType = new ApprovalProfileNumberOfApprovals();
        }
        data.put(APPROVALPROFILETYPE, profileType);
        final Map<String, Object> typeFields = profileType.getAllFields();
        Set<Entry<String, Object>> entries = typeFields.entrySet();
        for(Entry<String, Object> entry : entries) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if(fields != null && fields.containsKey(key)) {
                value = fields.get(key);
            }
            data.put(key, value);
        }
    }
    
    public String getProfileName() {
        return (String) data.get(PROFILENAME);
    }

    public ApprovalProfileType getApprovalProfileType() {
        return (ApprovalProfileType) data.get(APPROVALPROFILETYPE);
    }
    
    public void setApprovalProfileType(ApprovalProfileType type) {
        data.put(APPROVALPROFILETYPE, type);
    }

    @Override
    public ApprovalProfile clone() throws CloneNotSupportedException {
        final ApprovalProfile clone = new ApprovalProfile(getProfileName()+"-(Clone)");
        // We need to make a deep copy of the hashmap here
        clone.data = new LinkedHashMap<>(data.size());
        for (final Entry<Object,Object> entry : data.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof ArrayList<?>) {
                        // We need to make a clone of this object, but the stored immutables can still be referenced
                        value = ((ArrayList<?>)value).clone();
                }
                clone.data.put(entry.getKey(), value);
        }
        return clone;
    }
    

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        // TODO Auto-generated method stub
        
    }
}
