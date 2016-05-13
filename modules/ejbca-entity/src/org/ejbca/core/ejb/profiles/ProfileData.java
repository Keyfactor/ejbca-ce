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
package org.ejbca.core.ejb.profiles;

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;

import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.JBossUnmarshaller;
import org.ejbca.core.model.approval.ApprovalProfile;

/**
 * Implementation of the "ProfileData" table in the database
 * 
 * @version $Id$
 */
@Entity
@Table(name="ProfileData")
public class ProfileData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(ProfileData.class);

    private int id;
    private String profileName;
    private  String profileType;
    private Serializable data;
    private int rowVersion = 0;
    private String rowProtection;
    
    public ProfileData() {}
    
    /**
     * Entity holding data of an approval profile.
     */
    public ProfileData(int id, String profileName, ApprovalProfile approvalProfile) {
        setId(id);
        setProfileName(profileName);
        setProfileType(ApprovalProfile.TYPE);
        setProfile(approvalProfile);
        log.debug("Created profile " + profileName);
    }
    
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getProfileName() { return profileName; }
    public void setProfileName(String profileName) { this.profileName = profileName; }
    
    public String getProfileType() { return profileType; }
    public void setProfileType(String profileType) { this.profileType = profileType; }
    
    public Serializable getDataUnsafe() { return data; }
    // /** DO NOT USE! Stick with setData(HashMap data) instead. */
    private void setDataUnsafe(Serializable data) { this.data = data; }

    @Transient
    private LinkedHashMap<?, ?> getData() {
        return JBossUnmarshaller.extractLinkedHashMap(data);
    }
    private void setData(LinkedHashMap<?, ?> data) { setDataUnsafe(JBossUnmarshaller.serializeObject(data)); }
    
    /**
     * Method that returns the approval profile and updates it if necessary.
     */
    @Transient
    public ApprovalProfile getProfile() {
        return readAndUpgradeProfileInternal();
    }

    /**
     * Method that saves the approval profile.
     */
    public void setProfile(ApprovalProfile profile) {
        setData((LinkedHashMap<?, ?>) profile.saveData());
    }
    
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }
    
    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getProfileName()).append(getData());
        return build.toString();
    }
    
    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @Override
    public String getRowProtection() { return rowProtection; }
    @Override
    public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    @Override
    @Transient
    protected String getRowId() {
        return String.valueOf(getId());
    }
    
    /** 
     * Method that upgrades an approval Profile, if needed.
     */
    public void upgradeProfile() {
        readAndUpgradeProfileInternal();
    }

    /**
     * We have an internal method for this read operation with a side-effect. 
     * This is because getProfile() is a read-only method, so the possible side-effect of upgrade will not happen,
     * and therefore this internal method can be called from another non-read-only method, upgradeProfile().
     * @return ApprovalProfile
     * TODO: Still true with JPA?
     */
    private ApprovalProfile readAndUpgradeProfileInternal() {
        ApprovalProfile returnval = new ApprovalProfile();
        HashMap<?, ?> data = getData();
        // If ApprovalProfile-data is upgraded we want to save the new data, so we must get the old version before loading the data 
        // and perhaps upgrading
        float oldversion = ((Float) data.get(UpgradeableDataHashMap.VERSION)).floatValue();
        // Load the profile data, this will potentially upgrade the ApprovalProfile
        returnval.loadData(data);
        if (Float.compare(oldversion, returnval.getVersion()) != 0) {
            // Save new data versions differ
            setProfile(returnval);
            if (log.isDebugEnabled()) {
                log.debug("Saved upgraded profile, old version="+oldversion+", new version="+returnval.getVersion());               
            }
        }
        return returnval;
    }
     
}
