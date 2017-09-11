/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.profiles;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.profiles.Profile;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;

/**
 * Implementation of the "ProfileData" table in the database
 * 
 * @version $Id$
 */
@Entity
@Table(name="ProfileData")
public class ProfileData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

    private int id;
    private String profileName;
    private String profileType;
    private String rawData;
    private int rowVersion = 0;
    private String rowProtection;

    
    public ProfileData() {}
    
    /**
     * Entity holding data of an approval profile.
     */
    public ProfileData(int id, Profile profile) {
        setId(id);
        profile.setProfileId(id); // ID in the data map should be same as in database column
        setProfileName(profile.getProfileName());
        setProfileType(profile.getProfileType());
        setDataMap(profile.getDataMap());
    }
    
    /**
     * Loads the values of the submitted profile implementation into this entity object
     * @param profile a profile
     */
    @Transient
    public void setProfile(Profile profile) {
        setProfileName(profile.getProfileName());
        setProfileType(profile.getProfileType());
        setDataMap(profile.getDataMap());
    }
    
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getProfileName() { return profileName; }
    public void setProfileName(String profileName) { this.profileName = profileName; }
    
    public String getProfileType() { return profileType; }
    public void setProfileType(String profileType) { this.profileType = profileType; }

    /** Should not be invoked directly. Use getDataMap() instead. */
    public String getRawData() { return rawData; }
    /** Should not be invoked directly. Use setDataMap(..) instead. */
    public void setRawData(String rawData) { this.rawData = rawData; }

    @Transient
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMap() {
        try {
            XMLDecoder decoder = new  XMLDecoder(new ByteArrayInputStream(getRawData().getBytes("UTF8")));
            final Map<?, ?> h = (Map<?, ?>)decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap(h);
            return dataMap;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);  // No UTF8 would be real trouble
        }
    }

    @Transient
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
        try {
            // We must base64 encode string for UTF safety
            final LinkedHashMap<?, ?> a = new Base64PutHashMap();
            a.putAll((LinkedHashMap)dataMap);
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final XMLEncoder encoder = new XMLEncoder(baos);
            encoder.writeObject(a);
            encoder.close();
            final String data = baos.toString("UTF8");
            setRawData(data);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
    
    //
    // Start Database integrity protection methods
    //
    @Transient
    @Override
    public String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getProfileName()).append(getDataMap());
        return build.toString();
    }

    
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }
    
    
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
     * 
     * @return the value object representation of this database row
     */
    @SuppressWarnings("unchecked")
    @Transient
    public Profile getProfile() {
        LinkedHashMap<Object, Object> datamap = (LinkedHashMap<Object, Object>)getDataMap();
        Class<? extends Profile> implementationClass = (Class<? extends Profile>) datamap.get(Profile.PROFILE_TYPE);
        if (implementationClass == null) {
            throw new IllegalStateException("No implementation class defined in profile "+profileName);
        }
        Profile returnValue;
        try {     
            returnValue = implementationClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new IllegalStateException("Could not instansiate class of type " + implementationClass.getCanonicalName()+" for profile "+profileName, e);
        }
        returnValue.setProfileName(profileName);
        returnValue.setProfileId(id);
        returnValue.setDataMap(datamap);
        return returnValue;
    }

}
