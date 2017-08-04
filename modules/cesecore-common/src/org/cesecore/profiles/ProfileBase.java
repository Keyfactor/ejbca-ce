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
package org.cesecore.profiles;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * Base class for all Profile entity beans. Mainly a holder for an UpgradeableDataHashMap, it's meant to be completely agnostic of any implementation
 * details. 
 * 
 * @version $Id$
 *
 */
public abstract class ProfileBase extends UpgradeableDataHashMap implements Profile, Serializable{
    
    private static final long serialVersionUID = 1L;
    
    public static final float LATEST_VERSION = 1f;
    
    private static final String PROFILE_NAME_KEY = "profile.name";
    private static final String PROFILE_ID_KEY = "profile.id";
    
    private transient Class<? extends Profile> implementationClass = null;
    
    private transient String name = null;
    private transient Integer profileId = null;

    public ProfileBase() {
        //Public constructor needed deserialization 
    }
    public ProfileBase(final String name) {
        super();
        setProfileName(name);
        initialize();
    }
    
    /*
     * This method only needs to be called by the factory method (and some unit tests), because it sets a ton of boilerplate stuff which isn't 
     * required by already initialized profiles.
     */
    @Override
    public void initialize() {
        data.put(PROFILE_TYPE, getImplementationClass()); 
    }
    
    @Override
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMap() {
        LinkedHashMap<Object, Object> saveData = (LinkedHashMap<Object, Object>) saveData();
        return saveData;
    }
    
    protected abstract Class<? extends Profile>  getImplementationClass();
    
    /**
     * Method allows implementions to add non-datamapped objects to be persisted. 
     * 
     * @return
     */
    protected abstract void saveTransientObjects();
    
    protected abstract void loadTransientObjects();
    
    @Override
    public void setDataMap(LinkedHashMap<Object, Object> dataMap) {
        loadData(dataMap);
        loadTransientObjects();
    }
        
    @SuppressWarnings("unchecked")
    @Override
    public Class<? extends Profile> getType() {
        if(implementationClass == null) {
            implementationClass = (Class<? extends Profile>) data.get(PROFILE_TYPE);
        }
        return implementationClass;
    }
  
    @Override
    public Integer getProfileId() {
        if(profileId == null) {
            profileId = (Integer) data.get(PROFILE_ID_KEY);
        }
        return profileId;
    }
    
    @Override
    public void setProfileId(Integer profileId) {
        this.profileId = profileId;
        data.put(PROFILE_ID_KEY, profileId);
    }
    
    @Override
    public String getProfileName() {
        if(name == null) {
            name = (String) data.get(PROFILE_NAME_KEY);
        }
        return name;
    }     
    
    @Override
    public void setProfileName(String profileName) {
       this.name = profileName;
       data.put(PROFILE_NAME_KEY, profileName);
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    @Override
    public void upgrade() {}
    
    /** @return data from the underlying map. Encourages use of String valued keys. */
    @SuppressWarnings("unchecked")
    protected <T> T getData(final String key, final T defaultValue) {
        final T ret = (T) data.get(key);
        return ret==null ? defaultValue : ret;
    }
    
    /** Store data in the underlying map. Encourages use of String valued keys. */
    protected void putData(final String key, final Object value) {
        data.put(key, value);
    }
   
    @Override
    public Map<Object, Object> diff(Profile newobj) {
        Map<Object, Object> newmap = (Map<Object, Object>) newobj.getDataMap();
        return diffMaps(data, newmap);
    }
}
