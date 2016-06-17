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
package org.ejbca.core.model.profiles;

import java.io.Serializable;
import java.util.LinkedHashMap;

/**
 * Base interface for all Profile objects. 
 * 
 * @version $Id$
 *
 */
public interface Profile extends Serializable{
    
    /**
     * Designator for the base type, in this case a Class which extends ProfileBase
     */
    final String PROFILE_TYPE      = "profile.type";
    
    /**
     * 
     * @return the name of this particular profile type instance
     */
    String getProfileName();
    
    void setProfileName(String profileName);
    
    /** 
     * @return the database ID value of this profile. May be null if the profile has not yet been persisted. 
     */
    Integer getProfileId();
    
    void setProfileId(Integer profileId) ;
    
    /**
     * 
     * @return a string identifier for identifying this profile type in the database
     */
    String getProfileType();

    /**
     * 
     * @return the complete data map for this implementation, primarily used to persist it. 
     */
    LinkedHashMap<Object, Object> getDataMap();
    
    void setDataMap(LinkedHashMap<Object, Object> dataMap);
    
    /**
     * 
     * @return the implementing class
     */
    Class<? extends Profile> getType();
    
    void initialize();
    

}
