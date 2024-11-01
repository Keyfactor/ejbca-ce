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
package org.cesecore.keys.validation;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 *
 */
public class LinterProfileList{
    
    private Map<String, Set<LinterProfile>> profilesMap = new TreeMap<>();
    
    /**
     * Compiles a list of profiles, mapped by source. 
     * 
     * @param source
     * @param name
     * @param description
     */
    public void addProfile(final String source, final String name, final String description) {
        if(profilesMap.containsKey(source)) {
            Set<LinterProfile> profiles = profilesMap.get(source);
            profiles.add(new LinterProfile(name, description));
            profilesMap.put(source, profiles);
        } else {
            profilesMap.put(source, new TreeSet<>(Arrays.asList(new LinterProfile(name, description))));
        }

    }
    
    public  Map<String, Set<LinterProfile>> getProfiles() {
        return profilesMap;
    }
    
    public boolean isEmpty() {
        return profilesMap.isEmpty();
    }

}
