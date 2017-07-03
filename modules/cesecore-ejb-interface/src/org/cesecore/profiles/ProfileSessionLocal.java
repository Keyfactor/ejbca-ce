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

import java.util.Collection;
import java.util.List;

import javax.ejb.Local;

/**
 * Local interface for ProfileSession
 * 
 * @version $Id$
 *
 */
@Local
public interface ProfileSessionLocal {


    /**
     * Adds a profile to the database
     * @param profile a Profile object
     * 
     * @return the ID of the added profile
     */
    int addProfile(Profile profile);
    
    /**
     * @param id the ID of a profile
     *  
     * @return the found entity instance or null if the entity does not exist 
     */
    ProfileData findById(int id);
    
    /**
     * Retrieves a list of ProfileData objects
     * 
     * @param identifiers a list of identifiers
     * @return the list of objects specified. Returns an empty list if none where found.
     */
    List<ProfileData> findByIds(final Collection<Integer> identifiers);
    
    
    /**
     * Updates profile data
     * 
     * @param profile the updated profile
     */
    void changeProfile(final Profile profile);

    /**
     * Removes the given approval profile.
     * 
     * @param profileData a profile data object
     */
    void removeProfile(final ProfileData profileData);

    /**
     * Renames an approval profile
     * 
     * @param profile the profile to rename
     * @param newname the new name of the approval profile
     * @throws ProfileDoesNotExistException if the profile given as a parameter does not exist
     */
    void renameProfile(final Profile profile, final String newname) throws ProfileDoesNotExistException;
    
    /**
     * @param profileType the profile type 
     * @return return all approval profiles  as a List. 
     */
    List<ProfileData> findAllProfiles(final String profileType);
    
    /**
     * @param name the name of the sought profile
     * @param the type identifier of the sought profile
     * @return the found entity instances or an empty list. 
     */
    List<ProfileData> findByNameAndType(final String name, final String type);

}
