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
 
package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.web.admin.configuration.InformationMemory;

/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @version $Id$
 */
public class EndEntityProfileDataHandler implements Serializable {

    private static final long serialVersionUID = 1L;

    private EndEntityProfileSessionLocal endEntityProfileSession;
    private AuthenticationToken administrator;
    private InformationMemory info;

    public static final String EMPTY_PROFILE        = EndEntityProfileSession.EMPTY_ENDENTITYPROFILENAME;    
    /** Creates a new instance of EndEntityProfileDataHandler */
    public EndEntityProfileDataHandler(AuthenticationToken administrator, EndEntityProfileSessionLocal endEntityProfileSession, InformationMemory info) {
       this.endEntityProfileSession = endEntityProfileSession;        
       this.administrator = administrator;          
       this.info = info;
    }
        
    /** Method to add a end entity profile. Throws EndEntityProfileExitsException if profile already exists  */
    public void addEndEntityProfile(String name, EndEntityProfile profile) throws EndEntityProfileExistsException, AuthorizationDeniedException {
        endEntityProfileSession.addEndEntityProfile(administrator, name, profile);
        this.info.endEntityProfilesEdited();
    }
      
    /** Method to change a end entity profile. 
     * @throws EndEntityProfileNotFoundException if sought end entity profile was not found
     */     
    public void changeEndEntityProfile(String name, EndEntityProfile profile) throws AuthorizationDeniedException, EndEntityProfileNotFoundException{
        endEntityProfileSession.changeEndEntityProfile(administrator, name,profile);   
        this.info.endEntityProfilesEdited();
    }
    
    /** Method to remove a end entity profile.*/ 
    public void removeEndEntityProfile(String name) throws AuthorizationDeniedException{
        endEntityProfileSession.removeEndEntityProfile(administrator, name);
        this.info.endEntityProfilesEdited();
    }
    
    /** Metod to rename a end entity profile */
    public void renameEndEntityProfile(String oldname, String newname) throws EndEntityProfileExistsException, AuthorizationDeniedException{
        endEntityProfileSession.renameEndEntityProfile(administrator, oldname,newname);
        this.info.endEntityProfilesEdited();
    }
    

    public void cloneEndEntityProfile(String originalname, String newname) throws EndEntityProfileExistsException, AuthorizationDeniedException{         
        endEntityProfileSession.cloneEndEntityProfile(administrator, originalname,newname);
        this.info.endEntityProfilesEdited();
    }    
    
      /** Method to get a reference to a end entity profile.*/ 
    public EndEntityProfile getEndEntityProfile(int id) {  
        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(id); 
        return profile;
    }      
          
    public EndEntityProfile getEndEntityProfile(String profilename) {
        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(profilename);
        return profile;
    }
   
    /**  
     * @param profilename the name of the sought profile
     * @return the ID of the sought profile
     * @throws EndEntityProfileNotFoundException if no such profile exists
     */
    public int getEndEntityProfileId(String profilename) throws EndEntityProfileNotFoundException{
      return endEntityProfileSession.getEndEntityProfileId(profilename);  
    }
       
}
