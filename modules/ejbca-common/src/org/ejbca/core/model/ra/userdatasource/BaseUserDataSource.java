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
 
package org.ejbca.core.model.ra.userdatasource;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.internal.UpgradeableDataHashMap;



/**
 * BaseUserDataSource is a basic class that should be inherited by all types
 * of userdatasources in the system.
 * 
 * Contains data like description, applicable CAs and modifyable fields.
 *  
 *
 * @version $Id$
 */
public abstract class BaseUserDataSource extends UpgradeableDataHashMap implements Serializable, Cloneable {

    private static final long serialVersionUID = 2359037086634246374L;
    public static final String TRUE  = "true";
    public static final String FALSE = "false";
    
    /** Constant indicating that any CA can be used with this user data source.*/
    public static final int ANYCA = -1;

    // Protected Constants.
	public static final String TYPE                           = "type";
	
    protected static final String DESCRIPTION                 = "DESCRIPTION";
    protected static final String APPLICABLECAS                = "APPLICABLECAS";
    protected static final String MODIFYABLEFIELDS            = "MODIFYABLEFIELDS";
		
    // Public Methods

    /**
     * Creates a new instance of CertificateProfile
     */
    public BaseUserDataSource() {
      setDescription("");	
      
      ArrayList<Integer> applicablecas = new ArrayList<>();
      setApplicableCAs(applicablecas);
      
      HashSet<Integer> modifyableFields = new HashSet<>();
      for(int i=0; i< UserDataSourceVO.AVAILABLEMODIFYABLEFIELDS.length; i++){
    	  modifyableFields.add(Integer.valueOf(UserDataSourceVO.AVAILABLEMODIFYABLEFIELDS[i]));
      }
      setModifiableFields(modifyableFields);
  
    }

    // Public Methods
    /**
     * Returns the description of publisher
     */
    public String getDescription() { return (String) data.get(DESCRIPTION);}

	/**
	 * Sets the description. 
	 */
	public void setDescription(String description){ data.put(DESCRIPTION, description); }

    /**
     * Returns a Collections of caids (Integer), indicating which CAs the user data source should
     * be applicable to.
     *
     * If it contains the constant ANYCA then the user data source is applicable to all CAs
     */
    @SuppressWarnings("unchecked")
	public Collection<Integer> getApplicableCAs(){
      return (Collection<Integer>) data.get(APPLICABLECAS);   
    }
    
    /**
     * Saves the  list of CAs the  user data source is applicable to.
     *
     * @param applicablecas a Collection of caids (Integer)
     */
    
    public void setApplicableCAs(Collection<Integer> applicablecas){
      data.put(APPLICABLECAS, applicablecas);   
    }
    
    /**
     * 
     * @return true if user data source is applicable for all CAs
     */
    @SuppressWarnings("unchecked")
	public boolean isApplicableToAnyCA(){
    	return ((Collection<Integer>) data.get(APPLICABLECAS)).contains(Integer.valueOf(ANYCA));
    } 
    
    /**
     * Returns a Set of UserDataSourceVO.ISMODIFYABLE_ and DNFIELDExtractor constants (Integer) constants (All definded in the UserDataSourceVO.AVAILABLEMODIFYABLEFIELDS, 
     * indicating if the field should be modifyable by the CA or not.
     *
     */
    @SuppressWarnings("unchecked")
	public Set<Integer> getModifiableFields(){
      return (Set<Integer>) data.get(MODIFYABLEFIELDS);   
    }
    
    /**
     * Saves the set of which fields of the CA that should be modifyable by the RA or not.
     * The set should only contain UserDataSourceVO.ISMODIFYABLE_ and DNFIELDExtractor constants (Integer)
     */
    
    public void setModifiableFields(Set<Integer> modifiableFields){	
      data.put(MODIFYABLEFIELDS, modifiableFields);   
    }
    
    /**
     * Method that returns the fetched UserDataSourceVOs with the isModifyableset set.
     * This method should be used by external UserDataSource callers
     */    
    public  Collection<UserDataSourceVO> fetchUserDataSourceVOs(AuthenticationToken admin, String searchstring) throws UserDataSourceException{
    	Collection<UserDataSourceVO> result = fetch(admin,searchstring);
    	
    	Set<Integer> isModifyable = getModifiableFields();
    	Iterator<UserDataSourceVO> iter = result.iterator();
    	while(iter.hasNext()){
    		UserDataSourceVO next = iter.next();
    		next.setIsModifyableSet(isModifyable);
    	}
    	return result;
    }
    
    // Abstact methods.
    
    /**
     * Searches for userdata given the searchstring
     *
     * @param searchstring the string the user data source should use to look for the data.
     *
     * @return a collection of UserDataSourceVO, returns an Empty Collection if no userdata could be found
     *
     * @throws UserDataSourceException if a communication or other error occurs.
     */    
    protected abstract Collection<UserDataSourceVO> fetch(AuthenticationToken admin, String searchstring) throws UserDataSourceException;
	
    /**
     * Optional method used to remove user data from a user data source.
     * It's up to the implementation if it should be supported or not.
     * 
     * Removes user data that matches the given search string.
     *
     * @param searchstring the string the user data source that should be removed
     * @param removeMultipleMatch use to indicate if all entries should be removed it the search string
     * @return true if the user was remove successfully from at least one of the user data sources.
     * matches more than one, if false will a UserDataSourceException be thrown if more than one User data
     * matches the search string.  
     *
     *
     * @throws UserDataSourceException if a communication or other error occurs.
     */   
    public abstract boolean removeUserData(AuthenticationToken admin, String searchstring, boolean removeMultipleMatch) throws MultipleMatchException, UserDataSourceException;
    
    /**
     * Method used to test the connection to a user data source.
     * 
     * @param admin the administrator perfoming the test
     * @throws UserDataSourceConnectionException when a connection couldn't be set up correctly in any way.
     */
    public abstract void testConnection(AuthenticationToken admin) throws UserDataSourceConnectionException;
    

    @Override
    public abstract Object clone() throws CloneNotSupportedException;

    
    @Override
    public abstract float getLatestVersion();

    @Override
    public void upgrade(){
    	// Performing upgrade rutines
    }
    
	

}
