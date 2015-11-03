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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import javax.ejb.EJBException;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * CustomUserDataSourceContainer is a class handling a custom user data source. It is used 
 * to store and retrieve custom user data source configuration to database.
 * 
 *
 * @version $Id$
 */
public class CustomUserDataSourceContainer extends BaseUserDataSource{
	private static final long serialVersionUID = -1356929899319563228L;

    private ICustomUserDataSource customuserdatasource = null; 
	
	public static final float LATEST_VERSION = 1;
	
	public static final int TYPE_CUSTOMUSERDATASOURCECONTAINER = 1;
	
	// Default Values
    
    protected static final String CLASSPATH                       = "classpath";
    protected static final String PROPERTYDATA                 = "propertydata";
		
    
    
    public CustomUserDataSourceContainer(){
    	super();
    	data.put(TYPE, Integer.valueOf(TYPE_CUSTOMUSERDATASOURCECONTAINER));
    	setClassPath("");
    	setPropertyData("");
    }
    
    // Public Methods    
    /**
     *  Returns the class path of custom publisher used.
     */    
    public String getClassPath(){
    	return (String) data.get(CLASSPATH);
    }

    /**
     *  Sets the class path of custom publisher used.
     */        
	public void setClassPath(String classpath){
	  data.put(CLASSPATH, classpath);	
	}

	/**
	 *  Returns the propertydata used to configure this custom publisher.
	 */    
	public String getPropertyData(){
		return (String) data.get(PROPERTYDATA);
	}

	/**
	 *  Sets the propertydata used to configure this custom publisher.
	 */   
	public void setPropertyData(String propertydata){
		data.put(PROPERTYDATA, propertydata);	
	}
	
	public Properties getProperties() throws IOException{
		Properties prop = new Properties();
		prop.load(new ByteArrayInputStream(getPropertyData().getBytes()));
		return prop;
	}
  
    

    
    // Private methods
	private ICustomUserDataSource getCustomUserDataSource() {
		if(customuserdatasource == null){
			try{
				@SuppressWarnings("unchecked")
                Class<? extends ICustomUserDataSource> implClass = (Class<? extends ICustomUserDataSource>) Class.forName( getClassPath() );
				this.customuserdatasource = implClass.newInstance();
				this.customuserdatasource.init(getProperties());				
			}catch(ClassNotFoundException e){
				throw new EJBException(e);
			}
			catch(IllegalAccessException iae){
				throw new EJBException(iae);
			}
			catch(IOException ioe){
				throw new EJBException(ioe);
			}
			catch(InstantiationException ie){
				throw new EJBException(ie);
			}
		}
		
		return customuserdatasource;
	}
		
	/** 
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource#clone()
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
    public Object clone() throws CloneNotSupportedException {
		CustomUserDataSourceContainer clone = new CustomUserDataSourceContainer();
		HashMap clonedata = (HashMap) clone.saveData();

        Iterator i = (data.keySet()).iterator();
		while(i.hasNext()){
			Object key = i.next();
			clonedata.put(key, data.get(key));
		}

		clone.loadData(clonedata);
		return clone;	
		}


	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	/** 
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource#fetch(AuthenticationToken, String)
	 */
	public Collection<UserDataSourceVO> fetch(AuthenticationToken admin, String searchstring) throws UserDataSourceException {		
		return getCustomUserDataSource().fetch(admin,searchstring);
	}
	
	/** 
	 * @throws MultipleMatchException 
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource#removeUserData(AuthenticationToken, String, boolean)
	 */
	
	public boolean removeUserData(AuthenticationToken admin, String searchstring, boolean removeMultipleMatch) throws UserDataSourceException, MultipleMatchException {
		return getCustomUserDataSource().removeUserData(admin, searchstring, removeMultipleMatch);		
	}
	
	/** 
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
	 */
	public void testConnection(AuthenticationToken admin) throws UserDataSourceConnectionException {
		getCustomUserDataSource().testConnection(admin);		
	}
	
	/**
	 * Resets the current custom user data source
	 * @see org.ejbca.core.model.UpgradeableDataHashMap#saveData()
	 */
	public Object saveData() {
		this.customuserdatasource = null;
		return super.saveData();
	}





}
