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
 
package org.ejbca.core.model.ca.publisher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;



/**
 * CustomPublisherContainer is a class handling a custom publisher. It is used 
 * to store and retrieve custom publisher configuration to database.
 * 
 *
 * @version $Id$
 */
public class CustomPublisherContainer extends BasePublisher{
	private ICustomPublisher custompublisher = null; 
	
	public static final float LATEST_VERSION = 1;
	
	public static final int TYPE_CUSTOMPUBLISHERCONTAINER = 1;
	
	// Default Values
    
    protected static final String CLASSPATH                       = "classpath";
    protected static final String PROPERTYDATA                 = "propertydata";
		
    
    
    public CustomPublisherContainer(){
    	super();
    	data.put(TYPE, new Integer(TYPE_CUSTOMPUBLISHERCONTAINER));
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
		Object description = data.get(BasePublisher.DESCRIPTION);
		if (description != null && description instanceof String) {
			prop.setProperty(BasePublisher.DESCRIPTION, (String) description);
		}
		return prop;
	}
  
    
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public boolean storeCertificate(Admin admin, Certificate incert, String username, String password, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException{
		return this.getCustomPublisher().storeCertificate(admin,incert,username,password, cafp,status,type, revocationDate, revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation);		
	}
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) throws PublisherException{
		return this.getCustomPublisher().storeCRL(admin,incrl,cafp,number);		
	}
    
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public void testConnection(Admin admin) throws PublisherConnectionException{
        this.getCustomPublisher().testConnection(admin);
	} 
    
    // Private methods
	private ICustomPublisher getCustomPublisher() {
		if(custompublisher == null){
			try{
				Class implClass = Class.forName( getClassPath() );
				Object obj = implClass.newInstance();
				this.custompublisher = (ICustomPublisher) obj;
				this.custompublisher.init(getProperties());				
			}catch(ClassNotFoundException e){
				throw new RuntimeException(e);
			}
			catch(IllegalAccessException iae){
				throw new RuntimeException(iae);
			}
			catch(IOException ioe){
				throw new RuntimeException(ioe);
			}
			catch(InstantiationException ie){
				throw new RuntimeException(ie);
			}
		}
		
		return custompublisher;
	}
		
	/** 
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
		CustomPublisherContainer clone = new CustomPublisherContainer();
		HashMap clonedata = (HashMap) clone.saveData();

		Iterator i = (data.keySet()).iterator();
		while(i.hasNext()){
			Object key = i.next();
			clonedata.put(key, data.get(key));
		}

		clone.loadData(clonedata);
		return clone;	
		}

	/* *
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
	 */
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	/**
	 * Resets the current custom publisher
	 * @see org.ejbca.core.model.UpgradeableDataHashMap#saveData()
	 */
	public Object saveData() {
		this.custompublisher = null;
		return super.saveData();
	}
	

}
