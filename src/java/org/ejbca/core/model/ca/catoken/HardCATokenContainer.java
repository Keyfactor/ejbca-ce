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

package org.ejbca.core.model.ca.catoken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import javax.ejb.EJBException;




/**
 * HardCATokenContainer is a class managing the persistent storage of a hardcatoken publisher.
 * 
 *
 * @version $Id: HardCATokenContainer.java,v 1.4 2006-05-28 14:21:11 anatom Exp $
 */
public class HardCATokenContainer extends CAToken{
	private IHardCAToken hardcatoken = null; 
	
	public static final float LATEST_VERSION = 1;
	
	public static final int TYPE_CUSTOMPUBLISHERCONTAINER = 1;
	
	// Default Values
    
    protected static final String CLASSPATH                       = "classpath";   
    protected static final String PROPERTYDATA                 = "propertydata";
		
    
    
    public HardCATokenContainer(){
    	super();
    	data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_HSM));
    	setClassPath(null);
    	setPropertyData("");
    }
    
    public HardCATokenContainer(HashMap data) {
        loadData(data);  
        data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_HSM));                  
     }
    
    // Public Methods    

	/**
     * Returns the current hardcatoken configuration.
	 */
	public CATokenInfo getCATokenInfo() {
		HardCATokenInfo info = new HardCATokenInfo();
		info.setClassPath(getClassPath());
		info.setProperties(getPropertyData());
		info.setSignatureAlgorithm(getSignatureAlgorithm());
		if ( hardcatoken!=null ){
			info.setCATokenStatus(hardcatoken.getCATokenStatus());
		}else{
			info.setCATokenStatus(IHardCAToken.STATUS_OFFLINE);
		}
			
		return info;
	}

	/** 
	 * Updates the hardcatoken configuration
	 */
	public void updateCATokenInfo(CATokenInfo catokeninfo) {
		// We must be able to upgrade class path
		if (((HardCATokenInfo)catokeninfo).getClassPath() != null) {
			  this.setClassPath(((HardCATokenInfo)catokeninfo).getClassPath());			
			  this.hardcatoken = null;
		}
		if(getSignatureAlgorithm() == null)
		  this.setSignatureAlgorithm(catokeninfo.getSignatureAlgorithm());
		
		if(!this.getPropertyData().equals(((HardCATokenInfo)catokeninfo).getProperties())){
		  this.setPropertyData(((HardCATokenInfo)catokeninfo).getProperties());				
		  this.hardcatoken = null;
		}  
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CAToken#activate(java.lang.String)
	 */
	public void activate(String authorizationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		getHardCAToken().activate(authorizationcode);		
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CAToken#deactivate()
	 */
	public boolean deactivate() {		
		return getHardCAToken().deactivate();
	}

	
	/**
	 * @see org.ejbca.core.model.ca.catoken.CAToken#getPrivateKey()
	 */
	public PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException{		
		return getHardCAToken().getPrivateKey(purpose);
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CAToken#getPublicKey()
	 */
	public PublicKey getPublicKey(int purpose) throws CATokenOfflineException{
		return getHardCAToken().getPublicKey(purpose);
	}


	/**
	 * @see org.ejbca.core.model.ca.catoken.CAToken#getProvider()
	 */
	public String getProvider() {		
		return getHardCAToken().getProvider();
	}

    
    
    // Private methods
    /**
     *  Returns the class path of custom publisher used.
     */    
    private String getClassPath(){
    	return (String) data.get(CLASSPATH);
    }

    /**
     *  Sets the class path of custom publisher used.
     */        
    private void setClassPath(String classpath){
	  data.put(CLASSPATH, classpath);	
	}
    
    /**
     *  Returns the class path of custom publisher used.
     */    
    private String getSignatureAlgorithm(){
    	return (String) data.get(SIGNATUREALGORITHM);
    }

    /**
     *  Sets the SignatureAlgoritm
     */        
    private void setSignatureAlgorithm(String signaturealgoritm){
	  data.put(SIGNATUREALGORITHM, signaturealgoritm);	
	}


	/**
	 *  Returns the propertydata used to configure this custom publisher.
	 */    
	private String getPropertyData(){
		return (String) data.get(PROPERTYDATA);
	}

	/**
	 *  Sets the propertydata used to configure this custom publisher.
	 */   
	private void setPropertyData(String propertydata){
		data.put(PROPERTYDATA, propertydata);	
	}
	
	private Properties getProperties() throws IOException{
		Properties prop = new Properties();
		prop.load(new ByteArrayInputStream(getPropertyData().getBytes()));
		return prop;
	}

    
    
	private IHardCAToken getHardCAToken() {
		if(hardcatoken == null){
			try{				
				Class implClass = Class.forName( getClassPath());
				Object obj = implClass.newInstance();
				this.hardcatoken = (IHardCAToken) obj;
				this.hardcatoken.init(getProperties(), getSignatureAlgorithm());				
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
		
		return hardcatoken;
	}
		
	/** 
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
		HardCATokenContainer clone = new HardCATokenContainer();
		HashMap clonedata = (HashMap) clone.saveData();

		Iterator i = (data.keySet()).iterator();
		while(i.hasNext()){
			Object key = i.next();
			clonedata.put(key, data.get(key));
		}

		clone.loadData(clonedata);
		return clone;	
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
	 */
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}



	public void upgrade() {
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
	        // New version of the class, upgrade

	        data.put(VERSION, new Float(LATEST_VERSION));
	      }  		
	}
	

}
