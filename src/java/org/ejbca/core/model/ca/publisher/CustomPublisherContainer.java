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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.endentity.ExtendedInformation;



/**
 * CustomPublisherContainer is a class handling a custom publisher. It is used 
 * to store and retrieve custom publisher configuration to database.
 * 
 *
 * @version $Id$
 */
public class CustomPublisherContainer extends BasePublisher {
	private static final long serialVersionUID = -7060678968358301488L;

    private ICustomPublisher custompublisher = null; 
	
	public static final float LATEST_VERSION = 1;
		
	// Default Values
    
    protected static final String CLASSPATH                       = "classpath";
    protected static final String PROPERTYDATA                 = "propertydata";
		
    
    
    public CustomPublisherContainer(){
    	super();
    	data.put(TYPE, Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER));
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
	
	public boolean isCustomUiRenderingSupported() {
	    return getCustomPublisher() instanceof CustomPublisherUiSupport;
	}
    public List<CustomPublisherProperty> getCustomUiPropertyList() {
        if (getCustomPublisher() instanceof CustomPublisherUiSupport) {
            return ((CustomPublisherUiSupport)getCustomPublisher()).getCustomUiPropertyList();
        }
        return new ArrayList<CustomPublisherProperty>();
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
  
	@Override
	public boolean isFullEntityPublishingSupported() {
	    return this.getCustomPublisher() instanceof FullEntityPublisher
	            && ((FullEntityPublisher)this.getCustomPublisher()).isFullEntityPublishingSupported();
	}
    
    @Override
    public boolean storeCertificate(final AuthenticationToken authenticationToken, final CertificateData certificateData, final Base64CertData base64CertData) throws PublisherException {
        if (isFullEntityPublishingSupported()) {
            return ((FullEntityPublisher)this.getCustomPublisher()).storeCertificate(authenticationToken, certificateData, base64CertData);
        } else {
            return super.storeCertificate(authenticationToken, certificateData, base64CertData);
        }
    }

	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException{
		return this.getCustomPublisher().storeCertificate(admin,incert,username,password, userDN, cafp,status,type, revocationDate, revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation);		
	}
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException{
		return this.getCustomPublisher().storeCRL(admin,incrl,cafp,number,userDN);		
	}
    
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public void testConnection() throws PublisherConnectionException{
        this.getCustomPublisher().testConnection();
	} 
    
    // Private methods
	private ICustomPublisher getCustomPublisher() {
		if(custompublisher == null){
		    final String classPath = getClassPath();
		    if (classPath==null || classPath.isEmpty()) {
		        return null;
		    }
			try{
				@SuppressWarnings("unchecked")
                Class<? extends ICustomPublisher> implClass = (Class<? extends ICustomPublisher>) Class.forName( classPath );
				this.custompublisher =  implClass.newInstance();
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
	@SuppressWarnings({ "rawtypes", "unchecked" })
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
