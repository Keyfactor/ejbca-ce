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

package org.ejbca.core.model.ca.certextensions;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;

/**
 * Class parsing the src/java/certextensions.properties file 
 * and maintains a set of available extensions to the system.
 * 
 * It is also responsible for creating the actual CertificateExtensions
 * used in certificate generation.
 * 
 * 
 * @author Philip Vendil 2007 jan 5
 *
 * @version $Id: CertificateExtensionFactory.java,v 1.3 2007-02-02 18:09:42 anatom Exp $
 */

public class CertificateExtensionFactory {

	private static Logger log = Logger.getLogger(CertificateExtensionFactory.class);
	private static final InternalResources intres = InternalResources.getInstance();
	
	private static CertificateExtensionFactory instance = null;
	
	private static String PROPERTY_ID           = "id";
	private static String PROPERTY_OID          = ".oid";
	private static String PROPERTY_CLASSPATH    = ".classpath";
	private static String PROPERTY_DISPLAYNAME  = ".displayname";
	private static String PROPERTY_USED         = ".used";
	private static String PROPERTY_TRANSLATABLE = ".translatable";
	private static String PROPERTY_CRITICAL     = ".critical";
	
	private ArrayList availableCertificateExtensions = new ArrayList();
	private HashMap certificateExtensions = new HashMap();
	
	private CertificateExtensionFactory(){}
	
	
	/**
	 * Special Method that should only be used from test scripts.
	 */
	static CertificateExtensionFactory getInstance(Properties props){
		if(instance == null){
			instance = parseConfiguration(props);
		}
		
		return instance;
	}
	
	/**
	 * Method used to get the instance of the factory.
	 * If it is the first time the method is called will
	 * the configuration file be parsed.
	 */
	public static CertificateExtensionFactory getInstance(){
		if(instance == null){
			instance = parseConfiguration(null);
		}
		
		return instance;
	}
	
	/**
	 * Method returning a list of all of (AvailableCertificateExtensions)
	 * to be used in the 'Edit Certificate Profile' page
	 */
	public List getAvailableCertificateExtensions(){				
		return availableCertificateExtensions;
	}
	
	/**
	 * Method returning the instance of the CertificateExtension
	 * given its Id
	 * 
	 * @returns null if the CertificateExtension doesn't exist
	 */
	public CertificateExtension getCertificateExtensions(Integer id){
		return (CertificateExtension) certificateExtensions.get(id);
	}

	/** 
	 * Method reponsible to read the configuration file.
	 * and parse it into AvailableCertificateExtentions and
	 * also generate instances of the actual CertificateExtensions.
	 * @param props2 
	 *
	 */
	private static CertificateExtensionFactory parseConfiguration(Properties props) {
		
		CertificateExtensionFactory retval = new CertificateExtensionFactory();
		try{
			if(props == null){
				props = new Properties();
				InputStream is = null;
				try {
					is = CertificateExtensionFactory.class.getResourceAsStream("/certextensions.properties");
					if(is != null){
						props.load(is);
					}else{
						log.error("Certificate Extension configuration file not found");
					}
				} finally {
					if (is != null) is.close();
				}
			}			
			
			for(int i=1;i<255;i++){
				if(props.get("id" + i +".oid")!=null){
					log.debug("found " + props.get("id" + i +".oid"));
					retval.addCertificateExtension(props,i);
				}else{
					break;
				}
			}
			log.debug("Nr of availableCeritficateExtensions: " + retval.availableCertificateExtensions.size());
		}catch(IOException e){
			log.error(intres.getLocalizedMessage("certext.errorparsingproperty"),e);
		} catch (CertificateExtentionConfigurationException e) {
			log.error(e.getMessage(),e);
		}
		
		return retval;
	}


	private void addCertificateExtension(Properties props, int id) throws CertificateExtentionConfigurationException {
		try{
			String oid = props.getProperty(PROPERTY_ID + id + PROPERTY_OID);
			String classPath = props.getProperty(PROPERTY_ID + id + PROPERTY_CLASSPATH);
			String displayName = props.getProperty(PROPERTY_ID + id + PROPERTY_DISPLAYNAME);
			log.debug(PROPERTY_ID + id + PROPERTY_USED + ":" + props.getProperty(PROPERTY_ID + id + PROPERTY_USED));
			boolean used = props.getProperty(PROPERTY_ID + id + PROPERTY_USED).trim().equalsIgnoreCase("TRUE");
			boolean translatable = props.getProperty(PROPERTY_ID + id + PROPERTY_TRANSLATABLE).trim().equalsIgnoreCase("TRUE");
			boolean critical = props.getProperty(PROPERTY_ID + id + PROPERTY_CRITICAL).trim().equalsIgnoreCase("TRUE");
			log.debug(id + ", " + used + ", " +oid + ", " +critical+ ", " +translatable +  ", " + displayName);   
			if(used){
				if(oid != null && classPath != null && displayName != null){					
					AvailableCertificateExtension availableCertificateExtension = new AvailableCertificateExtension(id,oid.trim(),displayName.trim(),translatable);
					Class implClass = Class.forName(classPath);
					CertificateExtension certificateExtension = (CertificateExtension) implClass.newInstance();					
					certificateExtension.init(id, oid.trim(), critical, props);                    
					availableCertificateExtensions.add(availableCertificateExtension);
                    certificateExtensions.put(new Integer(id), certificateExtension);

				}else{
					throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.certextmissconfigured",new Integer(id)));
				}
			}
			
		}catch(Exception e){
			throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.certextmissconfigured",new Integer(id)),e);
		}		
	}
	
}
