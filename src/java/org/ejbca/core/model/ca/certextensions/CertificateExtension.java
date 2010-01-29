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

import java.security.PublicKey;
import java.util.Iterator;
import java.util.Properties;

import org.bouncycastle.asn1.DEREncodable;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * Base class for a certificate extension.
 * All extensions should inherit this class.
 * 
 * The methods that need implementation is getValue
 * 
 * 
 * @author Philip Vendil 2007 jan 5
 *
 * @version $Id$
 */

public abstract class CertificateExtension {
	
	private int id;
	private String oID;
	private boolean criticalFlag;
	private Properties properties;
	
	/**
	 * Constuctor for creating a Certificate Extension. 
	 */
	public CertificateExtension() {
		super();
	}

	/**
	 * @return the unique id of the extension
	 */
	public int getId() {
		return id;
	}

	/**
	 * @return The unique OID of the extension
	 */
	public String getOID() {
		return oID;
	}
	
	/**
	 * @param The unique OID of the extension
	 */
	public void setOID(String oID) {
		this.oID = oID;
	}
	
	/**
	 * @return flag indicating if the extension should be marked as critical or not.
	 */
	public boolean isCriticalFlag() {
		return criticalFlag;
	}

	/**
	 * @param flag indicating if the extension should be marked as critical or not.
	 */
	public void setCriticalFlag(boolean criticalFlag) {
		this.criticalFlag = criticalFlag;
	}

	/**
	 * The propertes configured for this extension. The properties are stripped
	 * of the beginning "idX.property.". Soo searching for the property
	 * "id1.property.value" only the key "value" should be used in the returned property.
	 * 
	 * @return the properties configured for this certificate extension.
	 */
	protected Properties getProperties() {
		return properties;
	}
	
	/**
	 * Method that initialises the CertificateExtension
	 * 
	 * @param id, the uniqueID of the extension
	 * @param oID, the OID 
	 * @param criticalFlag if the extension should be marked as critical or not. 
	 * @param config the complete configuration property file. The init method
	 * parses it's own propery file and creates a propertary property file.
	 */
	public void init(int id, String oID, boolean criticalFlag, Properties config){
		this.id = id;
		this.oID = oID;
		this.criticalFlag = criticalFlag;
	
		this.properties = new Properties();
		Iterator keyIter = config.keySet().iterator();
		String matchString = "id" + id + ".property."; 
		while(keyIter.hasNext()){
			String nextKey = (String) keyIter.next();
			if(nextKey.startsWith(matchString)){
				if(nextKey.length() > matchString.length()){
				  properties.put(nextKey.substring(matchString.length()), config.get(nextKey));				  
				}
			}			
		}		
	}
	
	/**
	 * Method that should return the DEREncodable value used in the extension
	 * this is the method at all implementors must implement.
	 * 
	 * @param userData the userdata of the issued certificate.
	 * @param ca the CA data with access to all the keys etc
	 * @param certProfile the certificate profile
	 * @param userPublicKey public key of the user, or null if not available
	 * @return a DEREncodable or null, if this extension should not be used, which was determined from the values somehow.
	 * @throws CertificateExtensionException TODO
	 */
	public abstract DEREncodable getValue(UserDataVO userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException;

	
}
