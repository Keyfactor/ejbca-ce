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
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.certextensions.standard.AuthorityInformationAccess;
import org.ejbca.core.model.ca.certextensions.standard.AuthorityKeyIdentifier;
import org.ejbca.core.model.ca.certextensions.standard.BasicConstraint;
import org.ejbca.core.model.ca.certextensions.standard.CertificatePolicies;
import org.ejbca.core.model.ca.certextensions.standard.CrlDistributionPoints;
import org.ejbca.core.model.ca.certextensions.standard.ExtendedKeyUsage;
import org.ejbca.core.model.ca.certextensions.standard.FreshestCrl;
import org.ejbca.core.model.ca.certextensions.standard.KeyUsage;
import org.ejbca.core.model.ca.certextensions.standard.MsTemplate;
import org.ejbca.core.model.ca.certextensions.standard.OcspNoCheck;
import org.ejbca.core.model.ca.certextensions.standard.PrivateKeyUsagePeriod;
import org.ejbca.core.model.ca.certextensions.standard.QcStatement;
import org.ejbca.core.model.ca.certextensions.standard.SeisCardNumber;
import org.ejbca.core.model.ca.certextensions.standard.StandardCertificateExtension;
import org.ejbca.core.model.ca.certextensions.standard.SubjectAltNames;
import org.ejbca.core.model.ca.certextensions.standard.SubjectDirectoryAttributes;
import org.ejbca.core.model.ca.certextensions.standard.SubjectKeyIdentifier;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.util.CertTools;

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
 * @version $Id$
 */

public class CertificateExtensionFactory {

	private static final Logger log = Logger.getLogger(CertificateExtensionFactory.class);
	private static final InternalResources intres = InternalResources.getInstance();
	
	private static CertificateExtensionFactory instance = null;
	
	private static String PROPERTY_ID           = "id";
	private static String PROPERTY_OID          = ".oid";
	private static String PROPERTY_CLASSPATH    = ".classpath";
	private static String PROPERTY_DISPLAYNAME  = ".displayname";
	private static String PROPERTY_USED         = ".used";
	private static String PROPERTY_TRANSLATABLE = ".translatable";
	private static String PROPERTY_CRITICAL     = ".critical";
	
	private ArrayList<AvailableCertificateExtension> availableCertificateExtensions = new ArrayList<AvailableCertificateExtension>();
	private HashMap<Integer, CertificateExtension> certificateExtensions = new HashMap<Integer, CertificateExtension>();
	private HashMap<String, String> standardCertificateExtensions = new HashMap<String, String>();
	{
		standardCertificateExtensions.put(X509Extensions.BasicConstraints.getId(), BasicConstraint.class.getName());
		standardCertificateExtensions.put(X509Extensions.SubjectKeyIdentifier.getId(), SubjectKeyIdentifier.class.getName());
		standardCertificateExtensions.put(X509Extensions.AuthorityKeyIdentifier.getId(), AuthorityKeyIdentifier.class.getName());
		standardCertificateExtensions.put(X509Extensions.KeyUsage.getId(), KeyUsage.class.getName());
		standardCertificateExtensions.put(X509Extensions.ExtendedKeyUsage.getId(), ExtendedKeyUsage.class.getName());
		standardCertificateExtensions.put(X509Extensions.SubjectAlternativeName.getId(), SubjectAltNames.class.getName());
		standardCertificateExtensions.put(X509Extensions.CRLDistributionPoints.getId(), CrlDistributionPoints.class.getName());
		standardCertificateExtensions.put(X509Extensions.FreshestCRL.getId(), FreshestCrl.class.getName());
		standardCertificateExtensions.put(X509Extensions.CertificatePolicies.getId(), CertificatePolicies.class.getName());
		standardCertificateExtensions.put(X509Extensions.SubjectDirectoryAttributes.getId(), SubjectDirectoryAttributes.class.getName());
		standardCertificateExtensions.put(X509Extensions.AuthorityInfoAccess.getId(), AuthorityInformationAccess.class.getName());
		standardCertificateExtensions.put(X509Extensions.QCStatements.getId(), QcStatement.class.getName());
		standardCertificateExtensions.put(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId(), OcspNoCheck.class.getName());
		standardCertificateExtensions.put(CertTools.OID_MSTEMPLATE, MsTemplate.class.getName());
		standardCertificateExtensions.put(SeisCardNumber.OID_CARDNUMBER, SeisCardNumber.class.getName());
		standardCertificateExtensions.put(X509Extensions.PrivateKeyUsagePeriod.getId(), PrivateKeyUsagePeriod.class.getName());
	}
	
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
	public List<AvailableCertificateExtension> getAvailableCertificateExtensions(){				
		return availableCertificateExtensions;
	}
	
	/**
	 * Method returning the instance of the CertificateExtension
	 * given its Id
	 * 
	 * @returns null if the CertificateExtension doesn't exist
	 */
	public CertificateExtension getCertificateExtensions(Integer id){
		CertificateExtension ret = (CertificateExtension) certificateExtensions.get(id);
		if (ret == null) {
			log.error(intres.getLocalizedMessage("certext.noextensionforid", id));			
		}
		return ret;
	}

	/**
	 * Method returning the instance of the standard CertificateExtension
	 * given its object identifier
	 * 
	 * @returns null if the CertificateExtension doesn't exist
	 */
	public CertificateExtension getStandardCertificateExtension(String oid, CertificateProfile certProf){
		StandardCertificateExtension ret = null;
		String classPath = (String)standardCertificateExtensions.get(oid);
		if (classPath != null) {
			try {
				Class<?> implClass = Class.forName(classPath);
				ret = (StandardCertificateExtension)implClass.newInstance();					
				ret.init(certProf);                    
			} catch (ClassNotFoundException e) {
				log.error(intres.getLocalizedMessage("certext.noextensionforid", oid), e);			
			} catch (InstantiationException e) {
				log.error(intres.getLocalizedMessage("certext.noextensionforid", oid), e);			
			} catch (IllegalAccessException e) {
				log.error(intres.getLocalizedMessage("certext.noextensionforid", oid), e);			
			}			
		}
		if (ret == null) {
			log.error(intres.getLocalizedMessage("certext.noextensionforid", oid));			
		}
		return ret;
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
					if (is != null) {
						is.close();
					}
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
					Class<?> implClass = Class.forName(classPath);
					CertificateExtension certificateExtension = (CertificateExtension) implClass.newInstance();					
					certificateExtension.init(id, oid.trim(), critical, props);                    
					availableCertificateExtensions.add(availableCertificateExtension);
                    certificateExtensions.put(Integer.valueOf(id), certificateExtension);

				}else{
					throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.certextmissconfigured",Integer.valueOf(id)));
				}
			}
			
		}catch(Exception e){
			throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.certextmissconfigured",Integer.valueOf(id)),e);
		}		
	}
	
}
