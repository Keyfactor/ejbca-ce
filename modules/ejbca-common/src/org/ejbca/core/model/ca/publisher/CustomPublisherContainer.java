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
 
package org.ejbca.core.model.ca.publisher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.ExternalScriptsAllowlist;

import com.keyfactor.util.StringTools;
import com.keyfactor.util.string.StringConfigurationCache;


/**
 * CustomPublisherContainer is a class handling a custom publisher. It is used 
 * to store and retrieve custom publisher configuration to database.
 * 
 */
public class CustomPublisherContainer extends BasePublisher {
    
	private static final long serialVersionUID = -7060678968358301488L;

    private static final Logger log = Logger.getLogger(CustomPublisherContainer.class);
    
    private ICustomPublisher custompublisher = null; 
	
	public static final float LATEST_VERSION = 1;
		
	// Default Values
    
    public static final String CLASSPATH = "classpath";
    protected static final String PROPERTYDATA = "propertydata";
    private static final String PROPERTYDATA_PEERID = "peerId";
		
    public CustomPublisherContainer() {
    	super();
    	data.put(TYPE, PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER);
    	setClassPath("");
    	try {
            setPropertyData("");
        } catch (PublisherException e) {
            throw new IllegalStateException();
        }
    }
    
    /**
     * Copy constructor taking a BasePublisher returning a CustomPublisherContainer based on its values. 
     * @throws PublisherException 
     */
    public CustomPublisherContainer(BasePublisher basePublisher) {
        super(basePublisher);
        data.put(TYPE, PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER);
        setClassPath("");
        try {
            setPropertyData("");
        } catch (PublisherException e) {
            throw new IllegalStateException();
        }
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
     *  Sets the propertyData used to configure this custom publisher without validation.
     */
    public void setPropertyData(String propertyData) throws PublisherException {
        setPropertyData(propertyData, false);
    }

    /**
     *  Sets the propertyData used to configure this custom publisher with validation.
     */
    public void assignPropertyData(String propertyData) throws PublisherException {
        setPropertyData(propertyData, true);
    }

    /**
     *  Sets the propertyData used to configure this custom publisher.
     */
    private void setPropertyData(String propertyData, boolean validate) throws PublisherException {
        final ICustomPublisher publisher = getCustomPublisher();

        if (publisher != null) {
            final Properties properties = buildProperties(propertyData, "Properties could not be loaded.");
            final Set<String> propertyNames = properties.keySet().stream().map(Object::toString).collect(Collectors.toSet());

            final Set<String> unsupportedProperties = filterUnsupportedProperties(publisher.getDeclaredPropertyNames(), propertyNames);
            if (!unsupportedProperties.isEmpty()) {
                throw new PublisherException("Unsupported properties: " + String.join(", ", unsupportedProperties));
            }

            if (isCustomUiRenderingSupported()) {
                final StringBuilder rawPropertyData = new StringBuilder();

                for (String propertyName : propertyNames) {
                    final int propertyType = ((CustomPublisherUiSupport) publisher).getPropertyType(propertyName);
                    final String propertyValue = properties.getProperty(propertyName);
                    final String value = parsePropertyValue(propertyType, propertyName, propertyValue);

                    if (validate) {
                        validateProperty(propertyName, propertyValue);
                    }

                    rawPropertyData.append(propertyName).append("=").append(value).append("\n");
                }

                data.put(PROPERTYDATA, rawPropertyData.toString());
                return;
            }
        }

        data.put(PROPERTYDATA, propertyData);
    }

    private static Properties buildProperties(String propertyData, String errorMessage) {
        Properties properties = new Properties();
        if (propertyData != null) try {
            properties.load(new ByteArrayInputStream(propertyData.getBytes()));
        } catch (IOException e) {
            throw new IllegalArgumentException(errorMessage, e);
        }
        return properties;
    }

    private String parsePropertyValue(int propertyType, String propertyName, String propertyValue) throws PublisherException {
        if (propertyType == CustomPublisherProperty.UI_TEXTINPUT_PASSWORD) {
            //Property is of a type that shouldn't be written in clear text to disk. Encrypt!
            final char[] encryptionKey = StringConfigurationCache.INSTANCE.getEncryptionKey();
            return StringTools.pbeEncryptStringWithSha256Aes192(propertyValue, encryptionKey, StringConfigurationCache.INSTANCE.useLegacyEncryption());

        } else if ((propertyType == CustomPublisherProperty.UI_TEXTINPUT) && "dataSource".equals(propertyName)) {
            validateDataSource(propertyValue);
            return propertyValue;

        } else {
            return propertyValue;
        }
    }

    public void validateProperty(String name, String value) throws PublisherException {
        ICustomPublisher customPublisher = getCustomPublisher();
        if (customPublisher != null) customPublisher.validateProperty(name, value);
    }

    public boolean isCustomAccessRulesSupported() {
	    return getCustomPublisher() instanceof CustomPublisherAccessRulesSupport;
	}
	
    public boolean isAuthorizedToPublisher(AuthenticationToken authenticationToken) {
        if (getCustomPublisher() instanceof CustomPublisherAccessRulesSupport) {
            return ((CustomPublisherAccessRulesSupport)getCustomPublisher()).isAuthorizedToPublisher(authenticationToken);
        }
        return true;
    }

    public boolean isCustomUiRenderingSupported() {
	    return getCustomPublisher() instanceof CustomPublisherUiSupport;
	}
    public List<CustomPublisherProperty> getCustomUiPropertyList(final AuthenticationToken authenticationToken) {
        if (getCustomPublisher() instanceof CustomPublisherUiSupport) {
            return ((CustomPublisherUiSupport)getCustomPublisher()).getCustomUiPropertyList(authenticationToken);
        }
        return new ArrayList<>();
    }
    
    private List<String> getCustomUiPropertyNames() {
        if (getCustomPublisher() instanceof CustomPublisherUiSupport) {
            return ((CustomPublisherUiSupport)getCustomPublisher()).getCustomUiPropertyNames();
        }
        return new ArrayList<>();
    }
	
    public Properties getProperties() {
        final String propertyData = getPropertyData();
        // Re-Factor: Here the strings are escaped: \\ -> \; \n -> new line, etc.
        final Properties properties = buildProperties(propertyData, "Could not retrieve properties from database");

        /*
         * The below code is only to be able to handle the change of our EnterpriseValidationAuthorityPublisher from
         * built in to custom type.
         * 
         * Since the built in type had its properties in XML we need to provide a one time upgrade path.
         * The old settings will still be present in the XML, but can be removed in a future version with a
         * deterministic upgrade gate version to ensure that all installation data looks the same.
         * 
         * Note that for example get/setDescription belongs to the BasePublisher and not the ICustomPublisher instance.
         * This is just one of many small things that needs to be corrected in a major version rewrite.
         */
        for (final String key : getCustomUiPropertyNames()) {
            if (!properties.containsKey(key) && data.get(key)!=null) {
                // If this is a publisher that used to have it's specific properties in the "data", we need to provide an upgrade conversion path ONCE
                properties.setProperty(key, String.valueOf(data.get(key)));
            }
        }
		return properties;
	}
    
    public void setProperties(final Properties properties) throws PublisherException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            properties.store(baos, null);
            setPropertyData(baos.toString("8859_1")); // the properties are stored as ISO-8859-1
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode properties", e);
        }
    }

    public String getPeerId() {
	    return Optional.ofNullable(getProperties().getProperty(PROPERTYDATA_PEERID))
                       .orElse("");
    }
  
	@Override
	public boolean isFullEntityPublishingSupported() {
	    return getCustomPublisher() instanceof FullEntityPublisher
	            && ((FullEntityPublisher)getCustomPublisher()).isFullEntityPublishingSupported();
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
    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        return this.getCustomPublisher().storeCertificate(admin, incert, username, password, userDN, cafp, status, type, revocationDate,
                revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation);
    }
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	@Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException{
		return this.getCustomPublisher().storeCRL(admin,incrl,cafp,number,userDN);		
	}
	
	/**
	 * @throws PublisherConnectionException if the destination couldn't be connected to
	 * @throws FatalPublisherConnectionException if this CA is unable to publish to internal errors.
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	@Override
	public void testConnection() throws PublisherConnectionException, FatalPublisherConnectionException {
	    if (this.getCustomPublisher() == null) {
	        throw new FatalPublisherConnectionException("Custom Publisher is null. Initialization may have failed due to faulty configuration.");
	    }
        this.getCustomPublisher().testConnection();
	} 

	/**
	 * The ICustomPublisher is the custom implementation used for the actual publishing work.
	 * 
	 * Note that this class can only be queried about its specific settings (and not common base settings like
	 * publisher description or queue settings).
	 * 
	 * @return the custom publisher wrapped by this class, null if none is defined. 
	 */
	public ICustomPublisher getCustomPublisher() {
		if(custompublisher == null){
		    final String classPath = getClassPath();
		    if (classPath==null || classPath.isEmpty()) {
		        return null;
		    }
			try{
				@SuppressWarnings("unchecked")
                Class<? extends ICustomPublisher> implClass = (Class<? extends ICustomPublisher>) Class.forName( classPath );
				this.custompublisher =  implClass.getDeclaredConstructor().newInstance();
				this.custompublisher.init(getProperties());				
            } catch (ClassNotFoundException e) {
                // Probably means that we have not built in our custom publisher here in EJBCA, or it's an Enterprise only 
                // publisher configured (Peer publisher for example)
                log.info("Publisher class "+classPath+" is not available in this version/build of EJBCA.");
                return null;
            } catch (NumberFormatException e) {
                log.error("Publisher configured incorrectly, a number in configuration contains illegal characters.");
                return null;
            } catch (ReflectiveOperationException iae) {
                Throwable throwable = iae instanceof InvocationTargetException
                        ? ((InvocationTargetException) iae).getTargetException()
                        : iae;
                throw new IllegalStateException(throwable);
            } 
		}
		
		return custompublisher;
	}
		
	/** 
	 * @throws PublisherException 
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone()
	 */
	@Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public Object clone() throws CloneNotSupportedException {
		CustomPublisherContainer clone = new CustomPublisherContainer();
        HashMap clonedata = (HashMap) clone.saveData();

		for (Object key: data.keySet()) {
            clonedata.put(key, data.get(key));
        }

		clone.loadData(clonedata);
		return clone;	
		}

	/* *
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
	 */
	@Override
    public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	/**
	 * Resets the current custom publisher
	 * @see org.ejbca.core.model.UpgradeableDataHashMap#saveData()
	 */
	@Override
    public Object saveData() {
		this.custompublisher = null;
		return super.saveData();
	}

    @Override
    public boolean willPublishCertificate(int status, long revocationDate) {
        return getCustomPublisher().willPublishCertificate(status, revocationDate);
    }

    @Override
    public void validateDataSource(String dataSource) throws PublisherException {
        if (StringUtils.isNotBlank(dataSource)) {
            final Pattern dataSourcePattern = Pattern.compile("^(java):/.*$");
            final Matcher dataSrouceMatcher = dataSourcePattern.matcher(dataSource);
            if (dataSrouceMatcher.find()) {
                return;
            }
        }
        throw new PublisherException("Invalid data source!");
    }

    @Override
    public boolean storeOcspResponseData(OcspResponseData ocspResponseData) throws PublisherException {
        return this.getCustomPublisher().storeOcspResponseData(ocspResponseData);
    }

    @Override
    public boolean isCallingExternalScript() {
        // Must be overridden, or we may get a loop
        return getCustomPublisher().isCallingExternalScript();
    }
    @Override
    public void setExternalScriptsAllowlist(ExternalScriptsAllowlist allowList) {
        // Must be overridden, or we may get a loop
        getCustomPublisher().setExternalScriptsAllowlist(allowList);
    }
    
    /**
     * Filters for unsupported properties (not declared in #getDeclaredPropertyNames()).
     *  
     * @param declaredPropertyNames the declared property names.
     * @param properties the property names to be validated.
     * @return a set of all unsupported properties or an empty set.
     */
    // Static deterministic method made public for unit test.
    public static Set<String> filterUnsupportedProperties(final Set<String> declaredPropertyNames, final Set<String> properties) {
        final Set<String> result = new TreeSet<>();
        for (String property : properties) {
            boolean found = false;
            for (String dproperty : declaredPropertyNames) {
                if (dproperty.contains("*")) {
                    String tmp = property.replace(dproperty.substring(0, dproperty.indexOf("*")), "");
                    if (tmp.length() == property.length()) {
                        continue;
                    }
                    Long id = null;
                    try {
                        id = Long.valueOf(tmp.replace(dproperty.substring(dproperty.indexOf("*") + 1, dproperty.length()), ""));
                    } catch(NumberFormatException e) {
                        log.warn("Failed to parse ID by publisher properties: " + e.getMessage());
                        continue;
                    }
                    if (id != null) {
                        found = true;
                        break;
                    }
                } else {
                    if (property.equals(dproperty)) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                result.add(property);
            }
        }
        return result;
    } 

}
