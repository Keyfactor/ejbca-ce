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

package org.ejbca.config;

import java.io.File;
import java.net.URL;
import java.util.Iterator;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.SystemConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;

/**
 * This is a singleton. Used to configure common-configuration with our sources.
 * 
 * Use like this:
 *   String value = ConfigurationHolder.getString("my.conf.property.key"); or
 *   String value = ConfigurationHolder.getString("my.conf.property.key", "default value");
 * or
 *   String value = ConfigurationHolder.getExpandedString("my.conf.property.key", "default value");
 * to be able to parse values containing ${property}
 * 
 * See in-line comments below for the sources added to the configuration.
 * 
 * @version $Id$
 */
public final class EjbcaConfigurationHolder {

	private static final Logger log = Logger.getLogger(EjbcaConfigurationHolder.class);

	private static CompositeConfiguration config = null;
	private static CompositeConfiguration configBackup = null;
	
	/** This is a singleton so it's not allowed to create an instance explicitly */ 
	private EjbcaConfigurationHolder() {
	    super();
	}
	
	/** ejbca.properties must be first in this file, because CONFIGALLOWEXTERNAL is defined in there. */
	public static final String[] CONFIG_FILES = {"ejbca.properties", "web.properties", "cmptcp.properties",
	    "externalra-caservice.properties", "ocsp.properties", "jaxws.properties", "cache.properties", 
	    "database.properties", "va.properties", "va-publisher.properties"};

	/** Configuration property that enables dynamic reading of properties from the file system. This is not allowed by default for security reasons. */
	public static final String CONFIGALLOWEXTERNAL = "allow.external-dynamic.configuration";

	public static Configuration instance() {
		if (config == null) {
			// read ejbca.properties, from config file built into jar, and see if we allow configuration by external files
			boolean allowexternal = false;
			try {
				final URL url = EjbcaConfigurationHolder.class.getResource("/conf/"+CONFIG_FILES[0]);
				if (url != null) {
					final PropertiesConfiguration pc = new PropertiesConfiguration(url);
					allowexternal = "true".equalsIgnoreCase(pc.getString(CONFIGALLOWEXTERNAL, "false"));
					if (allowexternal) {
					    log.info("Allow external re-configuration: " + allowexternal);
					}
				}
			} catch (ConfigurationException e) {
				log.error("Error intializing configuration: ", e);
			}
			config = new CompositeConfiguration();

			// Only add these config sources if we allow external configuration
			if (allowexternal) {
				// Override with system properties, this is prio 1 if it exists (java -Dscep.test=foo)
				config.addConfiguration(new SystemConfiguration());
				log.info("Added system properties to configuration source (java -Dfoo.prop=bar).");

				// Override with file in "application server home directory"/conf, this is prio 2
				for (int i=0; i<CONFIG_FILES.length; i++) {
					File f = null;
					try {
						f = new File("conf"+File.separator+CONFIG_FILES[i]);
						final PropertiesConfiguration pc = new PropertiesConfiguration(f);
						pc.setReloadingStrategy(new FileChangedReloadingStrategy());
						config.addConfiguration(pc);
						log.info("Added file to configuration source: "+f.getAbsolutePath());
					} catch (ConfigurationException e) {
						log.error("Failed to load configuration from file " + f.getAbsolutePath());
					}
				}
				// Override with file in "/etc/ejbca/conf/, this is prio 3
				for (int i=0; i<CONFIG_FILES.length; i++) {
					File f = null;
					try {
						f = new File("/etc/ejbca/conf/" + CONFIG_FILES[i]);
						final PropertiesConfiguration pc = new PropertiesConfiguration(f);
						pc.setReloadingStrategy(new FileChangedReloadingStrategy());
						config.addConfiguration(pc);
						log.info("Added file to configuration source: "+f.getAbsolutePath());	        		
					} catch (ConfigurationException e) {
						log.error("Failed to load configuration from file " + f.getAbsolutePath());
					}
				}
			} // if (allowexternal)
			
			// Default values build into jar file, this is last prio used if no of the other sources override this
			for (int i=0; i<CONFIG_FILES.length; i++) {
				addConfigurationResource(CONFIG_FILES[i]);
			}
			// Load internal.properties only from built in configuration file
			try {
				final URL url = EjbcaConfigurationHolder.class.getResource("/internal.properties");
				if (url != null) {
					final PropertiesConfiguration pc = new PropertiesConfiguration(url);
					config.addConfiguration(pc);
					log.debug("Added url to configuration source: " + url);
				}
			} catch (ConfigurationException e) {
				log.error("Failed to load configuration from resource internal.properties", e);
			}
		}
		return config;
	}
	
	/** Method used primarily for JUnit testing, where we can add a new properties file (in tmp directory)
	 * to the configuration.
	 * @param filename the full path to the properties file used for configuration.
	 */
	public static void addConfigurationFile(final String filename) {
		// Make sure the basic initialization has been done
		instance();
		File f = null;
		try {
			f = new File(filename);
			final PropertiesConfiguration pc = new PropertiesConfiguration(f);
			pc.setReloadingStrategy(new FileChangedReloadingStrategy());
			config.addConfiguration(pc);
			log.info("Added file to configuration source: "+f.getAbsolutePath());	        		
		} catch (ConfigurationException e) {
			log.error("Failed to load configuration from file " + f.getAbsolutePath());
		}
	}
	
	/**
	 * Add built in config file
	 */
	public static void addConfigurationResource(final String resourcename) {
		// Make sure the basic initialization has been done
		instance();
		try {
			final URL url = EjbcaConfigurationHolder.class.getResource("/conf/" + resourcename);
			if (url != null) {
				final PropertiesConfiguration pc = new PropertiesConfiguration(url);
				config.addConfiguration(pc);
				log.debug("Added url to configuration source: " + url);
			}
		} catch (ConfigurationException e) {
			log.error("Failed to load configuration from resource " + "/conf/" + resourcename, e);
		}
	}
	
    /**
     * @return the configuration as a regular Properties object
     */
    public static Properties getAsProperties() {
        final Properties properties = new Properties();
        @SuppressWarnings("unchecked")
        final Iterator<String> i = instance().getKeys();
        while (i.hasNext()) {
            final String key = (String) i.next();
            properties.setProperty(key, instance().getString(key));
        }
        return properties;
    }

	/**
	 * @param property the property to look for
	 * @param defaultValue default value to use if property is not found
	 * @return String configured for property, or default value, if defaultValue is null and property is not found null is returned.
	 */
	public static String getString(final String property) {
		// Commons configuration interprets ','-separated values as an array of Strings, but we need the whole String for example SubjectDNs.
		String ret = null;
		final StringBuilder str = new StringBuilder();
		String rets[] = instance().getStringArray(property);
        if (rets.length == 0) {
            rets = ConfigurationHolder.getDefaultValueArray(property);
        }
		for (int i=0; i<rets.length; i++) {
			if (i != 0) {
				str.append(',');	
			}
			str.append(rets[i]);
		}
		if (str.length() != 0) {
			ret = str.toString();
        } else {
            ret = ConfigurationHolder.getDefaultValue(property);
        }
		return ret;
	}
	
	/**
	 * Return a the expanded version of a property. E.g.
	 *  property1=foo
	 *  property2=${property1}bar
	 * would return "foobar" for property2
	 * @param defaultValue to use if no property of such a name is found
	 */
	public static String getExpandedString(final String property) {
		String ret = getString(property);
		if (ret != null) {
			while (ret.indexOf("${") != -1) {
				ret = interpolate(ret);
			}
		}
		return ret;
	}
	
	private static String interpolate(final String orderString) {
		final Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
		final Matcher m = PATTERN.matcher(orderString);
		final StringBuffer sb = new StringBuffer(orderString.length());
		m.reset();
		while (m.find()) {
			// when the pattern is ${identifier}, group 0 is 'identifier'
			final String key = m.group(1);
			final String value = getExpandedString(key);
			
			// if the pattern does exists, replace it by its value
			// otherwise keep the pattern ( it is group(0) )
			if (value != null) {
				m.appendReplacement(sb, value);
			} else {
				// I'm doing this to avoid the backreference problem as there will be a $
				// if I replace directly with the group 0 (which is also a pattern)
				m.appendReplacement(sb, "");
				final String unknown = m.group(0);
				sb.append(unknown);
			}
		}
		m.appendTail(sb);
		return sb.toString();
	}

	/**
	 * Backups the original configuration in a non thread safe way.
	 * 
 	 * NOTE: This method should only be used by tests through ConfigurationSessionBean!
	 */
	public static boolean backupConfiguration() {
		if (configBackup != null) {
			return false;
		}
		configBackup = (CompositeConfiguration) config.clone();
		return true;
	}
	
	/**
	 * Restores the original configuration in a non thread safe way.
	 * 
	 * NOTE: This method should only be used by tests through ConfigurationSessionBean!
	 */
	public static boolean restoreConfiguration() {
		if (configBackup == null) {
			return false;
		}
		config = configBackup;
		configBackup = null;
		return true;
	}

	/**
	 * Takes a backup of the active configuration if necessary and updates the active configuration. 
	 * 
	 * NOTE: This method should only be used by tests through ConfigurationSessionBean!
	 */
	public static boolean updateConfiguration(final Properties properties) {
		backupConfiguration();	// Only takes a backup if necessary.
		final Iterator<Object> i = properties.keySet().iterator();
		while (i.hasNext()) {
			final String key = (String) i.next();
			final String value = (String) properties.get(key);
			config.setProperty(key, value);
		}
		return true;
	}

	/**
	 * Takes a backup of the active configuration if necessary and updates the active configuration. 
	 * 
	 * NOTE: This method should only be used by tests through ConfigurationSessionBean!
	 */
	public static boolean updateConfiguration(final String key, final String value) {
		backupConfiguration();	// Only takes a backup if necessary.
		config.setProperty(key, value);
		return true;
	}

}
