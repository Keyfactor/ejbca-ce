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
package org.ejbca.ui.cli.dbmanager;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Iterator;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * Used to parse commands with information from the EJBCA configuration.
 * @author Lars Silven PrimeKey Solution AB
 * @version $Id$
 *
 */
class DataBaseConfig {
	final private Properties dbProps;
	final private String propertiesFile;
	final private URI uri;
	final String dbName;
	/**
	 * Loads properties from the database properties of EJBCA.
	 * @param ejbcaHome the root directory of the EJBCA
	 * @throws IOException
	 */
	DataBaseConfig(String ejbcaHome, boolean isVA) throws IOException {
		final String vaPrefix = isVA?"ocsp-":"";
		this.propertiesFile = ejbcaHome+"/conf/"+(isVA?"va-publisher":"database")+".properties";
		this.dbProps = new Properties();
		try {
			this.dbProps.load(new FileInputStream(this.propertiesFile));
		} catch (FileNotFoundException e1) {
			System.out.println("File '"+this.propertiesFile+"' is not existing.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		this.dbName = getValue(vaPrefix+"database.name", "mysql");
		this.uri = getURI(vaPrefix+"database.url");
	}
	private String getValue(String key, String defaultValue) {
		final String value = this.dbProps.getProperty(key);
		if ( value==null && defaultValue==null ) {
			System.out.println("no key ("+key+") in properties file "+this.propertiesFile);
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		if ( value==null ) {
			return defaultValue;
		}
		return value;
	}
	private URI getURI(String keyName) {
		String sUrl = getValue(keyName, null);
		sUrl = sUrl.replaceFirst("^[a-zA-Z:]*:@", "thin://");
		while ( sUrl.indexOf(":")<sUrl.indexOf("://") ) {
			sUrl = sUrl.replaceFirst("^[a-zA-Z]*:", "");
		}
		System.err.println("URI: "+sUrl);
		try {
			final URI _uri = new URI(sUrl);
			if ( _uri.getPath()!=null && _uri.getHost()!=null ) {
				return _uri;
			}
			if ( _uri.getScheme().toLowerCase().indexOf("sqlserver")>=0 ) {
				sUrl = sUrl.replaceFirst(";DatabaseName=", "/");
			} else if ( _uri.getScheme().toLowerCase().indexOf("oracle")>=0 ) {
				sUrl = sUrl.replaceFirst(";SID=", "/");
			} else if ( _uri.getScheme().toLowerCase().indexOf("thin")>=0 ) {
				final int ix = sUrl.lastIndexOf(':');
				sUrl=sUrl.substring(0, ix)+"/"+sUrl.substring(ix+1, sUrl.length());
			}
			System.err.println("URI: "+sUrl);
			return new URI(sUrl);
		} catch (URISyntaxException e) {
			System.err.println("URL '"+sUrl+"' not valid.");
			System.exit(-1); // NOPMD, it's not a JEE app
			return null;
		}
	}
	/**
	 * Parsing of command lines. ${key} is substituted with information from database.properties in the EJBCA configuration directory.
	 * @param original The source.
	 * @param password Password to be used if needed.
	 * @return The parsed string.
	 */
	String parseCommandline(String original, String password) {
		final Iterator<Object> i = this.dbProps.keySet().iterator();
		String result = original;
		while ( i.hasNext() ) {
			final String key = (String)i.next();
			final String value = this.dbProps.getProperty(key);
			result = replace(key, value, result);
		}
		result = replace("url.port", Integer.toString(this.uri.getPort()), result);
		result = replace("url.host", this.uri.getHost(), result);
		result = replace("url.path", this.uri.getPath().replaceFirst("^/", ""), result);
		result = replace("url.authority", this.uri.getAuthority(), result);
		result = replace("url.fragment", this.uri.getFragment(), result);
		result = replace("url.query", this.uri.getQuery(), result);
		result = replace("url.scheme", this.uri.getScheme(), result);
		result = replace("url.userinfo", this.uri.getUserInfo(), result);

		result = replace("password", password, result);
		return result;
	}
	private String replace(final String key, final String value, final String original) {
		if ( value==null ) {
			return original;
		}
//		System.err.println("key: '"+key+"' value: '"+value+"' original: '"+original+"'.");
		return original.replaceAll( Pattern.quote("${"+key+"}"), value);
	}
}
