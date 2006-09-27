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
package org.ejbca.ui.tcp;
/*************************************************************************
 *                                                                       *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
import java.util.Properties;

import org.apache.commons.lang.StringUtils;

/**
 * A singleton holding configuration information about the CMP TCP service
 * 
 * @author tomas
 * @version $Id: CmpTcpConfiguration.java,v 1.1 2006-09-27 15:33:24 anatom Exp $
 */
public class CmpTcpConfiguration {

	/** Singleton instance */
	private static CmpTcpConfiguration config = null;
	
	/** Variable holding the properties configuration */
	private Properties prop = null;
	
	private static final int DEFAULT_PORT = 829;
	private static final String DEFAULT_BIND_HOST="0.0.0.0";
	private static final String DEFAULT_LOG_DIR="./log";
	private static final String DEFAULT_CONF_FILE="";
	
	private CmpTcpConfiguration() {
	}
	
	public static CmpTcpConfiguration instance() {
		if (config == null) {
			config = new CmpTcpConfiguration();
		}
		return config;
	}
	
	public void init(Properties prop) {
		this.prop = prop;
	}
	
	public int getPort() {
		int ret = DEFAULT_PORT;
		String str = prop.getProperty("portNo");
		if (StringUtils.isNotEmpty(str)) {
			ret = Integer.valueOf(str).intValue();
		}
		return ret;
	}
	public String getLogDir() {
		String ret = DEFAULT_LOG_DIR;
		String str = prop.getProperty("logDir");
		if (StringUtils.isNotEmpty(str)) {
			ret = str;
		}
		return ret;		
	}
	public String getConfFile() {
		String ret = DEFAULT_CONF_FILE;
		String str = prop.getProperty("confFile");
		if (StringUtils.isNotEmpty(str)) {
			ret = str;
		}
		return ret;		
	}

	public String getBindHost() {
		String ret = DEFAULT_BIND_HOST;
		String str = prop.getProperty("bindHost");
		if (StringUtils.isNotEmpty(str)) {
			ret = str;
		}
		return ret;
	}
	public Properties getProperties() {
		return prop;
	}
}
