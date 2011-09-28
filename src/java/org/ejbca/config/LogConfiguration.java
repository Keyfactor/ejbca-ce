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

package org.ejbca.config;

import java.util.HashMap;
import java.util.Map;

/**
 * This file handles configuration from log.properties
 */
public class LogConfiguration {
	
	private static Map<String, String> logDeviceMap = null;
	
	/**
	 * Get used log devices and initialize configuration
	 */
	public static synchronized Map<String, String> getUsedLogDevices() {
		if (logDeviceMap == null) {
			logDeviceMap = new HashMap<String, String>();
			String[] logDevicesList = EjbcaConfigurationHolder.getString("usedLogDevices").split(";");
			for (int i=0; i<logDevicesList.length; i++) {
				String name = logDevicesList[i];
				String[] logDeviceStrings = null;
				if ("DummyLogDevice".equalsIgnoreCase(name)) {
					logDeviceStrings = EjbcaConfigurationHolder.getString(name).split(";");
				} else if ("Log4jLogDevice".equalsIgnoreCase(name)) {
					logDeviceStrings = EjbcaConfigurationHolder.getString(name).split(";");
				} else if ("OldLogDevice".equalsIgnoreCase(name)) {
					logDeviceStrings = EjbcaConfigurationHolder.getString(name).split(";");
				} else {
					logDeviceStrings = EjbcaConfigurationHolder.getString(name).split(";");
				}
				if (logDeviceStrings != null && logDeviceStrings.length>0) {
					logDeviceMap.put(name, logDeviceStrings[0].trim());
					if (logDeviceStrings.length>1 && logDeviceStrings[1] != null && logDeviceStrings[1].length() > 0) {
						EjbcaConfigurationHolder.addConfigurationResource(logDeviceStrings[1].trim());
					}
				}
			}
		}
		return logDeviceMap;
	}
	
}
