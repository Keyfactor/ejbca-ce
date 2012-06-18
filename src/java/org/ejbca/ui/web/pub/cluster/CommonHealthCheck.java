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

package org.ejbca.ui.web.pub.cluster;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;

/** Base class for health checkers with functionality that is common to at least
 * both EJBCA and External OCSP.
 * 
 * @version $Id$
 */
public abstract class CommonHealthCheck implements IHealthCheck {
	private static final Logger log = Logger.getLogger(CommonHealthCheck.class);

	private final long minfreememory = EjbcaConfiguration.getHealthCheckAmountFreeMem();
	private final String maintenanceFile = EjbcaConfiguration.getHealthCheckMaintenanceFile();
	private final String maintenancePropertyName = EjbcaConfiguration.getHealthCheckMaintenancePropertyName();

	public CommonHealthCheck() {
		super();
	}
	
	public abstract String checkHealth(HttpServletRequest request);

	public void init() {
		initMaintenanceFile();
	}

	protected void checkMemory(final StringBuilder sb) {
	    if (log.isDebugEnabled()) {
	        log.debug("Checking JVM memory.");
	    }
	    if (minfreememory >= Runtime.getRuntime().freeMemory()) {
	        sb.append("\nMEM: Error Virtual Memory is about to run out, currently free memory :").append(String.valueOf(Runtime.getRuntime().freeMemory()));	
	    }		
	}

	protected void checkMaintenance(final StringBuilder sb) {
		if (StringUtils.isEmpty(maintenanceFile)) {
            if (log.isDebugEnabled()) {
                log.debug("Maintenance file not specified, node will be monitored");
            }
			return;
		} 
		InputStream in = null;
		try {
			in = new FileInputStream(maintenanceFile);
	        final Properties maintenanceProperties = new Properties();
			maintenanceProperties.load(in);
            final String maintenancePropertyValue = maintenanceProperties.getProperty(maintenancePropertyName);
            if (maintenancePropertyValue == null) {
                log.info("Could not find property " + maintenancePropertyName+ " in " + maintenanceFile+ ", will continue to monitor this node");
            } else if (Boolean.TRUE.toString().equalsIgnoreCase(maintenancePropertyValue)) {
                sb.append("MAINT: ").append(maintenancePropertyName);
            }
		} catch (IOException e) {
	        if (log.isDebugEnabled()) {
	            log.debug("Could not read Maintenance File. Expected to find file at: "+ maintenanceFile);
	        }
			return;
		} finally {
			if (in != null) {
				try {
					in.close();					
				} catch (IOException e) {
					log.error("Error closing file: ", e);
				}
			}
		}
	}
	
	private void initMaintenanceFile() {
		if (StringUtils.isEmpty(maintenanceFile)) {
			log.debug("Maintenance file not specified, node will be monitored");
		} else {
			Properties maintenanceProperties = new Properties();
			InputStream in = null;
			try {
				in = new FileInputStream(maintenanceFile);
				maintenanceProperties.load(in);
			} catch (IOException e) {
				log.debug("Could not read Maintenance File. Expected to find file at: "+ maintenanceFile);
				OutputStream out = null;
				try {
					out = new FileOutputStream("filename.properties");
					maintenanceProperties.store(out, null);
				} catch (IOException e2) {
					log.error("Could not create Maintenance File at: "+ maintenanceFile);
				} finally {
					if (out != null) {
						try {
							out.close();					
						} catch (IOException oe) {
							log.error("Error closing file: ", e);
						}
					}
				}
			} finally {
				if (in != null) {
					try {
						in.close();					
					} catch (IOException e) {
						log.error("Error closing file: ", e);
					}
				}
			}
		}
	}

}