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

package org.ejbca.ui.tcp;

import java.io.File;
import java.net.UnknownHostException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;
import org.ejbca.config.CmpTcpConfiguration;
import org.quickserver.net.AppException;
import org.quickserver.net.server.QuickServer;

/**
 * Starts and stops the CMP TCP listener service
 * 
 * @version $Id$
 */
public class CmpTcpServer {

	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(CmpTcpServer.class);
	private static final String VER = "1.0";

	private transient QuickServer myServer = null;
	
	public void start() throws UnknownHostException	{
		final String cmdHandle = org.ejbca.ui.tcp.CmpTcpCommandHandler.class.getName();

		myServer = new QuickServer();
		myServer.setClientAuthenticationHandler(null);
		myServer.setBindAddr(CmpTcpConfiguration.getTCPBindAdress());
		myServer.setPort(CmpTcpConfiguration.getTCPPortNumber());
		myServer.setName("CMP TCP Server v " + VER);
		if(QuickServer.getVersionNo() >= 1.2) {
			LOG.info("Using 1.2 feature");
			myServer.setClientBinaryHandler(cmdHandle);
			myServer.setClientEventHandler(cmdHandle);

			//reduce info to Console
			myServer.setConsoleLoggingToMicro();
		}

		//setup logger to log to file
		Logger logger = null;
		FileHandler txtLog = null;
		final String logDir = CmpTcpConfiguration.getTCPLogDir();
		final File logFile = new File(logDir + "/");
		if(!logFile.canRead()) {
			logFile.mkdir();
		}
		try	{
			logger = Logger.getLogger("");
			logger.setLevel(Level.INFO);

			logger = Logger.getLogger("cmptcpserver");
			logger.setLevel(Level.FINEST); 
			txtLog = new FileHandler(logDir+"/cmptcpserver.log");
			//reduce info 
			txtLog.setFormatter(new org.quickserver.util.logging.MicroFormatter());
			logger.addHandler(txtLog);

			myServer.setAppLogger(logger); //imp

			//myServer.setConsoleLoggingToMicro();
			myServer.setConsoleLoggingFormatter("org.quickserver.util.logging.SimpleTextFormatter");
			myServer.setConsoleLoggingLevel(Level.INFO);
		} catch(Exception e){
			LOG.error("Could not create xmlLog FileHandler : ", e);
		}
		try	{
			final String confFile = CmpTcpConfiguration.getTCPConfigFile();
			if (!StringUtils.isEmpty(confFile)) {
				final Object config[] = new Object[] {confFile};
				if (!myServer.initService(config)) {
					LOG.error("Configuration from config file "+confFile+" failed!");
				}
			}
			myServer.startServer();	
			//myServer.getQSAdminServer().setShellEnable(true);
			//myServer.startQSAdminServer();			
		} catch(AppException e){
			LOG.error("Error in server : ", e);
		}
	}

	public void stop() {
		if (myServer != null) {
			try {
				myServer.stopService();
				myServer.closeAllPools();
			} catch (AppException e) {
				LOG.error("Error in server : ", e);
			} catch (Exception e) {
				LOG.error("Error in server : ", e);
			}
		}
	}
}


