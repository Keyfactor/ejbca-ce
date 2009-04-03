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
/*
 * This file is part of the QuickServer library 
 * Copyright (C) 2003-2005 QuickServer.org
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the GNU Lesser General Public License. 
 * You should have received a copy of the GNU LGP License along with this 
 * library; if not, you can download a copy from <http://www.quickserver.org/>.
 *
 * For questions, suggestions, bug-reports, enhancement-requests etc.
 * visit http://www.quickserver.org
 *
 */

package org.ejbca.ui.tcp;

import java.io.File;
import java.net.UnknownHostException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;
import org.ejbca.config.CmpConfiguration;
import org.quickserver.net.AppException;
import org.quickserver.net.server.QuickServer;

/**
 * Starts and stops the CMP TCP listener service
 * 
 * @version $Id$
 */
public class CmpTcpServer {

	public static String VER = "1.0";
	
	public static QuickServer myServer = null;
	
	public static void start() throws UnknownHostException	{
		String cmdHandle = org.ejbca.ui.tcp.CmpTcpCommandHandler.class.getName();
		String auth = null;

		myServer = new QuickServer();
		myServer.setClientAuthenticationHandler(auth);
		myServer.setBindAddr(CmpConfiguration.getTCPBindAdress());
		myServer.setPort(CmpConfiguration.getTCPPortNumber());
		myServer.setName("CMP TCP Server v " + VER);
		if(getQuickServerVersion() >= 1.2) {
			System.out.println("Using 1.2 feature");
			myServer.setClientBinaryHandler(cmdHandle);
			myServer.setClientEventHandler(cmdHandle);

			//reduce info to Console
			myServer.setConsoleLoggingToMicro();
		}

		//setup logger to log to file
		Logger logger = null;
		FileHandler txtLog = null;
		String logDir = CmpConfiguration.getTCPLogDir();
		File log = new File(logDir + "/");
		if(!log.canRead()) {
			log.mkdir();
		}
		try	{
			logger = Logger.getLogger("");
			logger.setLevel(Level.FINEST);

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
			System.err.println("Could not create xmlLog FileHandler : "+e);
		}
		//end of logger code

		try	{
			String confFile = CmpConfiguration.getTCPConfigFile();
			if (!StringUtils.isEmpty(confFile)) {
				Object config[] = new Object[] {confFile};
				if (myServer.initService(config) == false) {
					System.out.println("Configuration from config file "+confFile+" failed!");
				}
			}

			myServer.startServer();	
			//myServer.getQSAdminServer().setShellEnable(true);
			//myServer.startQSAdminServer();			
		} catch(AppException e){
			System.out.println("Error in server : "+e);
			e.printStackTrace();
		}
	}

	public static void stop() {
		if (myServer != null) {
			try {
				myServer.stopServer();
			} catch (AppException e) {
				System.out.println("Error in server : "+e);
				e.printStackTrace();
			}			
		}
	}
	public static float getQuickServerVersion() {
		return QuickServer.getVersionNo();
	}
}


