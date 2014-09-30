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

package org.ejbca.core.protocol.ws.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;


/**
 * Logs a custom log entry in EJBCA log.
 *
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class CustomLogCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


	private static final int ARG_LEVEL           = 1;
	private static final int ARG_TYPE            = 2;
	private static final int ARG_MSG             = 3;
	private static final int ARG_CANAME          = 4;
	private static final int ARG_USERNAME        = 5;
	private static final int ARG_CERT            = 6;

	/**
	 * Creates a new instance Command
	 *
	 * @param args command line arguments
	 */
	public CustomLogCommand(String[] args) {
		super(args);
	}

	/**
	 * Runs the command
	 *
	 * @throws IllegalAdminCommandException Error in command args
	 * @throws ErrorAdminCommandException Error running command
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {

		try {   
			if(args.length < 6 || args.length > 7){
				getPrintStream().println("Number of arguments: "+args.length);
				usage();
				System.exit(-1); // NOPMD, this is not a JEE app
			}

			String level = args[ARG_LEVEL];
			String type = args[ARG_TYPE];
			String caname = args[ARG_CANAME];
			String username = args[ARG_USERNAME];
			String certfile = args[ARG_CERT];
			String msg = args[ARG_MSG];

			int logLevel = IEjbcaWS.CUSTOMLOG_LEVEL_INFO;
			if (StringUtils.equalsIgnoreCase(level, "error")) {
				logLevel = IEjbcaWS.CUSTOMLOG_LEVEL_ERROR;
			}
			if (StringUtils.equalsIgnoreCase(caname, "null")) {
				caname = null;
			}
			if (StringUtils.equalsIgnoreCase(username, "null")) {
				username = null;
			}
			getPrintStream().println("Custom log level: "+(logLevel == IEjbcaWS.CUSTOMLOG_LEVEL_ERROR ? "ERROR" : "INFO"));
			getPrintStream().println("Custom log type: "+type);
			getPrintStream().println("Custom log message: "+msg);
			getPrintStream().println("CA name: "+caname);
			getPrintStream().println("Username: "+username);
			getPrintStream().println("Certificate file: "+certfile);

			CryptoProviderTools.installBCProvider();

			Certificate incert = null;
			org.ejbca.core.protocol.ws.client.gen.Certificate logcert = null;
			if (!StringUtils.equalsIgnoreCase(certfile, "null")) {
				try {
					FileInputStream in = new FileInputStream(certfile);
					Collection<Certificate> certs = CertTools.getCertsFromPEM(in);
					Iterator<Certificate> iter = certs.iterator();
					if (iter.hasNext()) {
						incert = iter.next();
					}
				} catch (IOException e) {
					// It was perhaps not a PEM chain...see if it was a single binary CVC certificate
					byte[] bytes = FileTools.readFiletoBuffer(certfile);
					incert = CertTools.getCertfromByteArray(bytes); // check if it is a good cert, decode PEM if it is PEM, etc
				}				
				getPrintStream().println("Using certificate with subjectDN '"+CertTools.getSubjectDN(incert)+"', and issuerDN '"+CertTools.getIssuerDN(incert)+"'.");
				logcert = new org.ejbca.core.protocol.ws.client.gen.Certificate(incert);
			}

			getEjbcaRAWS().customLog(logLevel, type, caname, username, logcert, msg);
		} catch (Exception e) {
			if (e instanceof EjbcaException_Exception) {
				EjbcaException_Exception e1 = (EjbcaException_Exception)e;
				getPrintStream().println("Error code is: "+e1.getFaultInfo().getErrorCode().getInternalErrorCode());
			}
			throw new ErrorAdminCommandException(e);
		}
	}

	protected void usage() {
		getPrintStream().println("Command used to log a custom log row in the EJBCA log.");
		getPrintStream().println("Usage : customlog logLevel logType logMsg caName username certificate\n\n");
		getPrintStream().println("level: log level of the event, INFO or ERROR");
		getPrintStream().println("type: user defined string used as a prefix in the log comment");
		getPrintStream().println("msg: message data used in the log comment. The log comment will have a syntax of 'type : msg'");
		getPrintStream().println("caName: of the ca related to the event, use null if no specific CA is related. Then will the ca of the administrator be used.");
		getPrintStream().println("username of the related user, use null if no related user exists.");
		getPrintStream().println("certificate: file path to the certificate that relates to the log event, use null if no certificate is related");
	}


}
