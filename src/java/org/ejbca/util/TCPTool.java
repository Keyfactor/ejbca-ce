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
package org.ejbca.util;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPException;

/**
 * @author johan
 * @version $Id$
 */
public class TCPTool {
    private static final Logger log = Logger.getLogger(TCPTool.class);

	/**
	 * Probe a TCP port connection at hostname:port.  
	 * @param timeout in milliseconds
	 * @throws LDAPException if the connection fails
	 */
	public static void probeConnectionLDAP(String hostname, int port, int timeout) throws LDAPException {
		try {
			probeConnectionRaw(hostname, port, timeout);
		} catch (IOException e) {
			String msg = "Unable to connect to " + hostname + ":" + port + ".";
			throw new LDAPException(msg ,LDAPException.CONNECT_ERROR, msg);
		} 
	}

	/**
	 * Probe a TCP port connection at hostname:port.  
	 * @param timeout in milliseconds
	 * @throws IOException if the connection fails
	 */
	private static void probeConnectionRaw(String hostname, int port, int timeout) throws IOException {
		if (log.isTraceEnabled()) {
			log.trace(">probeConnectionRaw("+hostname+", "+port+", "+timeout+")");			
		}
		Socket probeSocket = new Socket();
		probeSocket.connect(new InetSocketAddress(hostname, port), timeout);
		probeSocket.close();
		if (log.isTraceEnabled()) {
			log.trace("<probeConnectionRaw");			
		}
	}
}
