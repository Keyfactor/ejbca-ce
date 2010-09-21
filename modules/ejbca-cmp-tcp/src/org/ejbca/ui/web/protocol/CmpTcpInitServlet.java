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

package org.ejbca.ui.web.protocol;

import java.net.UnknownHostException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.log4j.Logger;
import org.ejbca.ui.tcp.CmpTcpServer;

/**
 * Servlet with the sole purpose of starting the CMP TCP server. 
 *
 * @version $Id$
 */
public class CmpTcpInitServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CmpTcpInitServlet.class);

	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		log.info("Starting CMP TCP Service..");
		try {
			CmpTcpServer.start();
		} catch (UnknownHostException e) {
			throw new ServletException(e);
		}
	}
}
