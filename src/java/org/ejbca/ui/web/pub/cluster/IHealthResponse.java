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

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;


/**
 * Inteface used to generate apporiate responses to different LoadBalancers HTTP requests.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public interface IHealthResponse {
	
	/**
	 * Method used to initialize the health checker responder with parameters set
	 * in the web.xml file.
	 * 
	 *
	 */
	public void init(ServletConfig config);
	
	/**
	 * Method in charge of creating a response to the loadbalancer that this node in the
	 * cluster shouldn't be used.
	 * 
	 * @param status, if status is null then everything is OK, othervise failure with a errormessage
	 * that might be used in the reply.
	 * @param resp the HttpServletResponse.
	 */
	public void respond(String status, HttpServletResponse resp);

}
