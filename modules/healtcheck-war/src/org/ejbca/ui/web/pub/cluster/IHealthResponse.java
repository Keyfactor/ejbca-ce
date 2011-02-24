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

import javax.servlet.http.HttpServletResponse;


/**
 * Interface used to generate appropriate responses to different LoadBalancers HTTP requests.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public interface IHealthResponse {
	
	/**
	 * Method in charge of creating a response to the loadbalancer that this node in the
	 * cluster shouldn't be used.
	 * 
	 * @param status, if status is null then everything is OK, otherwise failure with an error message
	 * that might be used in the reply.
	 * @param resp the HttpServletResponse.
	 */
	public void respond(String status, HttpServletResponse resp);

}
