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
import javax.servlet.http.HttpServletRequest;


/**
 * Interface used for health polling purposes to see that everything is alive and ok.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public interface IHealthCheck {
	
	
	/**
	 * Method used to initialize the health checker with parameters set
	 * in the web.xml file.
	 * 
	 *
	 */
	public void init(ServletConfig config);
	
	/**
	 * Method used to check the health of a specific application.
	 * @return Null if everyting is OK, othervise it should return a String as errormessage.
	 */
	
	public String checkHealth(HttpServletRequest request);

}
