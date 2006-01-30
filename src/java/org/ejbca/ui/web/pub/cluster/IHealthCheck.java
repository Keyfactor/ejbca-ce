package org.ejbca.ui.web.pub.cluster;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;


/**
 * Inteface used for health polling purposes to see that everything is alive and ok.
 * 
 * @author Philip Vendil
 * $Id: IHealthCheck.java,v 1.1 2006-01-30 06:29:12 herrvendil Exp $
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
