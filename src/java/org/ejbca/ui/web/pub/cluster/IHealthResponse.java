package org.ejbca.ui.web.pub.cluster;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;


/**
 * Inteface used to generate apporiate responses to different LoadBalancers HTTP requests.
 * 
 * @author Philip Vendil
 * $Id: IHealthResponse.java,v 1.1 2006-01-30 06:29:12 herrvendil Exp $
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
