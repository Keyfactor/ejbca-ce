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
 
package org.ejbca.ui.web.pub;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.pub.cluster.IHealthCheck;
import org.ejbca.ui.web.pub.cluster.IHealthResponse;
import org.ejbca.util.CertTools;




/**
 * Servlet used to check the health of an EJBCA instance and can be used
 * to build a cluster using a loadbalancer.
 * 
 * This servlet should be configured with two init params:
 *   HealthCheckClassPath : containing the classpath to the IHealthCheck class to be used to check.
 *   HealthResponseClassPath : containing the classpath to the IHealthResponse class to be used 
 *   for the HTTPResponse
 * 
 * The loadbalancer or monitoring application should perform a GET request
 * to the url defined in web.xml.
 *
 * @author Philip Vendil
 * @version $Id: HealthCheckServlet.java,v 1.2 2006-01-31 14:34:51 herrvendil Exp $
 */
public class HealthCheckServlet extends HttpServlet {
    private static Logger log = Logger.getLogger(HealthCheckServlet.class);
    
    private IHealthCheck healthcheck = null;
    private IHealthResponse healthresponse = null;

    private String[] authIPs = null; 
    
    /**
     * Servlet init
     *
     * @param config servlet configuration
     *
     * @throws ServletException on error
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        try {
            // Install BouncyCastle provider
            CertTools.installBCProvider();

            String authIPString = config.getInitParameter("AuthorizedIPs");
            if(authIPString != null){
            	authIPs = authIPString.split(";");
            }
            
            
            healthcheck = (IHealthCheck) HealthCheckServlet.class.getClassLoader().loadClass(config.getInitParameter("HealthCheckClassPath")).newInstance();
            healthcheck.init(config);
            
            healthresponse = (IHealthResponse) HealthCheckServlet.class.getClassLoader().loadClass(config.getInitParameter("HealthResponseClassPath")).newInstance();
            healthresponse.init(config);
            
        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    /**
     * Handles HTTP POST
     *
     * @param request servlet request
     * @param response servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException on error
     */
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        log.debug(">doPost()");
        check(request, response);
        log.debug("<doPost()");
    }

    //doPost

    /**
     * Handles HTTP GET
     *
     * @param request servlet request
     * @param response servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException on error
     */
    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
        log.debug(">doGet()");
        check(request, response);
        log.debug("<doGet()");
    }
    
    private void check(HttpServletRequest request, HttpServletResponse response){
    	
      boolean authorizedIP = false;
      String remoteIP = request.getRemoteAddr();
      if(authIPs != null){
    	  for(int i=0; i < authIPs.length ; i++){
    		  if(remoteIP.equals(authIPs[i])){
    			  authorizedIP = true;
    		  }
    	  }
      }else{
    	  authorizedIP = true;
      }
      
      if(authorizedIP){    	
        healthresponse.respond(healthcheck.checkHealth(request),response);
      }else{
    	  healthresponse.respond("ERROR : Healthcheck request recieved from an non authorized IP.",response);
    	  log.error("ERROR : Healthcheck request recieved from an non authorized IP.");
      }
    }

}


// HealthCheckServlet
