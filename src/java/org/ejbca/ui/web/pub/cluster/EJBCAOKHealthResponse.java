package org.ejbca.ui.web.pub.cluster;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.pub.CertReqServlet;


/**
 * Class that responds with the String "EJBCAOK" of status is OK else it responds the error message.
 * @author Philip Vendil
 *
 */
public class EJBCAOKHealthResponse implements IHealthResponse {

	private static Logger log = Logger.getLogger(EJBCAOKHealthResponse.class);
	
	private static final String OK_MESSAGE = "EJBCAOK";
	public void init(ServletConfig config) {
		// no initialization needed.
	}

	public void respond(String status, HttpServletResponse resp) {
		resp.setContentType("text/html");
		try {	
			Writer out = resp.getWriter();
			if(status==null){
				// Return "EJBCAOK" Message    	      	  				
				out.write(OK_MESSAGE);		    	  
			}else{
				// Return failinfo
				out.write(status);
			}
			out.flush();
			out.close();
		} catch (IOException e) {
			log.error("Error writing to Servlet Response.",e);
		}
		
		
	}

}
