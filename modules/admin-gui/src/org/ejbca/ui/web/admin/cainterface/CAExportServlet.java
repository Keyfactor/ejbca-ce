package org.ejbca.ui.web.admin.cainterface;

import java.beans.Beans;
import java.io.IOException;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * This Servlet exports a CA as an octet/stream.
 */
public class CAExportServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(CAExportServlet.class);
	private static final long serialVersionUID = 378499368926058906L;
	public static final String HIDDEN_CANAME				= "hiddencaname";
	public static final String TEXTFIELD_EXPORTCA_PASSWORD	= "textfieldexportcapassword";
	
	@EJB
	private CAAdminSessionLocal caAdminSession;
	@EJB
	private CaSessionLocal caSession;

	/**
	 * Initialize.
	 */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    	if (caAdminSession==null) {
    		log.error("Local EJB injection failed.");
    	}
    }

    /**
     * Handle HTTP Post. Redirect the request to doGet(..). 
     * This method should not be called explicitly.
     * 
     * @param req The request.
     * @param res The response.
     */
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
	    log.trace(">doPost()");
	    doGet(req, res);
	    log.trace("<doPost()");
    }

    /**
     * Validates the request parameters and outputs the CA as an PKCS#12 output/octet-stream.
     * This method should not be called explicitly.
     * 
     * @param req The request.
     * @param res The response.
	 */
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws IOException, ServletException {
	    log.trace(">doGet()");
	    // Check if authorized
	    EjbcaWebBean ejbcawebbean= (EjbcaWebBean) req.getSession().getAttribute("ejbcawebbean");
	    if ( ejbcawebbean == null ) {
	      try {
	    	  ejbcawebbean = (EjbcaWebBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(), EjbcaWebBean.class.getName());
	      } catch (ClassNotFoundException e) {
	    	  throw new ServletException(e.getMessage());
	      } catch (Exception e) {
	    	  throw new ServletException ("Cannot create bean of class org.ejbca.ui.web.admin.configuration.EjbcaWebBean", e);
	      }
	       req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
	    }
	    try{
	    	ejbcawebbean.initialize(req, StandardRules.ROLE_ROOT.resource());
	    } catch(Exception e) {
	    	throw new java.io.IOException("Authorization Denied");
	    }
	    RequestHelper.setDefaultCharacterEncoding(req);
	    String caname = req.getParameter(HIDDEN_CANAME);
	    String capassword = req.getParameter(TEXTFIELD_EXPORTCA_PASSWORD);
	    log.info("Got request from "+req.getRemoteAddr()+" to export "+caname);
  		try{
    		byte[] keystorebytes = null;
        	CAInfo cainfo = caSession.getCAInfo(ejbcawebbean.getAdminObject(), caname);
        	String ext = "p12"; // Default for X.509 CAs
        	if (cainfo.getCAType() == CAInfo.CATYPE_CVC) {
        		ext = "pkcs8";
        	}
			keystorebytes = caAdminSession.exportCAKeyStore(ejbcawebbean.getAdminObject(), caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
            ServletUtils.removeCacheHeaders(res);	// We must remove cache headers for IE
        	res.setContentType("application/octet-stream");
        	res.setContentLength(keystorebytes.length);
        	res.setHeader("Content-Disposition", "attachment;filename=\"" + StringTools.stripFilename(caname+"."+ext) + "\"");
	        res.getOutputStream().write(keystorebytes);
  		} catch(Exception e) {
	        res.setContentType("text/plain");
	        res.sendError( HttpServletResponse.SC_BAD_REQUEST, e.getMessage() );
  		} 
	}
}
