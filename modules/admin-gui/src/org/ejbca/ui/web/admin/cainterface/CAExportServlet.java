package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;

import com.keyfactor.util.StringTools;

/**
 * This Servlet exports a CA as an octet/stream.
 */
public class CAExportServlet extends BaseAdminServlet {
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
	@Override
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
	@Override
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
	@Override
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws IOException, ServletException {
	    log.trace(">doGet()");
	    final AuthenticationToken admin = getAuthenticationToken(req);
	    RequestHelper.setDefaultCharacterEncoding(req);
	    String caname = req.getParameter(HIDDEN_CANAME);
	    String capassword = req.getParameter(TEXTFIELD_EXPORTCA_PASSWORD);
	    log.info("Got request from "+req.getRemoteAddr()+" to export "+caname);
  		try{
        	CAInfo cainfo = caSession.getCAInfo(admin, caname);
        	String ext = "p12"; // Default for X.509 CAs
        	if (cainfo.getCAType() == CAInfo.CATYPE_CVC) {
        		ext = "pkcs8";
        	}
			byte[] keystorebytes = caAdminSession.exportCAKeyStore(admin, caname, capassword, capassword, "SignatureKeyAlias", "EncryptionKeyAlias");
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
