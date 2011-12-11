package com.example.web;

import java.io.IOException;

import javax.ejb.EJB;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;

import org.cesecore.certificates.ca.CaSessionLocal;

/**
 * This is a demo servlet that list all CAs in the system
 */
public class ListCAs extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final static Logger log = Logger.getLogger(ListCAs.class);

    @EJB
    private CaSessionLocal caSession;
    
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        StringBuffer out = new StringBuffer ("<html><body><h3>List CAs</h3>");
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(this.getClass().getSimpleName() + ": "+request.getRemoteAddr()));
        for (String ca : caSession.getAvailableCANames(admin)) {
        	out.append("<br>").append(ca);
        }
        out.append("</body></html>");
        response.getOutputStream ().print (out.toString ());
        log.info("Listed a few CAs...");
    } // doGet

}
