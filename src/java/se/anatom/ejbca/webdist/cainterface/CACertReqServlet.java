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
 
package se.anatom.ejbca.webdist.cainterface;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.cert.Certificate;

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.apply.RequestHelper;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.util.ServiceLocator;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;

/**
 * Servlet used to distribute  CRLs.<br>
 *
 * The servlet is called with method GET or POST and syntax
 * <code>command=&lt;command&gt;</code>.
 * <p>The follwing commands are supported:<br>
 * <ul>
 * <li>crl - gets the latest CRL.
 *
 * @version $Id: CACertReqServlet.java,v 1.4 2005-01-04 10:04:20 anatom Exp $
 */
public class CACertReqServlet extends HttpServlet {

    private static Logger log = Logger.getLogger(CACertReqServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CERTREQ = "certreq";
	private static final String COMMAND_CERT           = "cert";    
	private static final String COMMAND_CERTPKCS7 = "certpkcs7";
	
	private ISignSessionLocal signsession = null;
   
   private ISignSessionLocal getSignSession(){
   	  if(signsession == null){	
		try {
		    ISignSessionLocalHome signhome = (ISignSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
		    signsession = signhome.create();
		}catch(Exception e){
			throw new EJBException(e);      	  	    	  	
		}
   	  }
   	  return signsession;
   }
   
   
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {


        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(req, res);
        log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");

        // Check if authorized
        EjbcaWebBean ejbcawebbean= (se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean)
                                   req.getSession().getAttribute("ejbcawebbean");
        if ( ejbcawebbean == null ){
          try {
            ejbcawebbean = (se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean) java.beans.Beans.instantiate(this.getClass().getClassLoader(), "se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean");
           } catch (ClassNotFoundException exc) {
               throw new ServletException(exc.getMessage());
           }catch (Exception exc) {
               throw new ServletException (" Cannot create bean of class "+"se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean", exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

		// Check if authorized
		CAInterfaceBean cabean= (se.anatom.ejbca.webdist.cainterface.CAInterfaceBean)
								   req.getSession().getAttribute("cabean");
		if ( cabean == null ){
		  try {
			cabean = (se.anatom.ejbca.webdist.cainterface.CAInterfaceBean) java.beans.Beans.instantiate(this.getClass().getClassLoader(), "se.anatom.ejbca.webdist.cainterface.CAInterfaceBean");
		   } catch (ClassNotFoundException exc) {
			   throw new ServletException(exc.getMessage());
		   }catch (Exception exc) {
			   throw new ServletException (" Cannot create bean of class "+"se.anatom.ejbca.webdist.cainterface.CAInterfaceBean", exc);
		   }
		   req.getSession().setAttribute("cabean", cabean);
		}


        try{
          ejbcawebbean.initialize(req, "/super_administrator");          
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }

		try{
		  cabean.initialize(req, ejbcawebbean);
		} catch(Exception e){
		   throw new java.io.IOException("Error initializing CACertReqServlet");
		}        
                
        
        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null)
            command = "";
        if (command.equalsIgnoreCase(COMMAND_CERTREQ)) {
            try {
                
                PKCS10CertificationRequest pkcs10request = cabean.getPKCS10RequestData();
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				DEROutputStream dOut = new DEROutputStream(bOut);
				dOut.writeObject(pkcs10request);
				dOut.close();
												          
												          
				byte[] b64certreq = se.anatom.ejbca.util.Base64.encode(bOut.toByteArray());
				String out = "-----BEGIN CERTIFICATE REQUEST-----\n";
				out += new String(b64certreq);
				out += "\n-----END CERTIFICATE REQUEST-----\n";      				
                
                String filename = "pkcs10certificaterequest.pem";
                res.setHeader("Content-disposition", "attachment; filename=" +  filename);
                res.setContentType("application/octet-stream");
                res.setContentLength(out.length());
                res.getOutputStream().write(out.getBytes());
                log.info("Sent latest Certificate Request to client at " + remoteAddr);
            } catch (Exception e) {
                PrintStream ps = new PrintStream(res.getOutputStream());
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error sending Certificate Request.");
                e.printStackTrace(ps);
                log.error("Error sending Certificate Request to " + remoteAddr, e);
                return;
            }
        }
		if (command.equalsIgnoreCase(COMMAND_CERT)) {
			 try {
			 	Certificate cert = cabean.getProcessedCertificate();			 	
				byte[] b64cert = se.anatom.ejbca.util.Base64.encode(cert.getEncoded());	
				RequestHelper.sendNewB64Cert(b64cert, res, RequestHelper.BEGIN_CERTIFICATE_WITH_NL, RequestHelper.END_CERTIFICATE_WITH_NL);							
			 } catch (Exception e) {
				 PrintStream ps = new PrintStream(res.getOutputStream());
				 res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting processed certificate.");
				 e.printStackTrace(ps);
				 log.error("Error sending processed certificate to " + remoteAddr, e);
				 return;
			 }
		 }
		if (command.equalsIgnoreCase(COMMAND_CERTPKCS7)) {
			 try {
				Certificate cert = cabean.getProcessedCertificate();		
		        byte[] pkcs7 =  getSignSession().createPKCS7(ejbcawebbean.getAdminObject(),cert);							 	
			    byte[] b64cert = se.anatom.ejbca.util.Base64.encode(pkcs7);	
			    RequestHelper.sendNewB64Cert(b64cert, res, RequestHelper.BEGIN_PKCS7_WITH_NL, RequestHelper.END_PKCS7_WITH_NL);																		 					
			 } catch (Exception e) {
				 PrintStream ps = new PrintStream(res.getOutputStream());
				 res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting processed certificate.");
				 e.printStackTrace(ps);
				 log.error("Error sending processed certificate to " + remoteAddr, e);
				 return;
			 }
		 }




    } // doGet

    /**
     * Prints debug info back to browser client
     **/
    private class Debug {
        private final ByteArrayOutputStream buffer;
        private final PrintStream printer;
        Debug( ){
            buffer=new ByteArrayOutputStream();
            printer=new PrintStream(buffer);

            print("<html>");
            print("<body>");
            print("<head>");

            String title = "Certificate/CRL distribution servlet";
            print("<title>" + title + "</title>");
            print("</head>");
            print("<body bgcolor=\"white\">");

            print("<h2>" + title + "</h2>");
        }

        void printDebugInfo(OutputStream out) throws IOException {
            print("</body>");
            print("</html>");
            out.write(buffer.toByteArray());
        }

        void print(Object o) {
            printer.println(o);
        }
        void printInsertLineBreaks( byte[] bA ) throws Exception {
            BufferedReader br=new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(bA)) );
            while ( true ){
                String line=br.readLine();
                if (line==null)
                    break;
                print(line.toString()+"<br>");
            }
        }
        void takeCareOfException(Throwable t ) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            t.printStackTrace(new PrintStream(baos));
            print("<h4>Exception:</h4>");
            try {
                printInsertLineBreaks( baos.toByteArray() );
            } catch (Exception e) {
                e.printStackTrace(printer);
            }
        }
    }
}
