package se.anatom.ejbca.protocol;

import java.io.*;
import java.util.Enumeration;
import java.security.Provider;
import java.security.Security;

import javax.servlet.*;
import javax.servlet.http.*;

import javax.rmi.PortableRemoteObject;
import javax.naming.InitialContext;

import org.apache.log4j.*;

import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.Base64;

/** Servlet implementing server side of the Simple Certificate Enrollment Protocol (SCEP)
* snip from OpenSCEP
* -----
*This processes does the following:
*
* 1. decode a PKCS#7 signed data message from the standard input
* 2. extract the signed attributes from the the message, which indicate
*     the type of request
* 3. decrypt the enveloped data PKCS#7 inside
* 4. branch to different actions depending on the type of the message:
*     - PKCSReq
*     - GetCertInitial
*     - GetCert
*     - GetCRL
*     - v2 PKCSReq or Proxy request
* 5. envelop (PKCS#7) the reply data from the previous step
* 6. sign the reply data (PKCS#7) from the previous step
* 7. output the result as a der encoded block on stdout
* -----
* @version $Id: ScepServlet.java,v 1.2 2002-09-21 11:30:03 anatom Exp $
*/
public class ScepServlet extends HttpServlet {

    static private Category cat = Category.getInstance( ScepServlet.class.getName() );

    private InitialContext ctx = null;
    private Admin administrator = null;
    ISignSessionHome home = null;

    public void init(ServletConfig config) throws ServletException {
    super.init(config);
        try {
            // Install BouncyCastle provider
            Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            int result = Security.addProvider(BCJce);

            // Get EJB context and home interfaces
            ctx = new InitialContext();
            home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		cat.debug(">doPost()");
		Debug debug = new Debug(request, response);
		debug.print("The certificate request servlet only handles POST method.");
		debug.printDebugInfo();
		cat.debug("<doPost()");
	} //doPost

    public void doGet(HttpServletRequest request,  HttpServletResponse response) throws java.io.IOException, ServletException {
        cat.debug(">doGet()");
        Debug debug = new Debug(request, response);
		try {
			String operation = request.getParameter("operation");
            String message = request.getParameter("message");
            if ((operation == null) || (message == null)) {
				debug.print("<h3>Parameters 'operation' and 'message' must be supplied!</h3>");
                debug.print((operation == null) ? "operation" : "message" + "is null.");
				debug.printDebugInfo();
				return;
			}
			administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
			cat.debug("Got request '" + operation + "'");
			debug.print("<h3>Operation: " + operation + "</h3>");
            ISignSessionRemote ss = home.create(administrator);
			if (operation.equals("PKIOperation")) {
                byte[] scepmsg = Base64.decode(message.getBytes());
                ScepPkiOpHelper helper = new ScepPkiOpHelper(scepmsg);
			} else if (operation.equals("GetCACert")) {
			} else if (operation.equals("GetCACertChain")) {
			} else {
                debug.print("<h3>Invalid parameter '"+operation+"'!</h3>");
                debug.printDebugInfo();
			}
        } catch (java.lang.ArrayIndexOutOfBoundsException ae) {
            cat.debug("Empty or invalid request received.");
            debug.printMessage("Empty or invalid request!");
            debug.printMessage("Please supply a correct request.");
            debug.printDebugInfo();
            return;
		} catch (Exception e) {
			cat.debug(e);
			debug.print("<h3>parameter name and values: </h3>");
			Enumeration paramNames = request.getParameterNames();
			while (paramNames.hasMoreElements()) {
				String name = paramNames.nextElement().toString();
				String parameter = request.getParameter(name);
				debug.print("<h4>" + name + ":</h4>" + parameter + "<br>");
			}
			debug.takeCareOfException(e);
			debug.printDebugInfo();
		}
        cat.debug("<doGet()");
    } // doGet

    /**
     * Prints debug info back to browser client
     **/
    private class Debug {
        final private ByteArrayOutputStream buffer;
        final private PrintStream printer;
        final private HttpServletRequest request;
        final private HttpServletResponse response;
        Debug(HttpServletRequest request, HttpServletResponse response){
            buffer=new ByteArrayOutputStream();
            printer=new PrintStream(buffer);
            this.request=request;
            this.response=response;
        }

        void printDebugInfo() throws IOException, ServletException {
            request.setAttribute("ErrorMessage",new String(buffer.toByteArray()));
            request.getRequestDispatcher("/error.jsp").forward(request, response);
        }

        void print(Object o) {
            printer.println(o);
        }
        void printMessage(String msg) {
            print("<p>"+msg);
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
            request.setAttribute("Exception", "true");
        }
    } // Debug

} // ScepServlet
