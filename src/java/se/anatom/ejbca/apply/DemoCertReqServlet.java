package se.anatom.ejbca.apply;

import java.beans.Beans;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.ejb.CreateException;
import javax.ejb.ObjectNotFoundException;
import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Category;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.PKCS10RequestMessage;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.FileTools;
import se.anatom.ejbca.util.KeyTools;
import se.anatom.ejbca.webdist.rainterface.RAInterfaceBean;
import se.anatom.ejbca.webdist.rainterface.UserView;


/**
 * This is a servlet that is used for creating a user into EJBCA and
 * retrieving her certificate.  Supports only POST.
 * <p>
 *   The CGI parameters for requests are the following.
 * </p>
 * <dl>
 * <dt>pkcs10req</dt>
 * <dd>
 *   A PKCS#10 request, mandatory. TODO more on this
 * </dd>
 * <dt>username</dt>
 * <dd>
 *   The username (for EJBCA use only).  Optional, defaults to the CN in
 *   the PKCS#10 request.
 * </dd>
 * <dt>password</dt>
 * <dd>
 *   Password for the user (for EJBCA internal use only).  Optional,
 *   defaults to an empty string.
 *   TODO does this have anything to do with the returned cert?
 * </dd>
 * <dt>entityprofile</dt>
 * <dd>
 *   The name of the EJBCA end entity profile for the user.  Optional,
 *   defaults to an empty end entity profile.
 * </dd>
 * <dt>certificateprofile</dt>
 * <dd>
 *   The name of the EJBCA certificate profile to use.  Optional,
 *   defaults to the fixed end user profile.
 * </dd>
 * </dl>
 *
 * @author Ville Skyttä
 * @version $Id: DemoCertReqServlet.java,v 1.1 2003-01-02 14:09:57 anatom Exp $
 */
public class DemoCertReqServlet
  extends HttpServlet {

  private final static Category cat =
    Category.getInstance(CertReqServlet.class.getName());

  private InitialContext ctx = null;
  private ISignSessionHome home = null;
  private ISignSessionRemote ss = null;
  private IUserAdminSessionRemote adminsession = null;
  private IUserAdminSessionHome adminsessionhome = null;

  private final static byte[] BEGIN_CERT =
    "-----BEGIN CERTIFICATE-----".getBytes();
  private final static int BEGIN_CERT_LENGTH = BEGIN_CERT.length;

  private final static byte[] END_CERT =
    "-----END CERTIFICATE-----".getBytes();
  private final static int END_CERT_LENGTH = END_CERT.length;

  private final static byte[] NL = "\n".getBytes();
  private final static int NL_LENGTH = NL.length;

  public void init(ServletConfig config)
    throws ServletException
  {
    super.init(config);
    try {
      // Install BouncyCastle provider
      Provider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
      int result = Security.addProvider(p);

      // Get EJB context and home interfaces
      ctx = new InitialContext();
      home = (ISignSessionHome) PortableRemoteObject
        .narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class);
      Object obj1 = ctx.lookup("UserAdminSession");
      adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
    } catch (Exception e) {
      throw new ServletException(e);
    }
  }


  /**
   * Handles PKCS10 certificate request, these are constructed as:
   * <pre><code>
   * CertificationRequest ::= SEQUENCE {
   * certificationRequestInfo  CertificationRequestInfo,
   * signatureAlgorithm          AlgorithmIdentifier{{ SignatureAlgorithms }},
   * signature                       BIT STRING
   * }
   * CertificationRequestInfo ::= SEQUENCE {
   * version             INTEGER { v1(0) } (v1,...),
   * subject             Name,
   * subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
   * attributes          [0] Attributes{{ CRIAttributes }}
   * }
   * SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
   * algorithm           AlgorithmIdentifier {{IOSet}},
   * subjectPublicKey    BIT STRING
   * }
   * </pre>
   *
   * PublicKey's encoded-format has to be RSA X.509.
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException
  {
    Debug debug = new Debug(request, response);

    try {
        adminsession = adminsessionhome.create();
        ss = home.create();
    } catch (CreateException e) {
      throw new ServletException(e);
    }

    Admin admin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
    //Admin admin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
    byte[] buffer = pkcs10Bytes(request.getParameter("pkcs10req"));
    if (buffer == null) {
      // abort here, no PKCS#10 received
      throw new ServletException("A certification request must be provided!");
    }

    // Decompose the PKCS#10 request, and create the user.
    PKCS10RequestMessage p10 = new PKCS10RequestMessage(buffer);
    String dn = p10.getCertificationRequest().getCertificationRequestInfo().getSubject().toString();

    String username = request.getParameter("username");
    if (username == null || username.trim().length() == 0) {
      username = CertTools.getPartFromDN(dn, "CN");
    }
    // need null check here?
    // Before doing anything else, check if the user name is unique and ok.
    username = checkUsername(admin,username);

    UserView newuser = new UserView();
    newuser.setUsername(username);

    newuser.setSubjectDN(dn);
    newuser.setTokenType(SecConst.TOKEN_SOFT_BROWSERGEN);
    newuser.setAdministrator(false);
    newuser.setKeyRecoverable(false);

    String email = CertTools.getPartFromDN(dn, "E"); // BC says VeriSign
    if (email == null) email = CertTools.getPartFromDN(dn, "EMAILADDRESS");
    // TODO: get values from subject altname, lookup email as well
    // newuser.setSubjectAltName(...)
    if (email != null) {
      newuser.setEmail(email);
    }

    int eProfileId = SecConst.EMPTY_ENDENTITYPROFILE;
    if (request.getParameter("entityprofile") != null) {
      // TODO: resolve eProfile's Id
    }
    // TODO: check that we're authorized to use the profile
    newuser.setEndEntityProfileId(eProfileId);

    int cProfileId = SecConst.CERTPROFILE_FIXED_ENDUSER;
    if (request.getParameter("certificateprofile") != null) {
      // TODO: resolve cProfile's Id
    }
    // TODO: check that we're authorized to use the profile
    newuser.setCertificateProfileId(cProfileId);

    // TODO: figure out if we can manage without a password.
    String password = request.getParameter("password");
    if (password == null) password = "";
    newuser.setPassword(password);
    newuser.setClearTextPassword(false);

    try {
        adminsession.addUser(admin, newuser.getUsername(), newuser.getPassword(), newuser.getSubjectDN(), newuser.getSubjectAltName()
                               ,newuser.getEmail(), newuser.getClearTextPassword(), newuser.getEndEntityProfileId(),
                                newuser.getCertificateProfileId(), newuser.getAdministrator(),
                                newuser.getKeyRecoverable(), newuser.getTokenType(), newuser.getHardTokenIssuerId());
    } catch (Exception e) {
      throw new ServletException("Error adding user: ", e);
    }

    byte[] pkcs7;
    try {
      X509Certificate cert =
        (X509Certificate) ss.createCertificate(admin, username, password, p10);
      //pkcs7 = ss.createPKCS7(admin, cert);
      pkcs7 = cert.getEncoded();
    } catch (java.security.cert.CertificateEncodingException e) {
      throw new ServletException(e);
    } catch (ObjectNotFoundException e) {
      // User not found
      throw new ServletException(e);
    } catch (AuthStatusException e) {
      // Wrong user status, shouldn't really happen.  The user needs to have
      // status of NEW, FAILED or INPROCESS.
      throw new ServletException(e);
    } catch (AuthLoginException e) {
      // Wrong username or password, hmm... wasn't the wrong username caught
      // in the objectnotfoundexception above... and this shouldn't happen.
      throw new ServletException(e);
    } catch (IllegalKeyException e) {
      // Malformed key (?)
      throw new ServletException(e);
    } catch (SignRequestException e) {
      // Invalid request
      throw new ServletException(e);
    } catch (SignRequestSignatureException e) {
      // Invalid signature in certificate request
      throw new ServletException(e);
    }


    sendNewB64Cert(Base64.encode(pkcs7), response);

  }


  public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException
  {
    cat.debug(">doGet()");
    Debug debug = new Debug(request,response);
    debug.print("The certificate request servlet only handles POST method.");
    debug.printDebugInfo();
    cat.debug("<doGet()");
  } // doGet


  private void sendNewB64Cert(byte[] b64cert, HttpServletResponse out)
    throws IOException
  {
    out.setContentType("application/octet-stream");
    out.setHeader("Content-disposition", " attachment; filename=cert.crt");
    out.setContentLength(b64cert.length +
                         BEGIN_CERT_LENGTH + END_CERT_LENGTH + (3 *NL_LENGTH));

    ServletOutputStream os = out.getOutputStream();
    os.write(BEGIN_CERT);
    os.write(NL);
    os.write(b64cert);
    os.write(NL);
    os.write(END_CERT);
    os.write(NL);
    out.flushBuffer();
  }


  /**
   *
   */
  private final static byte[] pkcs10Bytes(String pkcs10)
  {
    if (pkcs10 == null) return null;
    byte[] reqBytes = pkcs10.getBytes();
    byte[] bytes = null;
    try {
      // A real PKCS10 PEM request
      String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
      String endKey   = "-----END CERTIFICATE REQUEST-----";
      bytes = FileTools.getBytesFromPEM(reqBytes, beginKey, endKey);
    } catch (IOException e) {
      try {
        // Keytool PKCS10 PEM request
        String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
        String endKey   = "-----END NEW CERTIFICATE REQUEST-----";
        bytes = FileTools.getBytesFromPEM(reqBytes, beginKey, endKey);
      } catch (IOException e2) {
        // IE PKCS10 Base64 coded request
        bytes = Base64.decode(reqBytes);
      }
    }
    return bytes;
  }

  /**
   *
   */
  private final String checkUsername(Admin admin, String username)
    throws ServletException
  {
    if (username != null) username = username.trim();
    if (username == null || username.length() == 0) {
      throw new ServletException("Username must not be empty.");
    }

    try {
        UserAdminData tmpuser = adminsession.findUser(admin, username);
        if (tmpuser != null) {
            throw new ServletException("User '" + username + "' already exists.");
        }
    } catch (Exception e) {
      throw new ServletException("Error checking username '" + username +
                                 ": ", e);
    }
    return username;
  }


  /**
   * Prints debug info back to browser client
   */
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
      request.getRequestDispatcher("/ejbca/adminweb/error.jsp").forward(request, response);
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
  }

}
