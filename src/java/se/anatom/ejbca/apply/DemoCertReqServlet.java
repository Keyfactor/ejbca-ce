package se.anatom.ejbca.apply;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.Provider;
import java.security.Security;
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
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.FileTools;
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
 * </dd>
 * <dt>email</dt>
 * <dd>
 *   Email of the user for inclusion in subject alternative names.  Optional,
 *   defaults to none.
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
 * @version $Id: DemoCertReqServlet.java,v 1.8 2003-01-23 09:40:14 anatom Exp $
 */
public class DemoCertReqServlet extends HttpServlet {

  private final static Category cat = Category.getInstance(DemoCertReqServlet.class.getName());

  private InitialContext ctx = null;
  private ISignSessionHome signsessionhome = null;
  private IUserAdminSessionHome adminsessionhome = null;

  private final static byte[] BEGIN_CERT =
    "-----BEGIN CERTIFICATE-----".getBytes();
  private final static int BEGIN_CERT_LENGTH = BEGIN_CERT.length;

  private final static byte[] END_CERT =
    "-----END CERTIFICATE-----".getBytes();
  private final static int END_CERT_LENGTH = END_CERT.length;

  private final static byte[] NL = "\n".getBytes();
  private final static int NL_LENGTH = NL.length;

  public void init(ServletConfig config) throws ServletException
  {
    super.init(config);
    try {
      // Install BouncyCastle provider
      Provider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
      int result = Security.addProvider(p);

      // Get EJB context and home interfaces
      ctx = new InitialContext();
      signsessionhome = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class);
      adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("UserAdminSession"), IUserAdminSessionHome.class);
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
    ServletDebug debug = new ServletDebug(request, response);

    ISignSessionRemote signsession = null;
    IUserAdminSessionRemote adminsession = null;
    try {
        adminsession = adminsessionhome.create();
        signsession = signsessionhome.create();
    } catch (CreateException e) {
      throw new ServletException(e);
    }

     Admin admin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
     RequestHelper helper = new RequestHelper(admin, debug);

      String dn = null;
      dn = request.getParameter("user");
      byte[] reqBytes = null;
      int type = 0;
      if (request.getParameter("keygen") != null) {
          reqBytes=request.getParameter("keygen").getBytes();
          cat.debug("Received NS request:"+new String(reqBytes));
          if (reqBytes != null) {
              type = 1;
          }
      } else if (request.getParameter("pkcs10req") != null) {
          // if not netscape, check if it's IE
          reqBytes=request.getParameter("pkcs10req").getBytes();
          cat.debug("Received IE request:"+new String(reqBytes));
          if (reqBytes != null) {
              type = 2;
          }
      }
    if (reqBytes == null) {
      // abort here, no request received
      throw new ServletException("A certification request must be provided!");
    }

    String username = request.getParameter("username");
    if (username == null || username.trim().length() == 0) {
        username = CertTools.getPartFromDN(dn, "CN");
    }
    // need null check here?
    // Before doing anything else, check if the user name is unique and ok.
    boolean check = checkUsername(admin,username, adminsession);
    if (check == false) {
        String msg = "User '"+username+"' already exist.";
        cat.error(msg);
        debug.printMessage(msg);
        debug.printDebugInfo();
        return;
    }

    String includeEmail = request.getParameter("includeemail");
    cat.debug("includeEmail="+includeEmail);

    UserView newuser = new UserView();
    newuser.setUsername(username);

    newuser.setSubjectDN(dn);
    newuser.setTokenType(SecConst.TOKEN_SOFT_BROWSERGEN);
    newuser.setAdministrator(false);
    newuser.setKeyRecoverable(false);

    String email = request.getParameter("email");
    if (email == null) email = CertTools.getPartFromDN(dn, "EMAILADDRESS");
    if (email != null) {
      newuser.setEmail(email);
      if (includeEmail != null) {
          newuser.setSubjectAltName("email="+email);
      }
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

    String password = request.getParameter("password");
    if (password == null) password = "demo";
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
        if (type == 1) {
              byte[] certs = helper.nsCertRequest(signsession, reqBytes, username, password);
              RequestHelper.sendNewCertToNSClient(certs, response);
        }
        if (type == 2) {
              byte[] b64cert=helper.pkcs10CertRequest(signsession, reqBytes, username, password);
              debug.ieCertFix(b64cert);
              RequestHelper.sendNewCertToIEClient(b64cert, response.getOutputStream(), getServletContext(), getInitParameter("responseTemplate"));
        }

    //} catch (java.security.cert.CertificateEncodingException e) {
    //  throw new ServletException(e);
    } catch (ObjectNotFoundException e) {
      // User not found
      cat.error(e);
      throw new ServletException(e);
    } catch (AuthStatusException e) {
      // Wrong user status, shouldn't really happen.  The user needs to have
      // status of NEW, FAILED or INPROCESS.
      cat.error(e);
      throw new ServletException(e);
    } catch (AuthLoginException e) {
      // Wrong username or password, hmm... wasn't the wrong username caught
      // in the objectnotfoundexception above... and this shouldn't happen.
      cat.error(e);
      throw new ServletException(e);
    } catch (IllegalKeyException e) {
      // Malformed key (?)
      cat.error(e);
      throw new ServletException(e);
    } catch (SignRequestException e) {
      // Invalid request
      cat.error(e);
      throw new ServletException(e);
    } catch (SignRequestSignatureException e) {
      // Invalid signature in certificate request
      cat.error(e);
      throw new ServletException(e);
    } catch (Exception e) {
        cat.error(e);
        throw new ServletException(e);
    }
  }


  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
  {
    cat.debug(">doGet()");
    ServletDebug debug = new ServletDebug(request,response);
    debug.print("The certificate request servlet only handles POST method.");
    debug.printDebugInfo();
    cat.debug("<doGet()");
  } // doGet


private void sendNewCertToIEClient(byte[] b64cert, OutputStream out) throws Exception {
    PrintStream ps = new PrintStream(out);
    BufferedReader br = new BufferedReader(new InputStreamReader(getServletContext().getResourceAsStream(getInitParameter("responseTemplate"))));
    while ( true ) {
        String line=br.readLine();
        if ( line==null )
            break;
        if ( line.indexOf("cert =")<0 )
            ps.println(line);
        else
            RequestHelper.ieCertFormat(b64cert, ps);
    }
    ps.close();
    cat.info("Sent reply to IE client");
    cat.debug(new String(b64cert));
}

private void sendNewB64Cert(byte[] b64cert, HttpServletResponse out)
    throws IOException
  {
    out.setContentType("application/octet-stream");
    out.setHeader("Content-disposition", " attachment; filename=cert.crt");
    out.setContentLength(b64cert.length +BEGIN_CERT_LENGTH + END_CERT_LENGTH + (3 *NL_LENGTH));
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
   * @return true if the username is ok (does not already exist), false otherwise
   */
  private final boolean checkUsername(Admin admin, String username, IUserAdminSessionRemote adminsession) throws ServletException
  {
    if (username != null) username = username.trim();
    if (username == null || username.length() == 0) {
      throw new ServletException("Username must not be empty.");
    }

    UserAdminData tmpuser = null;
    try {
        tmpuser = adminsession.findUser(admin, username);
     } catch (Exception e) {
        throw new ServletException("Error checking username '" + username +": ", e);
     }
    return (tmpuser==null) ? true:false;
  }

}
