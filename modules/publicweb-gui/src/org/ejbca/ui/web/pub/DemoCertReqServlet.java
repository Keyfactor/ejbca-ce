/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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
import java.util.Date;
import java.util.Enumeration;

import javax.ejb.EJB;
import javax.ejb.ObjectNotFoundException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.web.CertificateResponseType;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.HTMLTools;

/**
 * This is a servlet that is used for creating a user into EJBCA and retrieving her certificate. Supports only POST.
 * <p>
 * The CGI parameters for requests are the following.
 * </p>
 * <dl>
 * <dt>pkcs10req</dt>
 * <dd>
 * A PKCS#10 request, mandatory.</dd>
 * <dt>username</dt>
 * <dd>
 * The username (for EJBCA use only). Optional, defaults to the CN in the PKCS#10 request.</dd>
 * <dt>password</dt>
 * <dd>
 * Password for the user (for EJBCA internal use only). Optional, defaults to an empty string. Used for authorization of the certificate request.</dd>
 * <dt>email</dt>
 * <dd>
 * Email of the user for inclusion in subject alternative names. Optional, defaults to none.</dd>
 * <dt>entityprofile</dt>
 * <dd>
 * The name of the EJBCA end entity profile for the user. Optional, defaults to an empty end entity profile.</dd>
 * <dt>certificateprofile</dt>
 * <dd>
 * The name of the EJBCA certificate profile to use. Optional, defaults to the fixed end user profile.</dd>
 * </dl>
 * 
 * @version $Id$
 */
public class DemoCertReqServlet extends HttpServlet {

    private static final long serialVersionUID = -3011724049895073472L;

    private final static Logger log = Logger.getLogger(DemoCertReqServlet.class);

    // Edit this constant to the id of your preferable CA used to sign certificate.
    private final static int DEFAULT_DEMOCAID = 0;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            CryptoProviderTools.installBCProvider(); // Install BouncyCastle provider
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    /**
     * Handles PKCS10 certificate request, these are constructed as:
     * 
     * <pre>
     * <code>
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
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        ServletDebug debug = new ServletDebug(request, response);

        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("DemoCertReqServlet: "+request.getRemoteAddr()));
        //Admin admin = new Admin(Admin.TYPE_RA_USER, request.getRemoteAddr());
        RequestHelper.setDefaultCharacterEncoding(request);

        String dn = null;
        dn = request.getParameter("user");
        byte[] reqBytes = null;
        int type = 0;
        if (request.getParameter("keygen") != null) {
            reqBytes = request.getParameter("keygen").getBytes();
            log.debug("Received NS request:" + new String(reqBytes));
            if (reqBytes != null) {
                type = 1;
            }
        } else if (request.getParameter("pkcs10req") != null) {
            // if not firefox, check if it's IE
            reqBytes = request.getParameter("pkcs10req").getBytes();
            log.debug("Received IE request:" + new String(reqBytes));
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
        username = username + "(" + (new Date()).toString() + ")";
        // Strip dangerous chars
        username = StringTools.stripUsername(username);
        // need null check here?
        // Before doing anything else, check if the user name is unique and ok.
        boolean check = checkUsername(admin, username, endEntityAccessSession);
        if (check == false) {
            String msg = "User '" + HTMLTools.htmlescape(username) + "' already exist.";
            log.error(msg);
            debug.printMessage(msg);
            debug.printDebugInfo();
            return;
        }

        // Functionality to determine the class id of ie page.
        String classid = "clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1\" CODEBASE=\"/CertControl/xenroll.cab#Version=5,131,3659,0";
        if (request.getParameter("classid") != null && !request.getParameter("classid").equals("")) {
            classid = request.getParameter("classid");
        }

        String includeEmail = request.getParameter("includeemail");
        log.debug("includeEmail=" + includeEmail);

        EndEntityInformation newuser = new EndEntityInformation();
        newuser.setType(new EndEntityType(EndEntityTypes.ENDUSER));
        newuser.setUsername(username);
        newuser.setDN(dn);
        newuser.setTokenType(SecConst.TOKEN_SOFT_BROWSERGEN);
        newuser.setKeyRecoverable(false);
        newuser.setSendNotification(false);

        String email = request.getParameter("email");
        if (email == null) {
            email = CertTools.getPartFromDN(dn, "EMAILADDRESS");
        }
        if ((email != null) && (email.length() > 0)) {
            newuser.setEmail(email);
            if (includeEmail != null) {
                newuser.setSubjectAltName("RFC822NAME=" + email);
            }
        }

        String tmp = null;
        int eProfileId = SecConst.EMPTY_ENDENTITYPROFILE;
        if ((tmp = request.getParameter("entityprofile")) != null) {
            try {
                eProfileId = endEntityProfileSession.getEndEntityProfileId(request.getParameter("entityprofile"));
            } catch (EndEntityProfileNotFoundException e) {
                throw new ServletException("No such end entity profile: " + tmp, e);
            }
        }
        newuser.setEndEntityProfileId(eProfileId);

        int cProfileId = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
        if ((tmp = request.getParameter("certificateprofile")) != null) {
            cProfileId = certificateProfileSession.getCertificateProfileId(request.getParameter("certificateprofile"));
            if (cProfileId == 0) {
                throw new ServletException("No such certificate profile: " + tmp);
            }
        }
        newuser.setCertificateProfileId(cProfileId);

        int caid = DEFAULT_DEMOCAID;
        if ((tmp = request.getParameter("ca")) != null) {
            // Do NOT get requested CA to sign with from form.
            // For security reasons, if there are more than one CA in the system
            // we definataly want to hardwire the demo to the demo CA.
        }
        newuser.setCAId(caid);

        String password = request.getParameter("password");
        if (password == null) {
            password = "demo";
        }
        newuser.setPassword(password);

        try {
            endEntityManagementSession.addUser(admin, newuser.getUsername(), newuser.getPassword(), newuser.getDN(), newuser.getSubjectAltName(),
                    newuser.getEmail(), false, newuser.getEndEntityProfileId(), newuser.getCertificateProfileId(), newuser.getType(),
                    newuser.getTokenType(), newuser.getHardTokenIssuerId(), newuser.getCAId());
        } catch (Exception e) {
            throw new ServletException("Error adding user: ", e);
        }

        RequestHelper helper = new RequestHelper(admin, debug);
        try {
            if (type == 1) {
                byte[] certs = helper.nsCertRequest(signSession, reqBytes, username, password);
                RequestHelper.sendNewCertToNSClient(certs, response);
            }
            if (type == 2) {
                byte[] b64cert = helper.pkcs10CertRequest(signSession, caSession, reqBytes, username, password, CertificateResponseType.ENCODED_PKCS7).getEncoded();
                debug.ieCertFix(b64cert);
                RequestHelper.sendNewCertToIEClient(b64cert, response.getOutputStream(), getServletContext(), getInitParameter("responseTemplate"),
                        classid);
            }
        } catch (ObjectNotFoundException oe) {
            log.debug("Non existens username!");
            debug.printMessage("Non existent username!");
            debug.printMessage("To generate a certificate a valid username and password must be entered.");
            debug.printDebugInfo();
            return;
        } catch (AuthStatusException ase) {
            log.debug("Wrong user status!");
            debug.printMessage("Wrong user status!");
            debug.printMessage("To generate a certificate for a user the user must have status new, failed or inprocess.");
            debug.printDebugInfo();
            return;
        } catch (AuthLoginException ale) {
            log.debug("Wrong password for user!");
            debug.printMessage("Wrong username or password!");
            debug.printMessage("To generate a certificate a valid username and password must be entered.");
            debug.printDebugInfo();
            return;
        } catch (SignRequestException re) {
            log.debug("Invalid request!");
            debug.printMessage("Invalid request!");
            debug.printMessage("Please supply a correct request.");
            debug.printDebugInfo();
            return;
        } catch (SignRequestSignatureException se) {
            log.debug("Invalid signature on certificate request!");
            debug.printMessage("Invalid signature on certificate request!");
            debug.printMessage("Please supply a correctly signed request.");
            debug.printDebugInfo();
            return;
        } catch (java.lang.ArrayIndexOutOfBoundsException ae) {
            log.debug("Empty or invalid request received.");
            debug.printMessage("Empty or invalid request!");
            debug.printMessage("Please supply a correct request.");
            debug.printDebugInfo();
            return;
        } catch (DecoderException de) {
            log.debug("Empty or invalid request received.");
            debug.printMessage("Empty or invalid request!");
            debug.printMessage("Please supply a correct request.");
            debug.printDebugInfo();
            return;
        } catch (Exception e) {
            log.debug(e);
            debug.print("<h3>parameter name and values: </h3>");
            Enumeration<? extends Object> paramNames = request.getParameterNames();
            while (paramNames.hasMoreElements()) {
                String name = paramNames.nextElement().toString();
                String parameter = request.getParameter(name);
                debug.print("<h4>" + HTMLTools.htmlescape(name) + ":</h4>" + HTMLTools.htmlescape(parameter) + "<br>");
            }
            debug.takeCareOfException(e);
            debug.printDebugInfo();
            return;
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        log.trace(">doGet()");
        response.setHeader("Allow", "POST");
        ServletDebug debug = new ServletDebug(request, response);
        debug.print("The certificate request servlet only handles POST method.");
        debug.printDebugInfo();
        log.trace("<doGet()");
    } // doGet

    /**
     * @return true if the username is ok (does not already exist), false otherwise
     */
    private final boolean checkUsername(AuthenticationToken admin, String username, EndEntityAccessSession adminsession) throws ServletException {
        if (username != null) {
            username = username.trim();
        }
        if (username == null || username.length() == 0) {
            throw new ServletException("Username must not be empty.");
        }

        EndEntityInformation tmpuser = null;
        try {
            tmpuser = adminsession.findUser(admin, username);
        } catch (Exception e) {
            throw new ServletException("Error checking username '" + username + ": ", e);
        }
        return (tmpuser == null) ? true : false;
    }

}
