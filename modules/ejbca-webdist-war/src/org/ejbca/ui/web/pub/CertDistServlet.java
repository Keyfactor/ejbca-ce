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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.HTMLTools;

/**
 * Servlet used to distribute certificates and CRLs.<br>
 *
 * The servlet is called with method GET or POST and syntax
 * <code>command=&lt;command&gt;</code>.
 * <p>The following commands are supported:<br>
 * <ul>
 * <li>crl - gets the latest CRL.
 * <li>deltacrl - gets the latest delta CRL.
 * <li>lastcert - gets latest certificate of a user, takes argument 'subject=<subjectDN>'.
 * <li>listcerts - lists all certificates of a user, takes argument 'subject=<subjectDN>'.
 * <li>revoked - checks if a certificate is revoked, takes arguments 'subject=<subjectDN>&serno=<serial number>'.
 * <li>cacert - returns ca certificate in PEM-format, takes argument 'issuer=<issuerDN>&level=<ca-level, 0=root>'
 * <li>nscacert - returns ca certificate for Firefox, same args as above
 * <li>iecacert - returns ca certificate for Internet Explorer, same args as above
 * </ul>
 * cacert, nscacert and iecacert also takes optional parameter level=<int 1,2,...>, where the level is
 * which ca certificate in a hierachy should be returned. 0=root (default), 1=sub to root etc.
 *
 * @version $Id$
 */
public class CertDistServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(CertDistServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CRL = "crl";
    private static final String COMMAND_DELTACRL = "deltacrl"; 
    private static final String COMMAND_REVOKED = "revoked";
    private static final String COMMAND_EECERT = "eecert";
    private static final String COMMAND_CERTBYFP = "certbyfp";
    private static final String COMMAND_LASTCERT = "lastcert";
    private static final String COMMAND_LISTCERT = "listcerts";
    private static final String COMMAND_NSCACERT = "nscacert";
    private static final String COMMAND_IECACERT = "iecacert";
    private static final String COMMAND_CACERT = "cacert";
    private static final String COMMAND_CACHAIN = "cachain";
    
    private static final String SUBJECT_PROPERTY = "subject";
    private static final String FINGERPRINT_PROPERTY = "fingerprint";
	private static final String CAID_PROPERTY = "caid";
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String SERNO_PROPERTY = "serno";
    private static final String LEVEL_PROPERTY = "level";
    /* @Deprecated since EJBCA 6.3.0. MOZILLA_PROPERTY can be removed in EJBCA 6.4 or 6.5 */
    private static final String MOZILLA_PROPERTY = "moz";
    private static final String FORMAT_PROPERTY = "format";
    private static final String INSTALLTOBROWSER_PROPERTY = "installtobrowser";

    @EJB
    private CertificateStoreSessionLocal storesession;
    @EJB
    private CrlStoreSessionLocal crlSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SignSessionLocal signSession;

    /**
     * handles http post
     *
     * @param req servlet request
     * @param res servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException error
     */
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    }

	/**
	 * handles http get
	 *
	 * @param req servlet request
	 * @param res servlet response
	 *
	 * @throws IOException input/output error
	 * @throws ServletException error
	 */
    @Override
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doGet()");

        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        final AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new PublicWebPrincipal(remoteAddr));

        RequestHelper.setDefaultCharacterEncoding(req);
        String issuerdn = null; 
        if(req.getParameter(ISSUER_PROPERTY) != null){
            // HttpServetRequets.getParameter URLDecodes the value for you
            // No need to do it manually, that will cause problems with + characters
            issuerdn = req.getParameter(ISSUER_PROPERTY);
            issuerdn = CertTools.stringToBCDNString(issuerdn);
        }    
		int caid = 0; 
		try {
		    if(req.getParameter(CAID_PROPERTY) != null){
		        caid = Integer.parseInt(req.getParameter(CAID_PROPERTY));
		    }    
		} catch (NumberFormatException e) {
		    log.debug("Invalid CAId: ", e);
		    res.sendError(HttpServletResponse.SC_NOT_FOUND, "Invalid CAId.");
		    return;
		}
        // See if the client wants the response cert or CRL in PEM format (default is DER)
        String format = req.getParameter(FORMAT_PROPERTY); 
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null) {
            command = "";
        }
        if ((command.equalsIgnoreCase(COMMAND_CRL) || command.equalsIgnoreCase(COMMAND_DELTACRL)) && issuerdn != null) {
            try {
                byte[] crl = null;
                if (command.equalsIgnoreCase(COMMAND_CRL)) {
                	crl = crlSession.getLastCRL(issuerdn, false); // CRL
                } else {
                	crl = crlSession.getLastCRL(issuerdn, true); // deltaCRL
                } 
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                String dn = CertTools.getIssuerDN(x509crl);
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
                // moz is only kept for backwards compatibility, can be removed in EJBCA 6.4 or 6.5
                String moz = req.getParameter(MOZILLA_PROPERTY);
                String filename = CertTools.getPartFromDN(dn,"CN")+".crl";
                if (command.equalsIgnoreCase(COMMAND_DELTACRL)) {
                	filename = "delta_"+filename;
                }                 
                if ((moz == null) || !moz.equalsIgnoreCase("y")) {
                    res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(filename)+"\"");                    
                }
                res.setContentType("application/x-x509-crl");
                if (StringUtils.equals(format, "PEM")) {
                    RequestHelper.sendNewB64File(Base64.encode(crl, true), res, filename, RequestHelper.BEGIN_CRL_WITH_NL, RequestHelper.END_CRL_WITH_NL);
                } else {
                    res.setContentLength(crl.length);
                    res.getOutputStream().write(crl);                    
                }
                if (log.isDebugEnabled()) {
                    log.debug("Sent latest CRL to client at " + remoteAddr);
                }
            } catch (Exception e) {
                log.debug("Error sending latest CRL to " + remoteAddr+": ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting latest CRL.");
                return;
            }
        } else if (command.equalsIgnoreCase(COMMAND_EECERT)) {
            // HttpServetRequets.getParameter URLDecodes the value for you
            // No need to do it manually, that will cause problems with + characters
            String dn = req.getParameter(ISSUER_PROPERTY);
            if (dn == null) {
                log.debug("Bad request, no 'issuer' arg to 'eecert'.");
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=eecert?issuer=<issuerdn>&serno=<serialnumber in hex>.");
                return;
            }
            String serno = req.getParameter(SERNO_PROPERTY);
            if (serno == null) {
                log.debug("Bad request, no 'serno' arg to 'eeceert'.");
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=eecert?issuer=<issuerdn>&serno=<serialnumber in hex>.");
                return;
            }
            if (log.isDebugEnabled()) {
                log.debug("Looking for certificate with issuer/serno '" + dn + "', '" + serno + "'.");
            }
            try {
                // Serial number in hex
                Certificate cert = storesession.findCertificateByIssuerAndSerno(dn, new BigInteger(serno, 16));
                if (cert == null) {
                    log.debug("Error getting End Entity certificate, not found: ");
                    res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting End Entity certificate, not found.");
                    return;
                }
                sendEndEntityCert(administrator, req, res, format, cert);
            } catch (NumberFormatException e) {
                log.debug("Error getting End Entity certificate, invalid serial number (hex): ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting End Entity certificate, invalid serial number (hex).");
                return;
            } catch (CertificateEncodingException e) {
                log.info("Error getting End Entity certificate, invalid certificate?: ", e);
                res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error getting End Entity certificate, invalid certificate.");
                return;
            } catch (NoSuchFieldException e) {
                log.info("Error getting End Entity certificate, can not get field to generate filename?: ", e);
                res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error getting End Entity certificate, invalid certificate.");
                return;
            } catch (AuthorizationDeniedException e) {
                log.error("Error getting End Entity certificate, not authorized to create PKCS7: ", e);
                res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error getting End Entity certificate, not authorized to create PKCS7.");
                return;
            } catch (CesecoreException e) {
                log.info("Error getting End Entity certificate, CA to create PKCS7 does not exist, or can not create PKCS7: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting End Entity certificate, CA to create PKCS7 does not exist, or can not create PKCS7.");
                return;
            }
        } else if (command.equalsIgnoreCase(COMMAND_CERTBYFP)) {
            String fp = req.getParameter(FINGERPRINT_PROPERTY);
            if (fp == null || fp.trim().isEmpty()) {
                log.debug("Bad request, no 'fp' arg to 'certbyfp' command.");
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command="+COMMAND_CERTBYFP+"?"+FINGERPRINT_PROPERTY+"=<fingerprint>.");
                return;
            }
            try {
                final Certificate cert = storesession.findCertificateByFingerprint(fp);
                if (cert == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("No certificate found for requested fingerprint. '" + fp + "'.");
                    }
                    res.sendError(HttpServletResponse.SC_NOT_FOUND, "No certificate found for requested fingerprint.");
                } else {
                    final String dn = CertTools.getSubjectDN(cert);
                    sendEndEntityCert(administrator, req, res, format, cert);
                    if (log.isDebugEnabled()) {
                        log.debug("Sent certificate with fingerprint '" + fp + "' (and Subject DN '" + dn + "') to client at " + remoteAddr);
                    }
                }
            } catch (Exception e) {
                log.debug("Error getting certificate with fingerprint '"+fp+"' for "+remoteAddr+": ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting certificate.");
                return;
            }
        } else if (command.equalsIgnoreCase(COMMAND_LASTCERT) || command.equalsIgnoreCase(COMMAND_LISTCERT)) {
            // HttpServetRequets.getParameter URLDecodes the value for you
            // No need to do it manually, that will cause problems with + characters
        	String dn = req.getParameter(SUBJECT_PROPERTY);
            if (dn == null) {
                log.debug("Bad request, no 'subject' arg to 'lastcert' or 'listcert' command.");
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=lastcert/listcert?subject=<subjectdn>.");
                return;
            }
            try {
                log.debug("Looking for certificates for '"+dn+"'.");
                Collection<Certificate> certcoll = storesession.findCertificatesBySubject(dn);
                Object[] certs = certcoll.toArray();
                if (command.equalsIgnoreCase(COMMAND_LASTCERT)) {
                    long maxdate = 0;
                    int latestcertno = -1;
                    for (int i=0;i<certs.length;i++) {
                        if (i == 0) {
                            maxdate = CertTools.getNotBefore((Certificate)certs[i]).getTime();
                            latestcertno = 0;
                        }
                        else if ( CertTools.getNotBefore((Certificate)certs[i]).getTime() > maxdate ) {
                            maxdate = CertTools.getNotBefore(((Certificate)certs[i])).getTime();
                            latestcertno = i;
                        }
                    }
                    Certificate certcert = null;
                    if (latestcertno > -1) {
                    	certcert = (Certificate)certs[latestcertno];
                    }
                    if (certcert == null) {
                        if (log.isDebugEnabled()) {
                            log.debug("No certificate found for requested subject DN. '" + dn + "'.");
                        }
                        res.sendError(HttpServletResponse.SC_NOT_FOUND, "No certificate found for requested subject DN.");
                    } else {
                        sendEndEntityCert(administrator, req, res, format, certcert);
                        if (log.isDebugEnabled()) {
                            log.debug("Sent latest certificate for '" + dn + "' to client at " + remoteAddr);
                        }
                    }
                }
                if (command.equalsIgnoreCase(COMMAND_LISTCERT)) {
                    res.setContentType("text/html");
                    PrintWriter pout = new PrintWriter(res.getOutputStream());
                    printHtmlHeader("Certificates for "+HTMLTools.htmlescape(dn), pout);
                    for (int i=0;i<certs.length;i++) {
                        Date notBefore = CertTools.getNotBefore((Certificate)certs[i]);
                        Date notAfter = CertTools.getNotAfter((Certificate)certs[i]);
                        String subject = CertTools.getSubjectDN((Certificate)certs[i]);
                        String issuer = CertTools.getIssuerDN((Certificate)certs[i]);
                        BigInteger serno = CertTools.getSerialNumber((Certificate)certs[i]);
                        pout.println("<pre>Subject:"+subject);
                        pout.println("Issuer:"+issuer);
                        pout.println("NotBefore:"+notBefore.toString());
                        pout.println("NotAfter:"+notAfter.toString());
                        pout.println("Serial number:"+serno.toString());
                        pout.println("</pre>");
                        pout.println("<a href=\"certdist?cmd=revoked&issuer="+URLEncoder.encode(issuer, "UTF-8")+"&serno="+serno.toString()+"\">Check if certificate is revoked</a>");
                        pout.println("<hr>");

                    }
                    if (certs.length == 0) {
                        pout.println("No certificates exists for '"+HTMLTools.htmlescape(dn)+"'.");
                    }
                    printHtmlFooter(pout);
                    pout.close();
                }
            } catch (Exception e) {
                log.debug("Error getting certificates for '"+dn+"' for "+remoteAddr+": ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting certificates.");
                return;
            }
        } else if ((command.equalsIgnoreCase(COMMAND_NSCACERT) || command.equalsIgnoreCase(COMMAND_IECACERT) || command.equalsIgnoreCase(COMMAND_CACERT)) && ( issuerdn != null || caid != 0)) {
            String lev = req.getParameter(LEVEL_PROPERTY);
            int level = 0;
            boolean pkcs7 = false;
            try {
                if (lev != null) {
                    level = Integer.parseInt(lev);
                }else {
                    pkcs7 = true;
                }// CA is level 0, next over root level 1 etc etc, -1 returns chain as PKCS7
                Certificate[] chain = null;
                chain = getCertificateChain(caid, issuerdn);
                // chain.length-1 is last cert in chain (root CA)
                if (chain.length < level) {
                    PrintStream ps = new PrintStream(res.getOutputStream());
                    ps.println("No CA certificate of level "+level+" exist.");
                    log.debug("No CA certificate of level "+level+" exist.");
                    return;
                }
                Certificate cacert = chain[level];
                String filename = RequestHelper.getFileNameFromCertNoEnding(cacert, "ca");
                byte[] enccert = null;
                if (pkcs7) {
                    enccert = signSession.createPKCS7(administrator, (X509Certificate) cacert, true);
                } else {
                    enccert = cacert.getEncoded();
                }
                if (command.equalsIgnoreCase(COMMAND_NSCACERT)) {
                    res.setContentType("application/x-x509-ca-cert");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to NS client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_IECACERT)) {
                    // We must remove cache headers for IE
                    ServletUtils.removeCacheHeaders(res);
                    if (pkcs7){
                        res.setHeader("Content-disposition", "attachment; filename=\""+StringTools.stripFilename(filename)+".p7c\"");
                    } else {
                    	String ending = ".crt";
                    	if (cacert instanceof CardVerifiableCertificate) {
                    		ending = ".cvcert";
                    	}
                        res.setHeader("Content-disposition", "attachment; filename=\""+StringTools.stripFilename(filename+ending)+"\"");
                    }
                    res.setContentType("application/octet-stream");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to IE client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_CACERT)) {
                    byte[] b64cert = Base64.encode(enccert);
                    String out;
                    if (pkcs7) {
                        out = "-----BEGIN PKCS7-----\n";
                    } else {
                        out = "-----BEGIN CERTIFICATE-----\n";
                    }
                    out += new String(b64cert);
                    if (pkcs7) {
                        out += "\n-----END PKCS7-----\n";
                    } else {
                        out += "\n-----END CERTIFICATE-----\n";
                    }
                    // We must remove cache headers for IE
                    ServletUtils.removeCacheHeaders(res);
                    res.setHeader("Content-disposition", "attachment; filename=\""+StringTools.stripFilename(filename)+".pem\"");
                    res.setContentType("application/octet-stream");
                    res.setContentLength(out.length());
                    res.getOutputStream().write(out.getBytes());
                    log.debug("Sent CA cert to client, len="+out.length()+".");
                } else {
                    res.setContentType("text/plain");
                    res.getOutputStream().println("Commands="+COMMAND_NSCACERT+" || "+COMMAND_IECACERT+" || "+COMMAND_CACERT);
                    return;
                }
            } catch (NumberFormatException e) {
                log.debug("Invalid level number should be a number: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Invalid level, should be a number.");
                return;
            } catch (Exception e) {
                log.debug("Error getting CA certificates: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting CA certificates.");
                return;
            }
        } else if (command.equalsIgnoreCase(COMMAND_CACHAIN) && ( issuerdn != null || caid != 0)) {
            // Full certificate chain for CA was requested.
            try {
                handleCaChainCommands(issuerdn, caid, format, res);
            } catch (NoSuchFieldException e) {
                log.debug("Error getting certificates for '"+caid+"' for "+remoteAddr+": ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting certificates.");
                return;
            }
        } else if (command.equalsIgnoreCase(COMMAND_REVOKED)) {
            String dn = req.getParameter(ISSUER_PROPERTY);
            if (dn == null) {
                log.debug("Bad request, no 'issuer' arg to 'revoked' command.");
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=revoked?issuer=<issuerdn>&serno=<serialnumber>.");
                return;
            }
            String serno = req.getParameter(SERNO_PROPERTY);
            if (serno == null) {
                log.debug("Bad request, no 'serno' arg to 'revoked' command.");
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Usage command=revoked?issuer=<issuerdn>&serno=<serialnumber>.");
                return;
            }
            log.debug("Looking for certificate for '"+dn+"' and serno='"+serno+"'.");
            try {
                CertificateStatus revinfo = storesession.getStatus(dn, new BigInteger(serno));
                PrintWriter pout = new PrintWriter(res.getOutputStream());
                res.setContentType("text/html");
                printHtmlHeader("Check revocation", pout);
                if (revinfo != null) {
                    if (!revinfo.isRevoked()) {
                        pout.println("<h1>NOT REVOKED</h1>");
                        pout.println("Certificate with issuer '"+HTMLTools.htmlescape(dn)+"' and serial number '"+HTMLTools.htmlescape(serno)+"' is NOT revoked.");
                    } else {
                        pout.println("<h1>REVOKED</h1>");
                        pout.println("Certificate with issuer '"+HTMLTools.htmlescape(dn)+"' and serial number '"+HTMLTools.htmlescape(serno)+"' is revoked.");
                        pout.println("RevocationDate is '"+revinfo.revocationDate+"' and reason '"+revinfo.revocationReason+"'.");
                    }
                } else {
                    pout.println("<h1>CERTIFICATE DOES NOT EXIST</h1>");
                    pout.println("Certificate with issuer '"+HTMLTools.htmlescape(dn)+"' and serial number '"+HTMLTools.htmlescape(serno)+"' does not exist.");
                }
                printHtmlFooter(pout);
                pout.close();
            } catch (Exception e) {
                log.debug("Error checking revocation for '"+dn+"' with serno '"+serno+"': ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error checking revocation.");
                return;
            }
        } else {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Commands=cacert | lastcert | listcerts | crl | deltacrl | revoked && issuer=<issuerdn>");
            return;
        }

    }

    /** Sends a certificate for download to a client */
    private void sendEndEntityCert(final AuthenticationToken administrator, HttpServletRequest req, HttpServletResponse res, String format,
            Certificate certcert) throws CertificateEncodingException, NoSuchFieldException, IOException, CADoesntExistsException,
            SignRequestSignatureException, AuthorizationDeniedException {
        byte[] cert = certcert.getEncoded();
        String ending;
        if (certcert instanceof CardVerifiableCertificate) {
            ending = ".cvcert";
        } else if (StringUtils.equals(format, "PEM") || StringUtils.equals(format, "chain")) {
            ending = ".pem";
        } else if (StringUtils.equals(format, "PKCS7")) {
            ending = ".p7b";
        } else {
            ending = ".crt";
        }
        String filename = RequestHelper.getFileNameFromCertNoEnding(certcert, "ca");
        filename = filename+ending;                        
        // We must remove cache headers for IE
        ServletUtils.removeCacheHeaders(res);
        if ("netscape".equals(req.getParameter(INSTALLTOBROWSER_PROPERTY))) {
            res.setContentType("application/x-x509-user-cert");
        } else {
            res.setHeader("Content-disposition", "attachment; filename=\"" +  StringTools.stripFilename(filename)+"\"");
            res.setContentType("application/octet-stream");
        }
        if (StringUtils.equals(format, "PEM")) {
            RequestHelper.sendNewB64File(Base64.encode(cert, true), res, filename, RequestHelper.BEGIN_CERTIFICATE_WITH_NL, RequestHelper.END_CERTIFICATE_WITH_NL);
        } else if (StringUtils.equals(format, "PKCS7")) {
            byte[] pkcs7 = signSession.createPKCS7(administrator, (X509Certificate) certcert, true);
            RequestHelper.sendNewB64File(Base64.encode(pkcs7, true), res, filename, RequestHelper.BEGIN_PKCS7_WITH_NL, RequestHelper.END_PKCS7_WITH_NL);
        } else if (StringUtils.equals(format, "chain")) {
            int issuerCAId = CertTools.getIssuerDN(certcert).hashCode();
            LinkedList<Certificate> chain = new LinkedList<>(signSession.getCertificateChain(issuerCAId));
            chain.addFirst(certcert);
            byte[] chainbytes = CertTools.getPemFromCertificateChain(chain);
            RequestHelper.sendNewB64File(chainbytes, res, filename, "", ""); // chain includes begin/end already
        } else {
            res.setContentLength(cert.length);
            res.getOutputStream().write(cert);
        }
    } 

	private Certificate[] getCertificateChain(int caid, String issuerdn) {
		Certificate[] chain;
		if(caid != 0) {
		    chain = signSession.getCertificateChain(caid).toArray(new Certificate[0]);
		}
		else {
		    chain = signSession.getCertificateChain(issuerdn.hashCode()).toArray(new Certificate[0]);
		}
		return chain;
	}

	private void handleCaChainCommands(String issuerdn, int caid, String format, HttpServletResponse res) throws IOException, NoSuchFieldException {
		try {
		    // Construct the filename based on requested CA. Fail-back to
            // name "ca-chain.EXT".
            String filename;
			Certificate[] chain = getCertificateChain(caid, issuerdn);
            if (((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                    .getPublicWebCertChainOrderRootFirst()) {
                // Reverse the chain to get proper ordering for chain file
                // (top-level CA first, requested CA last).
                ArrayUtils.reverse(chain);
                filename = RequestHelper.getFileNameFromCertNoEnding(chain[chain.length-1], "ca") + "-chain." + format.toLowerCase();
            } else {
                filename = RequestHelper.getFileNameFromCertNoEnding(chain[0], "ca") + "-chain." + format.toLowerCase();
            }
		

				byte[] outbytes = new byte[0];
				// Encode and send back
				if ((format == null) || StringUtils.equalsIgnoreCase(format, "pem")) {
					outbytes = CertTools.getPemFromCertificateChain(Arrays.asList(chain));
				} else {
					// Create a JKS truststore with the CA certificates in
			        final KeyStore store = KeyStore.getInstance("JKS");
			        store.load(null, null);
			        for (int i = 0; i < chain.length; i++) {
				        String cadn = CertTools.getSubjectDN(chain[i]);
			        	String alias = CertTools.getPartFromDN(cadn, "CN");
			        	if (alias == null) {
			        		alias = CertTools.getPartFromDN(cadn, "O");
			        	}
			        	if (alias == null) {
			        		alias = "cacert"+i;
			        	}
			        	alias = StringUtils.replaceChars(alias, ' ', '_');
			        	alias = StringUtils.substring(alias, 0, 15);
			            store.setCertificateEntry(alias, chain[i]);
			            ByteArrayOutputStream out = new ByteArrayOutputStream();
			            store.store(out, "changeit".toCharArray());
			            out.close();
			            outbytes = out.toByteArray();
			        }
				}
				// We must remove cache headers for IE
				ServletUtils.removeCacheHeaders(res);
				res.setHeader("Content-disposition", "attachment; filename=\""+StringTools.stripFilename(filename)+"\"");
				res.setContentType("application/octet-stream");
				res.setContentLength(outbytes.length);
				res.getOutputStream().write(outbytes);
				log.debug("Sent CA certificate chain to client, len="+outbytes.length+".");						
            } catch (CertificateEncodingException e) {
                log.debug("Error getting CA certificate chain: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting CA certificate chain.");
            } catch (KeyStoreException e) {
                log.debug("Error creating JKS with CA certificate chain: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error creating JKS with CA certificate chain.");
			} catch (NoSuchAlgorithmException e) {
                log.debug("Error creating JKS with CA certificate chain: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error creating JKS with CA certificate chain.");
			} catch (CertificateException e) {
                log.debug("Error creating JKS with CA certificate chain: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error creating JKS with CA certificate chain.");
			} catch (EJBException e) {
                log.debug("CA does not exist: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "CA does not exist: "+HTMLTools.htmlescape(e.getMessage()));
			}
	}
    
    private void printHtmlHeader(String title, PrintWriter pout) {
                pout.println("<html><head>");
                pout.println("<title>"+title+"</title>");
                pout.println("<META HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">");
                pout.println("<META HTTP-EQUIV=\"Expires\" CONTENT=\"-1\">");
                pout.println("</head>");
                pout.println("<body><p>");
    }
    private void printHtmlFooter(PrintWriter pout) {
                pout.println("</body>");
                pout.println("<head>");
                pout.println("<META HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">");
                pout.println("<META HTTP-EQUIV=\"Expires\" CONTENT=\"-1\">");
                pout.println("</head>");
                pout.println("</html>");
    }

}
