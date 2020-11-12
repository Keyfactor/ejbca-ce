/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;

import com.digicert.autoenroll.DigicertCA;
import com.digicert.autoenroll.DigicertRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/**
 * WS based enrollment background: https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/certificate-enrollment-web-services/ba-p/397385
 * MS-XCEP: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/
 * MS-WCCE: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/
 * Advanced use cases: https://www.sysadmins.lv/blog-en/certificate-autoenrollment-in-windows-server-2016-part-4.aspx
 * 
 * @version $Id$
 */
// TODO Review this code to see what is read-only data that should be loaded only once (e.g., the OID map file, the template to profile map). 
public class MSEnrollmentServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(MSEnrollmentServlet.class);
    private static final long serialVersionUID = 1130199310912912438L;

    private LinkedHashMap<String, TemplateSettings> templateSettingsMap = new LinkedHashMap<>();
    private EJBCA ejbca;
    private DigicertCA digicertCA;
    private PublisherProperties msaesProperties;
    private ApplicationProperties msEnrollmentProperties;
    private String ca;
    private ADConnection adConnection;

    @Override
    public void init() throws ServletException {
        CryptoProviderTools.installBCProvider();

        // load configs
        ConfigLoader configLoader = new ConfigLoader(getServletContext());
        String configDirectory;
        if (configLoader.loadContext()) {
            configDirectory = ConfigLoader.getPathToConfigDirectory();
            if (!configDirectory.endsWith("/")) {
                configDirectory += "/";
            }
        } else {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("==== Config Directory ====");
            log.debug(configDirectory);
        }

        //Load MS Template to Settings config
        MSTemplateToSettings msts = new MSTemplateToSettings();
        try {
            templateSettingsMap = msts.load(configDirectory);
        } catch (Exception e) {
            log.fatal(e);
            throw new ServletException(e);
        }

        msEnrollmentProperties = new ApplicationProperties(configDirectory);
        ca = msEnrollmentProperties.getCA();

        if (ca.equalsIgnoreCase("ejbca")) {
            WebServiceConnection webServiceConnection = new WebServiceConnection(msEnrollmentProperties);
            ejbca = new EJBCA(webServiceConnection);
        } else if (ca.equalsIgnoreCase("digicert")) {
            digicertCA = new DigicertCA(msEnrollmentProperties);
            for(Map.Entry<String, TemplateSettings> entry : templateSettingsMap.entrySet()) {
                TemplateSettings templateSettings = entry.getValue();
                try {
                    templateSettings.validateTemplateSettings(msEnrollmentProperties);
                } catch (IOException | EnrollmentException e) {
                    log.fatal(e);
                    log.fatal("Template Settings validation failed. Check your configuration.");
                    throw new ServletException(e);
                }
            }
        }

        msaesProperties = new PublisherProperties(configDirectory);
        adConnection = new ADConnection(msaesProperties);
        if (log.isDebugEnabled()) {
            log.debug("AD connection initiated with parameters:");
            log.debug("usessl: " + adConnection.isUseSSL());
            log.debug("port: " + adConnection.getPort());
            log.debug("loginDN: " + adConnection.getLoginDN());
        }
    }

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request  servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    private void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        final String strContentType = request.getHeader("content-type");

        // If it is a real MS request, it will be a soap request, process that.
        if ((null != strContentType) && strContentType.startsWith("application/soap+xml;")) {
            if (log.isDebugEnabled()) {
                log.debug(getDebugOut(request, "\n"));
            }
            log.info("*** Start handling of enrollment request at: " + new Date());

            response.setContentType("application/soap+xml;charset=UTF-8");
            doSoapRequest(request, response);

            return;
        }

        // If it was not an MS request, but a simple GET request we just print back some information to the user.
        log.info("*** Start handling of non-enrollment request at: " + new Date());
        response.setContentType("text/html;charset=UTF-8");

        try (PrintWriter out = response.getWriter()) {
            /* output your page here */
            // Nothing interesting here; just output something about the http request, headers and such.
            out.println("<html>");
            out.println("<head>");
            out.println("<title>MS AutoEnrollment Proxy</title>");
            out.println("</head>");
            out.println("<body>");
            out.println("<h1>MSEnrollmentServlet at " + HTMLTools.htmlescape(request.getContextPath()) + "</h1>");

            out.println(getDebugOut(request, "<br>"));

            out.println("</body>");
            out.println("</html>");
        }
    }

    /**
     * Important to HTMLEsxcpe any output that may contain user provided input. This prevents XSS attacks
     *
     * @param request
     * @param nl
     * @return String with HTMLescaped debug information
     * @throws IOException if there are errors with byte array output stream, i.e. out of memory(?)
     */
    private String getDebugOut(HttpServletRequest request, String nl) throws IOException {
        try (
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                PrintWriter out = new PrintWriter(baos)) {

            // Just output something about the http request, headers and such.
            out.println(new Date() + nl);

            out.println(nl + "Headers:" + nl);

            Enumeration<String> enumHeaderNames = request.getHeaderNames();
            while (enumHeaderNames.hasMoreElements()) {
                String str = HTMLTools.htmlescape(enumHeaderNames.nextElement());
                out.println(str + ": " + HTMLTools.htmlescape(request.getHeader(str)) + nl);
            }

            out.println(nl + "Parameters:" + nl);

            Enumeration<String> enumParameters = request.getParameterNames();
            while (enumParameters.hasMoreElements()) {
                String str = HTMLTools.htmlescape(enumParameters.nextElement());
                out.println(str + ": " + HTMLTools.htmlescape(request.getParameter(str)) + nl);
            }

            HttpSession session = request.getSession();
            Enumeration<String> attrs = session.getAttributeNames();
            while (attrs.hasMoreElements()) {
                String attr = attrs.nextElement();
                out.println("Attr: [" + HTMLTools.htmlescape(attr) + "], Value: [" + HTMLTools.htmlescape(String.valueOf(session.getAttribute(attr))) + ", ID:" + HTMLTools.htmlescape(session.getId()) + nl);
            }

            out.println(nl + "Requested Session Id: " + request.getRequestedSessionId() + nl);
            out.println(nl + "Request URI: " + HTMLTools.htmlescape(request.getRequestURI()) + nl);
            out.println(nl + "Query String: " + HTMLTools.htmlescape(request.getQueryString()));

            out.flush();
            return baos.toString();
        }
    }

    private void doSoapRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {

            if (log.isTraceEnabled()) {
                log.trace("Request AuthType: [" + request.getAuthType() + "]");
                log.trace("Request Session: [" + request.getSession() + "]");
            }
            log.info("Account Name: [" + request.getRemoteUser() + "]");
            log.info("Principal Name: [" + request.getUserPrincipal().toString() + "]");

            final String domain = request.getUserPrincipal().toString().substring(request.getUserPrincipal().toString().indexOf("@") + 1);
            final String searchBase = "DC=" + domain.replaceAll("\\.", ",DC=");

            if (log.isDebugEnabled()) {
                log.debug("Domain: [" + domain + "]");
                log.debug("Base DN: [" + searchBase + "]");
            }
            final int contentLength = Integer.parseInt(request.getHeader("content-length"));
            final char[] cbuf = new char[contentLength];

            String enc = request.getCharacterEncoding();
            if (enc == null) {
                enc = "UTF-8";
            }
            final BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream(), enc));
            int offset = 0;
            int numRead = 0;
            while (0 < (numRead = reader.read(cbuf, offset, contentLength - offset))) {
                offset += numRead;
            }

            final String contents = new String(cbuf);

            if (log.isTraceEnabled()) {
                log.trace("contentLength = " + contentLength + ", numRead = " + numRead + ", encoding = " + request.getCharacterEncoding());
                log.trace("Contents [" + contents + "]");

                int indexStart = contents.indexOf("<");
                while (-1 != indexStart) {
                    int indexEnd = contents.indexOf(">", indexStart);
                    if (-1 == indexEnd) {
                        break;
                    }
                    log.trace(contents.substring(indexStart, indexEnd + 1));

                    indexStart = contents.indexOf("<", indexEnd);
                    if (indexStart > indexEnd + 1) {
                        log.trace("\t" + contents.substring(indexEnd + 1, indexStart));
                    }
                }
            }

            final String username = getUsernameFromContents(contents, request);
            final String sAMAccountName = getRemoteUser(request);

            String pkcs10request = getPKCS10Request(contents);
            if (log.isDebugEnabled()) {
                log.debug("PKCS10 Request: [" + pkcs10request + "]");
            }

            String templateOID = getTemplateOID(pkcs10request);
            if (null == templateOID) {
                throw new EnrollmentException("*** No OID was found in the PKCS10 request. ***");
            }
            if (log.isDebugEnabled()) {
                log.debug("Template OID: [" + templateOID + "]");
            }
            final TemplateSettings templateSettings = templateSettingsMap.get(templateOID);
            if (null == templateSettings) {
                throw new EnrollmentException("*** No settings found for template with OID: "
                        + templateOID + " or it was disabled. ***");
            }

            ADObject adObject = new ADObject(adConnection);
            adObject.getADDetails(templateSettings, searchBase, sAMAccountName, domain);

            X509Certificate x509cert = handlePkcs10request(contents, username, domain, pkcs10request, adObject, templateSettings, response);

            //Publish certificate to Active Directory if option set to true
            boolean publish_to_active_directory = templateSettings.isPublish_to_active_directory();
            if (publish_to_active_directory) {
                if (log.isDebugEnabled()) {
                    log.debug("=== publish_to_active_directory: " + publish_to_active_directory);
                }
                String distinguishedName = adObject.getDistinguishedName();
                if (adConnection.publishCertificateToLDAP(distinguishedName, x509cert, domain)) {
                    log.info("Certificate published to Active Directory for: " + distinguishedName);
                } else {
                    throw new EnrollmentException("Error publishing certificate to Active Directory for: " + distinguishedName);
                }
            }


        } catch (Exception exc) {
            log.info(exc);
        }
    }

    // Use this just to invoke getEjbcaVersion as a simple test to see if the EJBCA web services are working.
    void test() {
        WebServiceConnection ws = new WebServiceConnection();
        ws.test();
    }

    private String getTemplateOID(String pkcs10request) throws IOException, EnrollmentException {
        final PKCS10RequestMessage msg = new PKCS10RequestMessage(Base64.decode(pkcs10request.getBytes()));
        final Extensions requestExtensions = msg.getRequestExtensions();

        //Get Microsoft Certificate Template information from the CSR
        final String msTemplateHexValue = ASN1.msTemplateValueHexFormat(requestExtensions);
        final HashMap<String,String> templateOID = ASN1.msTemplateValueToASN1Strings(msTemplateHexValue);

        return templateOID.get("oid");
    }

    private X509Certificate handlePkcs10request(String contents, String username, String domain, String pkcs10request,
            ADObject adObject, TemplateSettings templateSettings, HttpServletResponse response)
            throws ServletException, IOException, CMSException, CertificateException {
        PrintWriter out = response.getWriter();
        StringBuilder sbOut = new StringBuilder();
        X509Certificate x509cert = null;

        String relatesTo = findTagValue("a:MessageID", contents);
        /**
         * TODO Do we need to put a lock around this try block so that each
         * request is handled serially? There is no static mutable data and
         * there is only a single call to the EJBCA web service, so this is
         * probably not necessary.
         */
        try {
            if (log.isTraceEnabled()) {
                final PKCS10CertificationRequest pkcs10CertReq = new PKCS10CertificationRequest(Base64.decode(pkcs10request.getBytes()));
                final ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(pkcs10CertReq.getEncoded()));
                final ASN1Object obj = ais.readObject();
                log.trace(ASN1Dump.dumpAsString(obj, true));
                X500Name subjectName = pkcs10CertReq.getSubject();
                log.trace("p10 subject name [" + subjectName.toString() + "]");
                log.trace("p10 attributes [" + pkcs10CertReq.getAttributes().toString() + "]");
            }

//            PKCS10Info pkcs10Info = new PKCS10Info();
//            ASN1.dump(obj, pkcs10Info);

            /**
             * Note: Can't use the following, because when invoked using
             * Kerberos authentication, the following line throws an exception:
             * sun.security.pkcs.ParsingException: Unsupported PKCS9 attribute:
             * 1.3.6.1.4.1.311.13.2.3 In this case, we wouldn't have a way to
             * get the subject name.
             */
//            PKCS10 p10 = new PKCS10(Base64.decode(pkcs10request));
//            System.out.println(p10.toString());
//            System.out.println("subjectname: [" + p10.getSubjectName().toString() + "] " + p10.getSubjectName().getCommonName());
            
            final PKCS10RequestMessage msg = new PKCS10RequestMessage(Base64.decode(pkcs10request.getBytes()));

            /**
             * TODO Replace with PKCS10Info data set by ASN1.dump? Need more doc
             * on how to parse alt names. This seems to be an octet string
             * consisting of a sequence of the following: an integer indicating
             * a type (eg, email, dns), followed by a length, followed by a
             * string of the specified length. Would need a list of these
             * integer types to be able to add this parsing to ASN1.java.
             */
//            String issuerDN = msg.getIssuerDN();
//            System.out.println("issuer DN: " + issuerDN);
//            String requestDN = msg.getRequestDN();
//            System.out.println("req DN: " + requestDN);
            final Extensions requestExtensions = msg.getRequestExtensions();
            if (log.isTraceEnabled()) {
                log.trace("req extensions: " + requestExtensions);
            }

            //Get Microsoft Certificate Template information from the CSR
            final String msTemplateHexValue = ASN1.msTemplateValueHexFormat(requestExtensions);

            //Generate input and issue certificate depending on CA
            byte[] issuedCertificate = null;
            if (ca.equalsIgnoreCase("ejbca")) {
                EJBCARequest ejbcaRequest = new EJBCARequest(msEnrollmentProperties, templateSettings, adObject, username, msTemplateHexValue, pkcs10request);
                issuedCertificate = ejbcaRequest.certificateRequest(ejbca);
            } else if (ca.equalsIgnoreCase("digicert")) {
                DigicertRequest digicertRequest = new DigicertRequest(templateSettings, adObject, domain, pkcs10request, msTemplateHexValue);
                issuedCertificate = digicertRequest.certificateRequest(digicertCA);
            }

            if (issuedCertificate == null) {
                throw new EnrollmentException("No certificates were received during the enrollment request!");
            }

            byte[] firstCertificate = CertUtils.getFirstCertificateFromPKCS7(issuedCertificate);

            final String strCertResult = new String(Base64.encode(firstCertificate));
            final String strCertChain = new String(Base64.encode(issuedCertificate));

            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            final InputStream in = new ByteArrayInputStream(firstCertificate);
            x509cert = (X509Certificate) certFactory.generateCertificate(in);

            log.info("Certificate created for " + username + " with SubjectDN: " + x509cert.getSubjectDN());

            if (log.isDebugEnabled()) {
                log.debug("CertResult Encoded: [" + strCertResult + "]");
            }

            if (log.isTraceEnabled()) {

                final PKCS7ResponseDecoder res = new PKCS7ResponseDecoder(issuedCertificate);
                final int numCertificates = res.numCertificates();
                log.trace("Num certificates: " + numCertificates);

                assert (2 <= numCertificates);
                for (int i = 0; i < numCertificates; i++) {
                    log.trace("Certificate(" + i + ") = [" + res.getCertificate(i).toString() + "]");
                }

                final X509Certificate certCA = res.getCertificate(1);
                log.trace("Length CA encoded = " + certCA.getEncoded().length);

                final X509Certificate certResult = res.getCertificate(0);
                log.trace("Length certResult encoded = " + certResult.getEncoded().length);
            }

            /*
             * TODO What does "Z" at end of time strings mean as in:
             * <u:Created>2011-12-06T20:23:17.828Z</u:Created>
             * "Z" can't go into format string because it indicates a time zone there.
             * Perhaps it is used in formatting the returned creation time string later on?  Or does it indicate that the timezone is GMT?
             * Similar question about "T"?  Is it a delimiter or for formatting or something else?
             */
            SimpleDateFormat df1 = new SimpleDateFormat("yyyy-MM-dd"); // Should be GMT.
            df1.setTimeZone(TimeZone.getTimeZone("GMT"));
            SimpleDateFormat df2 = new SimpleDateFormat("hh:mm:ss.SSS");
            df2.setTimeZone(TimeZone.getTimeZone("GMT"));
//            System.out.println("Response: [" + df1.format(certResponse.getCertificate().getNotBefore()) + "T" + df2.format(certResponse.getCertificate().getNotBefore()) + "Z]");
//            System.out.println("Response: [" + df1.format(certResponse.getCertificate().getNotAfter()) + "T" + df2.format(certResponse.getCertificate().getNotAfter()) + "Z]");

            try {
                sbOut.append("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">");
                sbOut.append("<s:Header>");
                sbOut.append("<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>");
                // sbOut.appendln("Relates to: [" + relatesTo + "]");
                sbOut.append("<a:RelatesTo>").append(relatesTo).append("</a:RelatesTo>");
                // TODO What should go into the ActivityId tag?  
                // Currently, a dummy value (copied from a successful request to an MS CA) is used.
                // Information on ActivityId: http://msdn.microsoft.com/en-us/library/cc485806(v=prot.10).aspx
                // It has something to do with activity tracing (and the Windows Event Viewer?).
                //String activityId = findTagValue("ActivityId", contents);
                // log.debug("activityId: [" + activityId + "]");
                sbOut.append("<ActivityId CorrelationId=\"1a764189-0ec7-4dd8-b26d-1d5ecfd66fae\" xmlns=\"http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics\">00000000-0000-0000-0000-000000000000</ActivityId>");
                sbOut.append("<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                // TODO What does the following line mean?
                sbOut.append("<u:Timestamp u:Id=\"_0\">");
                String strCreated = df1.format(x509cert.getNotBefore()) + "T" + df2.format(x509cert.getNotBefore()) + "Z";
                sbOut.append("<u:Created>").append(strCreated).append("</u:Created>");
                sbOut.append("<u:Expires>").append(df1.format(x509cert.getNotAfter())).append("T").append(df2.format(x509cert.getNotAfter())).append("Z</u:Expires>");
                sbOut.append("</u:Timestamp>");
                sbOut.append("</o:Security>");
                sbOut.append("</s:Header>");
                sbOut.append("<s:Body>");
                sbOut.append("<RequestSecurityTokenResponseCollection xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">");
                sbOut.append("<RequestSecurityTokenResponse>");
                sbOut.append("<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>");
                sbOut.append("<DispositionMessage xml:lang=\"en-US\" xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">Issued</DispositionMessage>");

                sbOut.append("<BinarySecurityToken ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                sbOut.append(strCertChain);
                sbOut.append("</BinarySecurityToken>");

                /**
                 * Note that there is some question as to whether the response
                 * is correctly formatted. Does it need carriage returns
                 * embedded in the XML? Probably not. Should the response string
                 * start on the BinarySecurityToken line?
                 *
                 * As the current formatting is accepted by the client, this is
                 * not an urgent issue.
                 */
                sbOut.append("<RequestedSecurityToken>");
                sbOut.append("<BinarySecurityToken ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                sbOut.append(strCertResult);
                sbOut.append("</BinarySecurityToken>");
                sbOut.append("</RequestedSecurityToken>");

                /**
                 * *********
                 * For the MS CA, the RequestID is a unique (integer?) value
                 * that is associated with the request to create a certificate.
                 * If you use Server Manager on MS Windows Server, then under
                 * Roles | Active Directory Certificate Services, choose a CA
                 * and look at Issued Certificates, you will see that the table
                 * listing the certificates has "RequestID" as the first column.
                 *
                 * TODO: What is comparable in EJBCA that can be used to
                 * associate the request with an item in the EJBCA database? For
                 * now, use the creation time so that the result can be queried
                 * in EJBCA.
                 */
                sbOut.append("<RequestID xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">");
                sbOut.append(strCreated);
                sbOut.append("</RequestID>");
                sbOut.append("</RequestSecurityTokenResponse>");
                sbOut.append("</RequestSecurityTokenResponseCollection>");
                sbOut.append("</s:Body>");
                sbOut.append("</s:Envelope>");

                log.info("*** Enrollment success ***");

            } catch (Exception ex) {
                // Let outside exception handler catch and respond.
                throw (ex);
            }
        } catch (Exception ex) {
            log.info("Exception caught: ", ex);
            if (false) {
                // This is the way it is documented as the format to return a failure;
                // however, useful information explaining the problem does not appear in the Windows Client.

                // 4.1.4.2 Server Fault Response
                // Clear buffer
                sbOut = new StringBuilder();

                sbOut.append("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\">");
                sbOut.append("<s:Header>");
                sbOut.append("<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/net/2005/12/windowscommunicationfoundation/dispatcher/fault</a:Action>");
                sbOut.append("<a:RelatesTo>").append(relatesTo).append("</a:RelatesTo>");
                sbOut.append("<ActivityId CorrelationId=\"4f0e4425-4883-41c1-b704-771135d18f84\" xmlns=\"http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics\">eda7e63d-0c42-455d-9c4f-47ab85803a50</ActivityId>");
                sbOut.append("</s:Header>");
                sbOut.append("<s:Body>");
                sbOut.append("<s:Fault>");
                sbOut.append("<s:Code>");
                sbOut.append("<s:Value>s:Receiver</s:Value>");
                sbOut.append("<s:Subcode>");
                sbOut.append("<s:Value xmlns:a=\"http://schemas.microsoft.com/net/2005/12/windowscommunicationfoundation/dispatcher\">a:InternalServiceFault</s:Value>");
                sbOut.append("</s:Subcode>");
                sbOut.append("</s:Code>");
                sbOut.append("<s:Reason>");
                /**
                 * TODO: Include stack trace as well as exception message? Or
                 * some additional information (time stamp?) that will help
                 * pinpoint info in server log?
                 */
                sbOut.append("<s:Text xml:lang=\"en-US\">The server was unable to process the request due to an internal error: ").append(ex.toString()).append("</s:Text>");
                sbOut.append("</s:Reason>");
                sbOut.append("</s:Fault>");
                sbOut.append("</s:Body>");
                sbOut.append("</s:Envelope>");
            } else {
                // Use the response format with deliberately missing or incorrect fields so that Windows client can display a more meaningful message than
                // that produced by the above soap fault format.
                // Otherwise, tracing has to be enabled on the client and Event Viewer has to be waded through in order to find any meaningful error messages.

                sbOut.append("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">");
                sbOut.append("<s:Header>");
                sbOut.append("<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>");
                sbOut.append("<a:RelatesTo>").append(relatesTo).append("</a:RelatesTo>");
                sbOut.append("<ActivityId CorrelationId=\"1a764189-0ec7-4dd8-b26d-1d5ecfd66fae\" xmlns=\"http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics\">00000000-0000-0000-0000-000000000000</ActivityId>");
                sbOut.append("<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                sbOut.append("</o:Security>");
                sbOut.append("</s:Header>");
                sbOut.append("<s:Body>");
                sbOut.append("<RequestSecurityTokenResponseCollection xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">");
                sbOut.append("<RequestSecurityTokenResponse>");
                sbOut.append("<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>");
                sbOut.append("<DispositionMessage xml:lang=\"en-US\" xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">Issued</DispositionMessage>");

                sbOut.append("<BinarySecurityToken ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                sbOut.append("sdfgdsfg");  // Something invalid, but not empty
                sbOut.append("</BinarySecurityToken>");

                sbOut.append("<RequestedSecurityToken>");
                sbOut.append("<BinarySecurityToken ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                sbOut.append("esrfgd");  // Something invalid, but not empty
                sbOut.append("</BinarySecurityToken>");
                sbOut.append("</RequestedSecurityToken>");

                /* 
                 * *** Note that we use the RequestID field to return a more helpful error message to the Windows client.
                 */
                sbOut.append("<RequestID xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">");
                // Message appears with prefix of "The request ID is " created by Windows client.
                // Since we can't remove it, we add the following to make the message a little clearer:
                sbOut.append(" not provided by EJBCA.\n");
                sbOut.append("The following exception was reported:\n ").append(ex.toString());
                sbOut.append("</RequestID>");
                sbOut.append("</RequestSecurityTokenResponse>");
                sbOut.append("</RequestSecurityTokenResponseCollection>");
                sbOut.append("</s:Body>");
                sbOut.append("</s:Envelope>");
            }

            log.info("*** Enrollment failure ***");
        } finally {
            out.print(sbOut.toString());
            out.close();
        }

        return x509cert;
    }

    private String getUsernameFromContents(String contents, HttpServletRequest request) {
        String username = findTagValue("o:Username>", contents);   // Need trailing ">" to avoid finding o:UsernameToken
        // This is what we expect to be the case when authentication is done via Kerberos.
        if (null == username) {
            // TODO use Principal.toString() or Principal.getName()?
            // Simple tests suggest that there is no difference, but is that true in general?
            username = request.getUserPrincipal().toString();
            username = username.replace("$", "");

            /**
             * When authentication is to be done via Kerberos, the
             * RequestSecurityToken also includes something like the following:
             *
             * <AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
             * <ContextItem Name="cdc"><Value>WIN-6LI9K21TSMS.test.Autumn14.org</Value></ContextItem>
             * <ContextItem Name="rmd"><Value>WinServer2008Test.test.Autumn14.org</Value></ContextItem>
             * <ContextItem Name="ccm"><Value>WinServer2008Test.test.Autumn14.org</Value></ContextItem>
             * </AdditionalContext></RequestSecurityToken>
             */
        } else {
            // Username/password authentication was used in this case.

            // TODO Provide a mechanism for authenticating the username/password values.
        }
        if (log.isDebugEnabled()) {
            log.debug("User: " + username);
        }
        return username;
    }

    private String getRemoteUser(HttpServletRequest request) {
        String remoteuser = null;

        // This is what we expect to be the case when authentication is done via Kerberos.
        if (null == remoteuser) {
            remoteuser = request.getRemoteUser();

        } else {
            // Username/password authentication was used in this case.

            // TODO Provide a mechanism for authenticating the username/password values.
        }
        if (log.isDebugEnabled()) {
            log.debug("RemoteUser: " + remoteuser);
        }
        return remoteuser;
    }

    private static String findTagValue(String tag, String contents) {
        String start = "<" + tag;
        int indexStart = contents.indexOf(start);
        if (-1 == indexStart) {
            return null;
        }

        int indexStart2 = contents.indexOf(">", indexStart);
        if (-1 == indexStart2) {
            return null;
        }

        String end = "</" + tag;
        if (!end.endsWith(">")) {
            end += ">";
        }
        int indexEnd = contents.indexOf(end, indexStart2);
        if (-1 == indexEnd) {
            return null;
        }

        String result = contents.substring(indexStart2 + 1, indexEnd);
        return result;
    }

    private static String findTagAttribute(String tag, String attr, String contents) {
        String start = "<" + tag;
        int indexStart = contents.indexOf(start);
        if (-1 == indexStart) {
            return null;
        }

        int indexEnd = contents.indexOf(">", indexStart);
        if (-1 == indexEnd) {
            return null;
        }

        String attrs = contents.substring(indexStart, indexEnd + 1);
//        System.out.println("Tag " + tag + " with attrs: [" + attrs + "]");

        String attr0 = " " + attr + "=\"";

        int indexStart2 = attrs.indexOf(attr0);
        if (-1 == indexStart2) {
            return null;
        }
        int indexEnd2 = attrs.indexOf("\" ", indexStart2);
        if (-1 == indexEnd2) {
            return null;
        }

        String result = attrs.substring(indexStart2 + attr0.length(), indexEnd2);
        return result;
    }

    private String getPKCS10Request(String contents) throws IOException, CMSException, GeneralSecurityException {
        // If the MS Certificate Template has a PolicySchema value of 1, then the request is in PKCS10 format.
        // If the value is 2, then it is in PKCS7 format.
        // (PolicySchema is a tag in the XML defining the poicy in the cached GetPoliciesResponse file).
        // Evidently 3 is also a valid value, according to
        //      http://msdn.microsoft.com/en-us/library/dd358327%28v=prot.10%29.aspx
        // but no explanation of what "3" means is given.
        // 3 implies PKCS7 format as well.
        // By examination,
        //  1 seems to mean that Windows 2000 is the minimum supported CA,
        //  2 means Windows Server 2003 Enterprise,
        //  3 means Windows Server 2008 Enterprise.

        String strValueType = findTagAttribute("BinarySecurityToken", "ValueType", contents);
        assert (null != strValueType);
        assert (strValueType.endsWith("#PKCS7") || strValueType.endsWith("#PKCS10"));
        // Parse out the value of the BinarySecurityToken tag from the content string.
        String binarySecurityToken = findTagValue("BinarySecurityToken", contents);
        // Remove new line characters placed in XML by MS.
        //log.trace("Length = " + binarySecurityToken.length());

        //            binarySecurityToken = binarySecurityToken.replaceAll("&#xD;\n", "");
        binarySecurityToken = binarySecurityToken.replaceAll("&#xD;", "");
        //log.trace("Tag value: [" + binarySecurityToken + "]");

        String pkcs10request = binarySecurityToken;

        if (strValueType.endsWith("#PKCS7")) {
            //log.trace("*** PKCS7 found ***");

            RequestDecoder req = new RequestDecoder(Base64.decode(binarySecurityToken.getBytes()));
            //log.trace("PKCS #10 blob is " + req.getPKCS10Blob().length + " bytes");

            pkcs10request = new String(Base64.encode(req.getPKCS10Blob()));
            //log.trace("PKCS #10 blob [" + pkcs10request + "]");
        }

        return pkcs10request;
    }

    private String getRequesterHostname(CertificationRequestInfo certificationRequestInfo) {

        //Get hostname from CSR p10 attributes
        Enumeration p10 = certificationRequestInfo.getAttributes().getObjects();

        String hostname = null;

        while (p10.hasMoreElements()) {
            DERSequence p10_attributes = (DERSequence) p10.nextElement();
            String attr_oid = p10_attributes.getObjectAt(0).toString();

            if (attr_oid.equals("1.3.6.1.4.1.311.21.20")) {
                String attrvalue = p10_attributes.getObjectAt(1).toString();
                List<String> items = Arrays.asList(attrvalue.split("\\s*,\\s*"));
                hostname = items.get(1);
            }
        }

        return hostname;
    }

// <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">

    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request  servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request  servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        /**
         * TODO: What should this description be?
         */
        return "EJBCA Enrollment from MS Windows Client";
    }// </editor-fold>
}
