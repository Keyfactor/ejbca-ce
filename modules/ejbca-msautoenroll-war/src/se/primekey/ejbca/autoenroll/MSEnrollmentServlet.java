/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package se.primekey.ejbca.autoenroll;

/**
 * @author Daniel Horn, SiO2 Corp.
 * 
 * @version $Id$
 */
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.TimeZone;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.common.CertificateHelper;

// TODO Review this code to see what is read-only data that should be loaded only once (e.g., the OID map file, the template to profile map). 
public class MSEnrollmentServlet extends HttpServlet
{

    private static boolean debug = false;
    private static boolean debug2 = true;

    /** 
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        if (debug2)
        {
            System.out.println("*** Start handling of enrollment request at: " + new Date());
        }

        String strContentType = request.getHeader("content-type");
        if ((null != strContentType) && strContentType.startsWith("application/soap+xml;"))
        {
// <editor-fold defaultstate="collapsed" desc="Debug Info. Click on the + sign on the left to edit the code.">
            if (debug)
            {
//                Properties props = System.getProperties();
//                System.out.println("**** Props: [" + props + "]");

                HttpSession session = request.getSession();

                Enumeration attrs = session.getAttributeNames();
                while (attrs.hasMoreElements())
                {
                    String attr = (String) attrs.nextElement();
                    System.out.println("Attr: [" + attr + "], Value: [" + session.getAttribute(attr) + ", ID:" + session.getId());
                }

                System.out.println("<\nHeaders:\n");

                Enumeration enumHeaderNames = request.getHeaderNames();
                while (enumHeaderNames.hasMoreElements())
                {
                    String str = (String) enumHeaderNames.nextElement();
                    System.out.println(str + ": " + request.getHeader(str));
                }

                System.out.println("\nParameters:\n");

                Enumeration enumParameters = request.getParameterNames();
                while (enumParameters.hasMoreElements())
                {
                    String str = (String) enumParameters.nextElement();
                    System.out.println(str + ": " + request.getParameter(str));
                }

                System.out.println("\nRequest URI: " + request.getRequestURI());
                System.out.println("\nRequest URL: " + request.getRequestURL());

                System.out.println("\nQuery String: " + request.getQueryString());
                System.out.println("\nRequested Session Id: " + request.getRequestedSessionId());
                System.out.println("\nSession: " + request.getSession());
            }
            // </editor-fold>

            response.setContentType("application/soap+xml;charset=UTF-8");
            doSoapRequest(request, response);

            return;
        }

// <editor-fold defaultstate="collapsed" desc="Output page when request not made using web services.  Nothing interesting to see here. Click on the + sign on the left to edit the code.">
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        try
        {
            /* output your page here */
            // Nothing interesting here; just output something about the http request, headers and such.
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet MSEnrollmentServlet</title>");
            out.println("</head>");
            out.println("<body>");
            out.println("<h1>Servlet MSEnrollmentServlet at " + request.getContextPath() + "</h1>");

            out.println(new Date());

            out.println("<br>Headers:<br><br>");
            System.out.println("<\nHeaders:\n");

            Enumeration enumHeaderNames = request.getHeaderNames();
            while (enumHeaderNames.hasMoreElements())
            {
                String str = (String) enumHeaderNames.nextElement();
                out.println(str + ": " + request.getHeader(str) + "<br>");
                System.out.println(str + ": " + request.getHeader(str));
            }

            out.println("<br>Parameters:<br><br>");
            System.out.println("\nParameters:\n");

            Enumeration enumParameters = request.getParameterNames();
            while (enumParameters.hasMoreElements())
            {
                String str = (String) enumParameters.nextElement();
                out.println(str + ": " + request.getParameter(str) + "<br>");
                System.out.println(str + ": " + request.getParameter(str));
            }

            out.println("<br>Request URI: " + request.getRequestURI() + "<br>");
            System.out.println("\nRequest URI: " + request.getRequestURI());

            System.out.println("\nQuery String: " + request.getQueryString());

            out.println("</body>");
            out.println("</html>");
            /* */
        }
        finally
        {
            out.close();
        }
        // </editor-fold>
    }

    void doSoapRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        try
        {
            if (debug2)
            {
                System.out.println("Request AuthType: [" + request.getAuthType() + "]");
                System.out.println("Request RemoteUser: [" + request.getRemoteUser() + "]");
                System.out.println("Request UserPrincipal: [" + request.getUserPrincipal().toString() + "], [" + request.getUserPrincipal().getName() + "]");
                System.out.println("Request Session: [" + request.getSession() + "]");
            }

            int contentLength = Integer.parseInt(request.getHeader("content-length"));
            char[] cbuf = new char[contentLength];

            String enc = request.getCharacterEncoding();
            if (enc == null)
            {
                enc = "UTF-8";
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream(), enc));
            int offset = 0;
            int numRead = 0;
            while (0 < (numRead = reader.read(cbuf, offset, contentLength - offset)))
            {
//                System.out.println("cbuf [" + new String(cbuf) + "]");
                offset += numRead;
            }

            String contents = new String(cbuf);

// <editor-fold defaultstate="collapsed" desc="Debug Info. Click on the + sign on the left to edit the code.">
            if (debug)
            {
                System.out.println("contentLength = " + contentLength + ", numRead = " + numRead + ", encoding = " + request.getCharacterEncoding());

                System.out.println("Contents [" + contents + "]");

                int indexStart = contents.indexOf("<");
                while (-1 != indexStart)
                {
                    int indexEnd = contents.indexOf(">", indexStart);
                    if (-1 == indexEnd)
                    {
                        break;
                    }
                    System.out.println(contents.substring(indexStart, indexEnd + 1));

                    indexStart = contents.indexOf("<", indexEnd);
                    if (indexStart > indexEnd + 1)
                    {
                        System.out.println("\t" + contents.substring(indexEnd + 1, indexStart));
                    }
                }
            }
            // </editor-fold>

//            test();

            handlePkcs10request(contents, request, response);
        }
        catch (Exception exc)
        {
            System.out.println(exc);
        }
    }

    // Use this just to invoke getEjbcaVersion as a simple test to see if the EJBCA web services are working.
    void test()
    {
        WebServiceConnection ws = new WebServiceConnection(new ApplicationProperties(getServletContext()));
        ws.test();
    }

    void handlePkcs10request(String contents, HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        PrintWriter out = response.getWriter();
        StringBuilder sbOut = new StringBuilder();

        String relatesTo = findTagValue("a:MessageID", contents);

        String username = findTagValue("o:Username>", contents);   // Need trailing ">" to avoid finding o:UsernameToken
        String password = findTagValue("o:Password", contents);
        // This is what we expect to be the case when authentication is done via Kerberos.
        if (null == username)
        {
            // TODO use Principal.toString() or Principal.getName()?
            // Simple tests suggest that there is no difference, but is that true in general?
            username = request.getUserPrincipal().toString();

            /** When authentication is to be done via Kerberos, the
             * RequestSecurityToken also includes something like the following:
             *
            <AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
            <ContextItem Name="cdc"><Value>WIN-6LI9K21TSMS.test.Autumn14.org</Value></ContextItem>
            <ContextItem Name="rmd"><Value>WinServer2008Test.test.Autumn14.org</Value></ContextItem>
            <ContextItem Name="ccm"><Value>WinServer2008Test.test.Autumn14.org</Value></ContextItem>
            </AdditionalContext></RequestSecurityToken>
             */
        }
        else
        {
            // Username/password authentication was used in this case.
            
            // TODO Provide a mechanism for authenticating the username/password values.
        }
        if (debug2)
        {
            System.out.println("User: " + username + ", Password: " + password);
        }


        /**
         * TODO Do we need to put a lock around this try block so that each request is handled serially?
         * There is no static mutable data and there is only a single call to the EJBCA web service, so this is probably not necessary.
         */
        try
        {
            String pkcs10request = getPKCS10Request(contents);
            if (debug)
            {
                System.out.println("PKCS10 Request: [" + pkcs10request + "]");
            }

            // Found something called MSPKCS10RequestMessage in v. 5.x of EJBCA but it doesn't
            // really show anything more than already parsed by ASN1.java
//            MSPKCS10RequestMessage mspkcs10 = new MSPKCS10RequestMessage(Base64.decode(pkcs10request));
//            String mSRequestInfoTemplateName = mspkcs10.getMSRequestInfoTemplateName();
//            System.out.println("msRequestInfoTemplateName: [" + mSRequestInfoTemplateName + "]");
//            String mSRequestInfoDNS = mspkcs10.getMSRequestInfoDNS();
//            System.out.println("msRequestInfoDNS: [" + mSRequestInfoDNS + "]");
//            String[] mSRequestInfoSubjectAltnames = mspkcs10.getMSRequestInfoSubjectAltnames();
//            for (int i = 0; i < mSRequestInfoSubjectAltnames.length; i++)
//            {
//                System.out.println(i + ": altname [" + mSRequestInfoSubjectAltnames[i] + "]");
//            }
//            // Make this public to see what it returns.
//            ArrayList mSRequestInfo = mspkcs10.getMSRequestInfo();
//            for (int i = 0; i < mSRequestInfo.size(); i++)
//            {
//                System.out.println(i + ": request info [" + mSRequestInfo.get(i) + "]");
//            }

            final PKCS10CertificationRequest pkcs10CertReq = new PKCS10CertificationRequest(Base64.decode(pkcs10request));
//          System.out.println("Verified: " + pkcs10CertReq.verify());
            CertificationRequestInfo certificationRequestInfo = pkcs10CertReq.getCertificationRequestInfo();
            X500Name subject = certificationRequestInfo.getSubject();
            System.out.println("Subject = [" + subject + "]");

            final ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(pkcs10CertReq.getEncoded()));
            final ASN1Primitive obj = ais.readObject();
            String dumpAsString = ASN1Dump.dumpAsString(obj, true);
            System.out.println(dumpAsString);

            PKCS10Info pkcs10Info = new PKCS10Info();
            ASN1.dump((ASN1Object) obj.toASN1Object(), pkcs10Info, true);
            System.out.println(pkcs10Info);

            /**
             * Note:  Can't use the following, because when invoked using Kerberos authentication, the following line throws an exception:
             *      sun.security.pkcs.ParsingException: Unsupported PKCS9 attribute: 1.3.6.1.4.1.311.13.2.3
             * In this case, we wouldn't have a way to get the subject name.
             */
//            PKCS10 p10 = new PKCS10(Base64.decode(pkcs10request));
//            System.out.println(p10.toString());
//            System.out.println("subjectname: [" + p10.getSubjectName().toString() + "] " + p10.getSubjectName().getCommonName());
            /**
             * TODO Where should this file be located with respect to application and appserver?  Probably into WEB-INF directory.
             * TODO Since it is read-only info, only load it once.
             */
            MSTemplateToEJBCAProfileMap profileMap = new MSTemplateToEJBCAProfileMap();
            profileMap.load(getServletContext());
//            System.out.println(profileMap.toString());
            String certificateProfileName = pkcs10Info.getEJBCACertificateProfileName(profileMap);
            // Nothing more can be done if no certificate profile corresponding to the certificate template in the request was found.
            if (null == certificateProfileName)
            {
                String temp = "*** No certificate profile corresponding to " + pkcs10Info.toMessage() + " was found. ***";

                throw new EnrollmentException(temp);
            }
            System.out.println("Certificate Profile to use: " + certificateProfileName);

//            X500Name subjectName = p10.getSubjectName();
            X500Name subjectName = certificationRequestInfo.getSubject();
            System.out.println("p10 subject name [" + subjectName.toString() + "]");
//            System.out.println("p10 attributes [" + p10.getAttributes().toString() + "]");
            System.out.println("p10 attributes [" + certificationRequestInfo.getAttributes().toString() + "]");

            PKCS10RequestMessage msg = new PKCS10RequestMessage(Base64.decode(pkcs10request));
            // This returns a string in a format supported by user1.setSubjectAltName(strSubjectName);
            /**
             * TODO Replace with PKCS10Info data set by ASN1.dump?
             * Need more doc on how to parse alt names.
             * This seems to be an octet string consisting of a sequence of the following:
             * an integer indicating a type (eg, email, dns), followed by a length, followed by a string of the specified length.
             * Would need a list of these integer types to be able to add this parsing to ASN1.java.
             */
            String requestAltNames = msg.getRequestAltNames();
            System.out.println("req alt names: " + requestAltNames);
//            String issuerDN = msg.getIssuerDN();
//            System.out.println("issuer DN: " + issuerDN);
//            String requestDN = msg.getRequestDN();
//            System.out.println("req DN: " + requestDN);
            Extensions requestExtensions = msg.getRequestExtensions();
            System.out.println("req extensions: " + requestExtensions.toASN1Object());
//            ASN1.dump((ASN1Object) requestExtensions.toASN1Object(), pkcs10Info, true);

            /** 
             * TODO: What should these settings be,
             * how should they be configured,
             * and
             * how should these settings be passed to this servlet?
             * 
             * See individual questions below.
             * 
             */
            UserDataVOWS user1 = new UserDataVOWS();

            /**
             * TODO userName cannot be empty or null.  Do we need any additional checks here?
             */
            user1.setUsername(username);
            /**
             * TODO: 
             * Currently, the end entity profile doesn't have the password marked as required.
             * If it should be required, the following statement needs to be uncommented.
             * *** And the password used probably should be uniquely generated for each request.
             */
//            user1.setPassword("M$3n40113e21Password1");

            /*
             * TODO Which Subject DN attributes need to be supported in the end entity profile?
             * Currently, list matches those in list of "Subject" tab of "Certificate Properties" for Windows Certificate Enrollment.
             */
            /**
             * TODO What should default subjectDN be?
             * Does this make sense?
             * 
             * Note that, with Kerberos, in the following scenario, the subject DN name will most likely be CN=<the user principal name>.
             * If this isn't correct, can Kerberos be somehow used to determine an appropriate DN name?
             * For example, with EJBCA, a subject DN might be "CN = DPH2@TEST.AUTUMN14.ORG",
             * while the same request made to the MS CA would have a DN of 
             "CN = DPH2
              CN = Users
              DC = test
              DC = Autumn14
              DC = org"
             */
            String strSubjectName = null;
            if (null != subjectName)
            {
                strSubjectName = subjectName.toString();
            }
            System.out.println("*** Subject Name = " + subjectName);
            if ((null != strSubjectName) && (0 < strSubjectName.length()))
            {
                user1.setSubjectDN(strSubjectName);

                /**
                 * TODO Is this a valid end entity name?
                 */
//                    user1.setUsername(strSubjectName);
            }
            else
            {
                /**
                 * TODO EJBCA appears to require a non-empty DN.
                 * Is this true?
                 * And is the following an adequate default?
                 * Should it be the value of CN?  (Does that mean CN should always be required?  (A certificate template issue?)
                 */
                user1.setSubjectDN("CN=" + user1.getUsername());
            }

            /**
             * TODO Which subject alternative name attributes need to be supported?
             * Currently, matches list in Windows client with following exceptions:
             *      IP address (v6) not supported by EJBCA?
             *      "Registered ID"?
             *      "Other name"?
             * If they are assigned values in the Windows client, the request is reported as
             * successful though these values are evidently ignored by EJBCA as they don't appear in the generated certificate. 
             */
            if ((null != requestAltNames) && (0 < requestAltNames.length()))
            {
                user1.setSubjectAltName(requestAltNames);
            }

            user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);


            /**
             * Choice of certificate profile is determined by profile map entry for certificate name (in the case of a 2000 certificate template)
             * or for the OID of the (2003 or 2008) certificate template in the request.
             */
            user1.setCertificateProfileName(certificateProfileName);

// <editor-fold defaultstate="collapsed" desc="Experimental. Click on the + sign on the left to edit the code.">
            /**
             * TODO Does anything need to be added as extendedInformation?
             * If so, what is the correct way to use this?
             */
//            if (debug)
//            {
//                LinkedList<ExtendedInformationWS> list = new LinkedList<ExtendedInformationWS>();
//                ExtendedInformationWS infoWS = new ExtendedInformationWS("Friendly", "My Custom Data");
//                infoWS.setName("1.2.3.4.5.6.7.8");
//                infoWS.setValue(Base64.encode("My Custome data".getBytes()));
//                list.add(infoWS);
//                ExtendedInformationWS infoWS2 = new ExtendedInformationWS("Description", Base64.encode("My Custom Data23".getBytes()));
//                infoWS2.setName("[1.2.840.113549.1.9.15");
//                infoWS2.setValue(Base64.encode("My Custome data23r4212345".getBytes()));
//                list.add(infoWS2);
//                ExtendedInformationWS infoWS3 = new ExtendedInformationWS();
//                infoWS3.setName(Base64.encode("[1.2.840.113549.1.9.15".getBytes()));
//                infoWS3.setValue(Base64.encode("smime My Custome data23r4212345".getBytes()));
//                list.add(infoWS3);
//                user1.setExtendedInformation(list);
//            }
            // </editor-fold>

            user1.setStatus(UserDataVOWS.STATUS_NEW);

            final ApplicationProperties applicationProperties = new ApplicationProperties(getServletContext());
            
            // The CA Name is user-configurable.
            user1.setCaName(applicationProperties.getCAName());

            /**
             * TODO The end entity profile name probably should be user-configurable as well.
             * Add support for this to the application properties file.
             */
            user1.setEndEntityProfileName("WindowsClientEnrollment");


            WebServiceConnection ws = new WebServiceConnection(applicationProperties);

            /** 
             * TODO Is there any difference between the two requests below?
             * Or any reason to prefer one over the other?
             * 
             * Evidently, certificateRequest handles the call to editUser for you.
             * 
             * We choose certificateRequest simply because then we need to make only one web service call instead of two.
             */
//            ws.editUser(user1);
//            CertificateResponse certResponse = ws.pkcs10Request(user1.getUsername(),
//                    user1.getPassword(),
//                    pkcs10request, // base64 encoded PKCS10
//                    null, // No hardtokenSN associated with certificate 
//                    CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN);
            
            // certificateRequest handles the editUser call so it is to be preferred to the combination of two calls (editUser and pkcs10Request)`
            CertificateResponse certResponse = ws.certificateRequest(user1,
                    pkcs10request,
                    CertificateHelper.CERT_REQ_TYPE_PKCS10,
                    null,
                    CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN);
//          System.out.println("Response: [" + certResponse.getCertificate() + "]");

            List<org.ejbca.core.protocol.ws.client.gen.Certificate> certs = ws.getLastCertChain(user1.getUsername());
            int numCerts = certs.size();
            assert (numCerts >= 2);

            if (debug)
            {
                for (int i = 0; i < numCerts; i++)
                {
                    org.ejbca.core.protocol.ws.client.gen.Certificate cert = certs.get(i);
                    System.out.println(i + ": [" + new String(cert.getCertificateData()) + "]");
                }
            }

            byte[] bytes = certResponse.getData();
            String strBytes = new String(bytes);

            String strCertChain = strBytes;
//            System.out.println("CertChain: [" + strCertChain + "]");

            String strCertResult = new String(certs.get(0).getCertificateData());
//            System.out.println("CertResult Encoded: [" + strCertResult + "]");

// <editor-fold defaultstate="collapsed" desc="Debugging Info. Click on the + sign on the left to edit the code.">
            if (debug)
            {
                byte[] pkcs7bytes = certResponse.getRawData();

                PKCS7ResponseDecoder res = new PKCS7ResponseDecoder(pkcs7bytes);
                int numCertificates = res.numCertificates();
                System.out.println("Num certificates: " + numCertificates);

                assert (2 <= numCertificates);
                for (int i = 0; i < numCertificates; i++)
                {
                    System.out.println("Certificate(" + i + ") = [" + res.getCertificate(i).toString() + "]");
                }

                X509Certificate certCA = res.getCertificate(1);
                System.out.println("Length CA encoded = " + certCA.getEncoded().length);

                X509Certificate certResult = res.getCertificate(0);
                System.out.println("Length certResult encoded = " + certResult.getEncoded().length);
            }
            // </editor-fold>


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

            try
            {
                sbOut.append("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">");
                sbOut.append("<s:Header>");
                sbOut.append("<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>");
//                System.sbOut.appendln("Relates to: [" + relatesTo + "]");
                sbOut.append("<a:RelatesTo>").append(relatesTo).append("</a:RelatesTo>");
                // TODO What should go into the ActivityId tag?  
                // Currently, a dummy value (copied from a successful request to an MS CA) is used.
                // Information on ActivityId: http://msdn.microsoft.com/en-us/library/cc485806(v=prot.10).aspx
                // It has something to do with activity tracing (and the Windows Event Viewer?).
                String activityId = findTagValue("ActivityId", contents);
//                System.out.println("activityId: [" + activityId + "]");
                sbOut.append("<ActivityId CorrelationId=\"1a764189-0ec7-4dd8-b26d-1d5ecfd66fae\" xmlns=\"http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics\">00000000-0000-0000-0000-000000000000</ActivityId>");
                sbOut.append("<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                // TODO What does the following line mean?
                sbOut.append("<u:Timestamp u:Id=\"_0\">");
                String strCreated = df1.format(certResponse.getCertificate().getNotBefore()) + "T" + df2.format(certResponse.getCertificate().getNotBefore()) + "Z";
                sbOut.append("<u:Created>").append(strCreated).append("</u:Created>");
                sbOut.append("<u:Expires>").append(df1.format(certResponse.getCertificate().getNotAfter())).append("T").append(df2.format(certResponse.getCertificate().getNotAfter())).append("Z</u:Expires>");
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
                 * Note that there is some question as to whether the response is correctly formatted.
                 * Does it need carriage returns embedded in the XML?  Probably not.
                 * Should the response string start on the BinarySecurityToken line?
                 * 
                 * As the current formatting is accepted by the client, this is not an urgent issue.
                 */
                sbOut.append("<RequestedSecurityToken>");
                sbOut.append("<BinarySecurityToken ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
                sbOut.append(strCertResult);
                sbOut.append("</BinarySecurityToken>");
                sbOut.append("</RequestedSecurityToken>");

                /*********** 
                 * For the MS CA, the RequestID is a unique (integer?) value that is associated with the request to create a certificate.
                 * If you use Server Manager on MS Windows Server, then under Roles | Active Directory Certificate Services, choose a CA and look at
                 * Issued Certificates, you will see that the table listing the certificates has "RequestID" as the first column.
                 * 
                 * TODO:  What is comparable in EJBCA that can be used to associate the request with an item in the EJBCA database?
                 * For now, use the creation time so that the result can be queried in EJBCA.
                 */
                sbOut.append("<RequestID xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">");
                sbOut.append(strCreated);
                sbOut.append("</RequestID>");
                sbOut.append("</RequestSecurityTokenResponse>");
                sbOut.append("</RequestSecurityTokenResponseCollection>");
                sbOut.append("</s:Body>");
                sbOut.append("</s:Envelope>");

                if (debug2)
                {
                    System.out.println("*** Enrollment success ***");
                }
            }
            catch (Exception ex)
            {
                // Let outside exception handler catch and respond.
                throw (ex);
            }
        }
        catch (Exception ex)
        {
//            System.out.println(ex.toString());  // Exception name plus message
            ex.printStackTrace();

//            Logger.getLogger(MSEnrollmentServlet.class.getName()).log(Level.SEVERE, null, ex);

            if (false)
            {
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
                 * TODO: Include stack trace as well as exception message?
                 * Or some additional information (time stamp?) that will help pinpoint info in server log?
                 */
                sbOut.append("<s:Text xml:lang=\"en-US\">The server was unable to process the request due to an internal error: ").append(ex.toString()).append("</s:Text>");
                sbOut.append("</s:Reason>");
                sbOut.append("</s:Fault>");
                sbOut.append("</s:Body>");
                sbOut.append("</s:Envelope>");
            }
            else
            {
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

            if (debug2)
            {
                System.out.println("*** Enrollment failure ***");
            }
        }
        finally
        {
            out.print(sbOut.toString());

            out.close();

//            System.out.println("PrintWriter: [" + sbOut + "]");
        }
    }

// <editor-fold defaultstate="collapsed" desc="XML Parsing methods. Click on the + sign on the left to edit the code.">
    private static String getPKCS10Request(String contents) throws IOException, CMSException, GeneralSecurityException
    {
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
        if (debug)
        {
            System.out.println("Length = " + binarySecurityToken.length());
        }
        //            binarySecurityToken = binarySecurityToken.replaceAll("&#xD;\n", "");
        binarySecurityToken = binarySecurityToken.replaceAll("&#xD;", "");
        if (debug)
        {
            System.out.println("Tag value: [" + binarySecurityToken + "]");
        }
        String pkcs10request = binarySecurityToken;

        if (strValueType.endsWith("#PKCS7"))
        {
            if (debug)
            {
                System.out.println("*** PKCS7 found ***");
            }

            RequestDecoder req = new RequestDecoder(Base64.decode(binarySecurityToken));

            if (debug)
            {
                System.out.println("PKCS #10 blob is " + req.getPKCS10Blob().length + " bytes");
            }

            pkcs10request = new String(Base64.encode(req.getPKCS10Blob()));
            if (debug)
            {
                System.out.println("PKCS #10 blob [" + pkcs10request + "]");
            }
        }

        return pkcs10request;
    }

    private static String findTagValue(String tag, String contents)
    {
        String start = "<" + tag;
        int indexStart = contents.indexOf(start);
        if (-1 == indexStart)
        {
            return null;
        }

        int indexStart2 = contents.indexOf(">", indexStart);
        if (-1 == indexStart2)
        {
            return null;
        }

        String end = "</" + tag;
        if (!end.endsWith(">"))
        {
            end += ">";
        }
        int indexEnd = contents.indexOf(end, indexStart2);
        if (-1 == indexEnd)
        {
            return null;
        }

        String result = contents.substring(indexStart2 + 1, indexEnd);
//        System.out.println("Tag " + tag + " value: [" + result + "]");

        return result;
    }

    private static String findTagAttribute(String tag, String attr, String contents)
    {
        String start = "<" + tag;
        int indexStart = contents.indexOf(start);
        if (-1 == indexStart)
        {
            return null;
        }

        int indexEnd = contents.indexOf(">", indexStart);
        if (-1 == indexEnd)
        {
            return null;
        }

        String attrs = contents.substring(indexStart, indexEnd + 1);
//        System.out.println("Tag " + tag + " with attrs: [" + attrs + "]");

        StringBuilder sbAttr = new StringBuilder(" ");
        sbAttr.append(attr).append("=\"");
        String attr0 = sbAttr.toString();

        int indexStart2 = attrs.indexOf(attr0);
        if (-1 == indexStart2)
        {
            return null;
        }
        int indexEnd2 = attrs.indexOf("\" ", indexStart2);
        if (-1 == indexEnd2)
        {
            return null;
        }

        String result = attrs.substring(indexStart2 + attr0.length(), indexEnd2);

//        System.out.println("\t[" + result + "]");

        return result;
    }
    // </editor-fold>

// <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /** 
     * Handles the HTTP <code>GET</code> method.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        processRequest(request, response);
    }

    /** 
     * Handles the HTTP <code>POST</code> method.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        processRequest(request, response);
    }

    /** 
     * Returns a short description of the servlet.
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo()
    {
        /**
         * TODO: What should this description be?
         */
        return "EJBCA Enrollment from MS Windows Client";
    }// </editor-fold>
}
