package se.anatom.ejbca.protocol;

import java.io.*;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.*;

import org.apache.log4j.Logger;
import org.apache.commons.lang.StringUtils;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.exception.MalformedRequestException;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.util.CertTools;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 * 
 * @author Thomas Meckel (Ophios GmbH)
 * @version  $Id: OCSPServlet.java,v 1.5 2003-12-12 14:59:54 anatom Exp $
 */
public class OCSPServlet extends HttpServlet {

    private static Logger m_log = Logger.getLogger(OCSPServlet.class);

    private ICertificateStoreSessionLocal m_certStore;
    private Admin m_adm;

    private PrivateKey m_signkey;
    private X509Certificate [] m_signcerts;
    private int m_responderIdx;
    private boolean m_reqMustBeSigned;

    protected Collection loadCertificates() 
        throws IOException {
        try {
            Collection cl;
            Iterator iter;
            
            return m_certStore.findCertificatesByType(m_adm, SecConst.CERTTYPE_SUBCA + SecConst.CERTTYPE_ROOTCA, null);
        } catch (Exception e) {
            m_log.error("Unable to load CA certificates from CA store.", e);
            throw new IOException(e.toString());
        }
    }

    protected X509Certificate findCAByHash(CertificateID certId, Collection certs) throws OCSPException {
        if (null == certId) {
            throw new IllegalArgumentException();
        }
        if (null == certs || certs.isEmpty()) {
            m_log.info("The passed certificate collection is empty.");
            return null;
        }
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            X509Certificate cacert = (X509Certificate)iter.next();
            CertificateID issuerId = new CertificateID(certId.getHashAlgOID(), cacert, cacert.getSerialNumber());
            if (m_log.isDebugEnabled()) {
                m_log.debug("Comparing the following certificate hashes:\n"
                            + " Hash algorithm : '" + certId.getHashAlgOID() + "'\n"
                            + " CA certificate hashes\n"
                            + "      Name hash : '" + Hex.encode(issuerId.getIssuerNameHash()) + "'\n"
                            + "      Key hash  : '" + Hex.encode(issuerId.getIssuerKeyHash()) + "'\n"
                            + " OCSP certificate hashes\n"
                            + "      Name hash : '" + Hex.encode(certId.getIssuerNameHash()) + "'\n"
                            + "      Key hash  : '" + Hex.encode(certId.getIssuerKeyHash()) + "'\n");
            }
            if (issuerId.equals(certId)) {
                return cacert;
            }
        }
        return null;
    }

    protected int findCertificateIndexBySubject(X509Certificate [] certs, String subject) 
    {
        if (certs == null || null == subject) {
            throw new IllegalArgumentException();
        }

        if (certs.length <= 0 || subject.length() <= 0) {
            return -1;
        }

        for (int i=0; i<certs.length; i++) {
            if (m_log.isDebugEnabled()) {
                m_log.debug("Checking certificate '"
                            + certs[i].getSubjectDN().getName()
                            + "' against '"
                            + subject
                            + "'");
            }
            if (subject.equalsIgnoreCase(CertTools.stringToBCDNString(certs[i].getSubjectDN().getName()))) {
                return i;
            }
        }
        return -1;
    }

    protected BasicOCSPRespGenerator createOCSPResponse(OCSPReq req) throws OCSPException {
        if (null == req) {
            throw new IllegalArgumentException();
        }
        BasicOCSPRespGenerator res = new BasicOCSPRespGenerator(m_signcerts[m_responderIdx].getPublicKey());
		DERObjectIdentifier id_pkix_ocsp_nonce = new DERObjectIdentifier(OCSPObjectIdentifiers.pkix_ocsp + ".2");
        X509Extension ext = (X509Extension)req.getRequestExtensions().getExtension(id_pkix_ocsp_nonce);
        if (null != ext) {
			X509Extensions exts = X509Extensions.getInstance(ext); 
            res.setResponseExtensions(exts);
        }
        return res;
    }
    
    public void init(ServletConfig config) 
        throws ServletException {
        super.init(config);
        
        try {
            String pkpass;
            String kspwd;
            String pkalias;
            String certalias;
            
            {
                File cwd = new File(".");
                m_log.info("OCSPServlet current working directory : '"
                            + cwd.getAbsolutePath()
                            + "'");
            }
            
            // Parameters for OCSP signing (private) key
            kspwd = config.getInitParameter("keyStorePass").trim();
            if (StringUtils.isEmpty(kspwd)) {
                m_log.error("Keystore password not defined in initialization parameters.");
                throw new ServletException("Missing keystore password.");
            }
            pkalias = config.getInitParameter("privateKeyAlias").trim();
            if (StringUtils.isEmpty(pkalias)) {
                pkalias = "ocspsignkey";
            }            
            pkpass = config.getInitParameter("privateKeyPass").trim();
            if (StringUtils.isEmpty(pkpass)) {
                pkpass = null;
            }
            certalias = config.getInitParameter("certificateAlias").trim();
            if (StringUtils.isEmpty(certalias)) {
                certalias = "ocspsigncert";
            }
            if (m_log.isDebugEnabled()) {
                m_log.debug("Certificate alias : '" + certalias + "'\n");
            }

            /* TODO: move this
            initparam = config.getInitParameter("responderID").trim();
            if (null == initparam || initparam.length() <= 0) {
                final String msg = "Required parameter 'responderID' not set.";
                m_log.error(msg);
                throw new ServletException(msg);
            }
            // Normalize DN in initparam
            initparam = CertTools.stringToBCDNString(initparam);
            m_responderIdx = findCertificateIndexBySubject(m_signcerts, initparam);
            if (m_responderIdx < 0) {
                final String msg = "Unable to find certificate for given responderID.";
                m_log.error(msg);
                throw new ServletException(msg);
            }
            */
            // TODO: END of private signing key todo
            
            String initparam = config.getInitParameter("enforceRequestSigning").trim();
            if (m_log.isDebugEnabled()) {
                m_log.debug("Enforce request signing : '" 
                            + (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
                            + "'");
            }
            m_reqMustBeSigned = true;
            if (!StringUtils.isEmpty(initparam)) {
                if (initparam.equalsIgnoreCase("false") 
                    || initparam.equalsIgnoreCase("no")) {
                    m_reqMustBeSigned = false;
                }
            }
        } catch(Exception e) {
            m_log.error("Unable to initialize OCSPServlet.", e);
            throw new ServletException(e);
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws IOException, ServletException {
        m_log.debug(">doPost()");
        try {
            OCSPResp ocspresp = null;
            BasicOCSPRespGenerator basicRes = null;
            OCSPRespGenerator res = new OCSPRespGenerator();
            try {
                Collection cacerts;
                X509Extension ext = null;

                OCSPReq req = new OCSPReq(request.getInputStream());

                cacerts = loadCertificates();
            
                if (m_log.isDebugEnabled()) {
                    StringBuffer certInfo = new StringBuffer();
                    Iterator iter = cacerts.iterator();
                    while (iter.hasNext()) {
                        X509Certificate cert = (X509Certificate)iter.next();
                        certInfo.append(cert.getSubjectDN().getName());
                        certInfo.append(',');
                        certInfo.append(cert.getSerialNumber().toString());
                        certInfo.append('\n');
                    }
                    m_log.debug("Found the following CA certificates : \n" 
                                + certInfo.toString());
                }

                basicRes = createOCSPResponse(req);
            
                /**
                 * check the signature if contained in request.
                 * if the request does not contain a signature
                 * and the servlet is configured in the way 
                 * the a signature is required we send back
                 * 'sigRequired' response.
                 */
                if (m_log.isDebugEnabled()) {
                    m_log.debug("Incoming OCSP request is signed : " + req.isSigned());
                }
                if (m_reqMustBeSigned) {
                    if (!req.isSigned()) {
                        m_log.info("OCSP request unsigned. Servlet enforces signing.");
                        throw new SignRequestException("OCSP request unsigned. Servlet enforces signing.");
                    }                
                    GeneralName requestor = req.getRequestorName();
                    X509Certificate[] certs = req.getCerts("BC");
                    PublicKey pk = null;
                    // We must find a cert to verify the signature with...
                    boolean verifyOK = false;
                    for (int i=0;i<certs.length;i++) {
                        if (req.verify(certs[i].getPublicKey(), "BC") == true) {
                          verifyOK = true;  
                          break;
                        }
                    }
                    if (!verifyOK) {                    
                        m_log.info("Signature of incoming OCSPRequest is invalid.");
                        throw new SignRequestSignatureException("Signature invalid.");
                    }
                }
            
                /**
                 * FIXME: tmeckel
                 * How to implement the list of allowed
                 * OCSP clients which are allowed to talk?
                 * 
                 * check if requestor is allowed to talk
                 * to the CA if not send back a 'unauthorized'
                 * response
                 */
                //throw new OCSPUnauthorizedException()
                Req[] requests = req.getRequestList();
                if (requests.length <= 0) {
                    String msg = "The OCSP request does not contain any simpleRequest entities.";
                    m_log.error(msg);
                    throw new MalformedRequestException(msg);
                } else {
                    for (int i=0;i<requests.length;i++) {
                        X509Certificate cacert = null;
                        X509Certificate cert = null;
                        CertificateID certId = requests[i].getCertID();
                        RevokedCertInfo rci;
                    
                        try {
                            cacert = findCAByHash(certId, cacerts);
                        } catch (OCSPException e) {
                            m_log.info("Unable to generate CA certificate hash.", e);    
                            cacert = null;
                            continue;
                        }
                        if (null == cacert) {
                            m_log.info("Unable to find CA certificate by hash.");
                            basicRes.addResponse(certId, new UnknownStatus());
                            continue;                    
                        }

                        /*
                         * Implement logic according to
                         * chapter 2.7 in RFC2560
                         * 
                         * 2.7  CA Key Compromise
                         *    If an OCSP responder knows that a particular CA's private key has
                         *    been compromised, it MAY return the revoked state for all
                         *    certificates issued by that CA.
                         */
                        rci = m_certStore.isRevoked(m_adm
                                               , cacert.getIssuerDN().getName()
                                               , cacert.getSerialNumber());
                        if (null != rci 
                            && rci.getReason() == RevokedCertInfo.NOT_REVOKED) {
                            rci = null;
                        }
                        if (null == rci) {
                            rci = m_certStore.isRevoked(m_adm
                                                   , cacert.getSubjectDN().getName()
                                                   , certId.getSerialNumber());
                            if (null == rci) {
                                m_log.info("Unable to find revocation information for certificate with serial '"
                                           + certId.getSerialNumber() + "'"
                                           + " from issuer '" + cacert.getSubjectDN().getName() + "'");
                                basicRes.addResponse(certId, new UnknownStatus());
                            } else {
                                CertificateStatus certStatus = null; // null mean good
                                if (rci.getReason() != RevokedCertInfo.NOT_REVOKED) {
                                    certStatus = new RevokedStatus(new RevokedInfo(
                                        new DERGeneralizedTime(rci.getRevocationDate()), 
                                        new CRLReason(rci.getReason())));
                                } else {
                                    certStatus = null;
                                }
                                if (m_log.isDebugEnabled()) {
                                    m_log.info("Adding status information for certificate with serial '"
                                               + certId.getSerialNumber() + "'"
                                               + " from issuer '" + cacert.getSubjectDN().getName() + "'");
                                }
                                basicRes.addResponse(certId, certStatus);
                            }
                        } else {
                            CertificateStatus certStatus = new RevokedStatus(new RevokedInfo(
                                new DERGeneralizedTime(rci.getRevocationDate()), 
                                new CRLReason(rci.getReason())));
                            basicRes.addResponse(certId, certStatus);
                        }
                    }
                    basicRes.generate("sha1withrsa", m_signkey, m_signcerts, new Date(), "BC" );
                    ocspresp = res.generate(OCSPRespGenerator.SUCCESSFUL, basicRes);
                }
            } catch (MalformedRequestException e) {
                m_log.info("MalformedRequestException caught : ", e);
                ocspresp = res.generate(OCSPRespGenerator.MALFORMED_REQUEST, basicRes);
            } catch (SignRequestException e) {
                m_log.info("SignRequestException caught : ", e);
                ocspresp = res.generate(OCSPRespGenerator.SIG_REQUIRED, basicRes);
            } catch (Exception e) {
                m_log.error("Unable to handle OCSP request.", e);
                ocspresp = res.generate(OCSPRespGenerator.INTERNAL_ERROR, basicRes);
            }
            response.getOutputStream().write(ocspresp.getEncoded());
        } catch (OCSPException e) {
            m_log.error("OCSPException caught, fatal error : ", e);
            throw new ServletException(e);
        }        
        m_log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest request,  HttpServletResponse response) 
        throws IOException, ServletException {
        m_log.debug(">doGet()");
        /**
         * We only support POST operation, so return
         * an appropriate HTTP error code to caller.
         */
        m_log.debug("<doGet()");
    } // doGet

} // OCSPServlet
