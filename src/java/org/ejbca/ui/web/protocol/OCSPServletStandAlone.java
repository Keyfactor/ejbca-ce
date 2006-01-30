package org.ejbca.ui.web.protocol;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.CertificateDataLocalHome;
import org.ejbca.core.ejb.ca.store.CertificateDataUtil;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 * 
 * @web.servlet name = "OCSP"
 *              display-name = "OCSPServlet"
 *              description="Answers OCSP requests"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/ocsp"
 *
 * @web.servlet-init-param description="Algorithm used by server to generate signature on OCSP responses"
 *   name="SignatureAlgorithm"
 *   value="SHA1WithRSA"
 *   
 * @web.servlet-init-param description="If set to true the servlet will enforce OCSP request signing"
 *   name="enforceRequestSigning"
 *   value="false"
 *   
 * @web.servlet-init-param description="If set to true the certificate chain will be returned with the OCSP response"
 *   name="includeCertChain"
 *   value="true"
 *   
 * @web.servlet-init-param description="If set to true the OCSP reponses will be signed directly by the CAs certificate instead of the CAs OCSP responder"
 *   name="useCASigningCert"
 *   value="${ocsp.usecasigningcert}"
 *   
 * @web.servlet-init-param description="Specifies the subject of a certificate which is used to identifiy the responder which will generate responses when no real CA can be found from the request. This is used to generate 'unknown' responses when a request is received for a certificate that is not signed by any CA on this server"
 *   name="defaultResponderID"
 *   value="${ocsp.defaultresponder}"
 *   
 *   
 *
 */
public class OCSPServletStandAlone extends OCSPServletBase implements CertificateDataUtil.Client {

    /**
     * The home interface of Certificate entity bean
     */
    private CertificateDataLocalHome certHome = null;

    /* (non-Javadoc)
     * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        certHome = (CertificateDataLocalHome)ServiceLocator.getInstance().getLocalHome(CertificateDataLocalHome.COMP_NAME);
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#findCertificatesByType(org.ejbca.core.model.log.Admin, int, java.lang.String)
     */
    Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
        return CertificateDataUtil.findCertificatesByType(adm, type, issuerDN, certHome, this);
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#extendedService(org.ejbca.core.model.log.Admin, int, org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest)
     */
    OCSPCAServiceResponse extendedService(Admin m_adm2, int caid, OCSPCAServiceRequest request) throws CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#isRevoked(org.ejbca.core.model.log.Admin, java.lang.String, java.math.BigInteger)
     */
    RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serialNumber) {
        return CertificateDataUtil.isRevoked(admin, issuerDN, serialNumber, certHome, this);
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Client#debug(java.lang.String)
     */
    public void debug(String s) {
        m_log.debug(s);
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Client#getLogger()
     */
    public Logger getLogger() {
        return m_log;
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.ejb.ca.store.CertificateDataUtil.Client#log(org.ejbca.core.model.log.Admin, int, int, java.util.Date, java.lang.String, java.security.cert.X509Certificate, int, java.lang.String)
     */
    public void log( Admin admin, int caid, int module, Date time, String username,
                     X509Certificate certificate, int event, String comment ) {
    }
}
