package se.anatom.ejbca.hardtoken;

import java.security.cert.X509Certificate;
import java.math.BigInteger;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocal.java,v 1.1 2003-02-06 15:35:46 herrvendil Exp $
 **/

public interface HardTokenCertificateMapLocal extends javax.ejb.EJBLocalObject {

    // Public methods
    
    public String getCertificateFingerprint();
    
    public String getTokenSN();

    public void setTokenSN(String tokensn);
}

