package se.anatom.ejbca.hardtoken;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocal.java,v 1.4 2003-09-03 20:05:28 herrvendil Exp $
 **/

public interface HardTokenCertificateMapLocal extends javax.ejb.EJBLocalObject {

    // Public methods
    
    public String getCertificateFingerprint();
    
    public String getTokenSN();

    public void setTokenSN(String tokensn);
}

