package se.anatom.ejbca.hardtoken;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocal.java,v 1.2 2003-02-09 14:56:16 anatom Exp $
 **/

public interface HardTokenCertificateMapLocal extends javax.ejb.EJBLocalObject {

    // Public methods
    
    public String getCertificateFingerprint();
    
    public String getTokenSN();

    public void setTokenSN(String tokensn);
}

