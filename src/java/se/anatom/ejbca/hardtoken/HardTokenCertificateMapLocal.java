package se.anatom.ejbca.hardtoken;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocal.java,v 1.5 2004-01-09 09:35:43 anatom Exp $
 **/

public interface HardTokenCertificateMapLocal extends javax.ejb.EJBLocalObject {

    // Public methods
    public String getCertificateFingerprint();    
    public String getTokenSN();
    public void setTokenSN(String tokenSN);
}

