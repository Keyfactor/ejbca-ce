package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;
import java.security.KeyPair;

/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocal.java,v 1.1 2003-02-12 13:21:30 herrvendil Exp $
 **/

public interface KeyRecoveryDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public BigInteger getCertificateSN();   
    public void setCertificateSN(BigInteger certificatesn);   
 
    public String getIssuerDN();   
    public void setIssuerDN(String issuerdn);   
    
    public String getUsername();
    public void setUsername(String username);                       
        
    public boolean getMarkedAsRecoverable();   
    public void setMarkedAsRecoverable(boolean markedasrecoverable);
    
    public KeyPair getKeyPair(); 
    public void setKeyPair(KeyPair keypair);
}

