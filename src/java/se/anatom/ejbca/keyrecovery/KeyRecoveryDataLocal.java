package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;
import java.security.KeyPair;

/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocal.java,v 1.2 2003-02-27 08:43:25 anatom Exp $
 **/

public interface KeyRecoveryDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public BigInteger getCertificateSN();
    public void setCertificateSN(BigInteger certificatesn);

    public String getIssuerDN();
    public void setIssuerDN(String issuerdn);

    public String getUsername();
    /** username must be called 'striped' using StringTools.strip()
    * @see se.anatom.ejbca.util.StringTools
    */
    public void setUsername(String username);

    public boolean getMarkedAsRecoverable();
    public void setMarkedAsRecoverable(boolean markedasrecoverable);

    public KeyPair getKeyPair();
    public void setKeyPair(KeyPair keypair);
}

