package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;

import java.security.KeyPair;


/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocal.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface KeyRecoveryDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public BigInteger getCertificateSN();

    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     */
    public void setCertificateSN(BigInteger certificatesn);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getIssuerDN();

    /**
     * DOCUMENT ME!
     *
     * @param issuerdn DOCUMENT ME!
     */
    public void setIssuerDN(String issuerdn);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public void setUsername(String username);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getMarkedAsRecoverable();

    /**
     * DOCUMENT ME!
     *
     * @param markedasrecoverable DOCUMENT ME!
     */
    public void setMarkedAsRecoverable(boolean markedasrecoverable);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public KeyPair getKeyPair();

    /**
     * DOCUMENT ME!
     *
     * @param keypair DOCUMENT ME!
     */
    public void setKeyPair(KeyPair keypair);
}
