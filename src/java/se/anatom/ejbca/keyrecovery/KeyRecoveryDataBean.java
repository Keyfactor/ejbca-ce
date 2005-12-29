/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package se.anatom.ejbca.keyrecovery;

import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.StringTools;

import javax.ejb.CreateException;
import java.math.BigInteger;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * certificates key recovery data in the ra. Information stored:
 * <pre>
 *  pk (Primary key, hashcodes of certificatesn and issuerdn)
 *  certificatesn
 *  issuerdn
 *  username
 *  markedasrecoverable
 *  keypair
 * </pre>
 *
 * @version $Id: KeyRecoveryDataBean.java,v 1.22 2005-12-29 13:51:29 anatom Exp $
 *
 * @ejb.bean
 *   description="Stores key recovery data"
 *   display-name="KeyRecoveryDataEB"
 *   name="KeyRecoveryData"
 *   local-jndi-name="KeyRecoveryData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="KeyRecoveryDataBean"
 *
 * @ejb.pk
 *   class="se.anatom.ejbca.keyrecovery.KeyRecoveryDataPK"
 *   extends="java.lang.Object"
 *   implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "KeyRecoveryData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.keyrecovery.KeyRecoveryDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.keyrecovery.KeyRecoveryDataLocal"
 *
 * @ejb.finder
 *   description="findByUsername"
 *   signature="Collection findByUsername(java.lang.String username)"
 *   query="SELECT DISTINCT OBJECT(a) from KeyRecoveryDataBean a WHERE a.username=?1"
 *
 * @ejb.finder
 *   description="findByUserMark"
 *   signature="Collection findByUserMark(java.lang.String usermark)"
 *   query="SELECT DISTINCT OBJECT(a) from KeyRecoveryDataBean a WHERE a.username=?1 AND a.markedAsRecoverable=TRUE"
 *
 * @ejb.transaction
 *   type="Supports"
 *
 * @jonas.bean
 *   ejb-name="KeyRecoveryData"
 *   jndi-name="KeyRecoveryData"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class KeyRecoveryDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(KeyRecoveryDataBean.class);

    /**
     * @ejb.persistence
     * @ejb.pk-field
     */
    public abstract String getCertSN();

    /**
     * @ejb.persistence
     */
    public abstract void setCertSN(String certificatesn);

    /**
     * @ejb.persistence
     * @ejb.pk-field
     * @ejb.interface-method view-type="local"
     */
    public abstract String getIssuerDN();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setIssuerDN(String issuerdn);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract boolean getMarkedAsRecoverable();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setMarkedAsRecoverable(boolean markedasrecoverable);

    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getKeyData();

    /**
     * @ejb.persistence
     */
    public abstract void setKeyData(String keydata);

    /**
     * @ejb.interface-method view-type="local"
     */
    public BigInteger getCertificateSN() {
        return new BigInteger(getCertSN(), 16);
    }

    /**
     * @ejb.interface-method view-type="local"
     */
    public void setCertificateSN(BigInteger certificatesn) {
        setCertSN(certificatesn.toString(16));
    }

    /**
     * @ejb.interface-method view-type="local"
     */
    public byte[] getKeyDataAsByteArray() {
        return Base64.decode(this.getKeyData().getBytes());
    }

    /**
     * @ejb.interface-method view-type="local"
     */
    public void setKeyDataFromByteArray(byte[] keydata) {
        setKeyData(new String(Base64.encode(keydata)));
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding keyrecovery data of users certificate.
     *
     * @param certificatesn of certificate the keys are belonging to.
     * @param issuerdn issuerdn of certificate the keys are belonging to.
     * @param username of the owner of the keys.
     * @param keydata the actual keydata.
     *
     * @return Primary Key
     *
     * @ejb.create-method
     */
    public KeyRecoveryDataPK ejbCreate(BigInteger certificatesn, String issuerdn, String username,
                                       byte[] keydata) throws CreateException {
        setCertificateSN(certificatesn);
        setIssuerDN(issuerdn);
        setUsername(StringTools.strip(username));
        setMarkedAsRecoverable(false);
        setKeyDataFromByteArray(keydata);
        KeyRecoveryDataPK pk = new KeyRecoveryDataPK(getCertSN(), issuerdn);
        log.debug("Created Key Recoverydata for user " + username);
        return pk;
    }

    public void ejbPostCreate(BigInteger certificatesn, String issuerdn, String username,
                              byte[] keydata) {
        // Do nothing. Required.
    }

}
