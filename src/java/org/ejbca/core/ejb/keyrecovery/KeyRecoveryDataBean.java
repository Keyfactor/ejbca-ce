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

package org.ejbca.core.ejb.keyrecovery;

import java.math.BigInteger;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.util.Base64;
import org.ejbca.util.StringTools;


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
 * @version $Id$
 *
 * @ejb.bean
 *   description="Stores key recovery data"
 *   display-name="KeyRecoveryDataEB"
 *   name="KeyRecoveryData"
 *   jndi-name="KeyRecoveryData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="KeyRecoveryDataBean"
 *
 * @ejb.pk
 *   class="org.ejbca.core.ejb.keyrecovery.KeyRecoveryDataPK"
 *   extends="java.lang.Object"
 *   implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "KeyRecoveryData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.keyrecovery.KeyRecoveryDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.keyrecovery.KeyRecoveryDataLocal"
 *
 * @ejb.finder
 *   description="findByUsername"
 *   signature="Collection findByUsername(java.lang.String username)"
 *   query="SELECT OBJECT(a) from KeyRecoveryDataBean a WHERE a.username=?1"
 *
 * @ejb.finder
 *   description="findByUserMark"
 *   signature="Collection findByUserMark(java.lang.String usermark)"
 *   query="SELECT OBJECT(a) from KeyRecoveryDataBean a WHERE a.username=?1 AND a.markedAsRecoverable=TRUE"
 *
 * @ejb.transaction type="Required"
 *
 * @jonas.bean
 *   ejb-name="KeyRecoveryData"
 *   jndi-name="KeyRecoveryData"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class KeyRecoveryDataBean extends BaseEntityBean {
    private static final Logger log = Logger.getLogger(KeyRecoveryDataBean.class);

    /**
     * @ejb.persistence column-name="certSN"
     * @ejb.pk-field
     */
    public abstract String getCertSN();

    /**
     */
    public abstract void setCertSN(String certificatesn);

    /**
     * @ejb.persistence column-name="issuerDN"
     * @ejb.pk-field
     * @ejb.interface-method view-type="local"
     */
    public abstract String getIssuerDN();

    /**
     */
    public abstract void setIssuerDN(String issuerdn);

    /**
     * @ejb.persistence column-name="username"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see org.ejbca.util.StringTools
     * @ejb.interface-method view-type="local"
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence column-name="markedAsRecoverable"
     * @ejb.interface-method view-type="local"
     */
    public abstract boolean getMarkedAsRecoverable();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setMarkedAsRecoverable(boolean markedasrecoverable);

    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="keyData"
     */
    public abstract String getKeyData();

    /**
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
