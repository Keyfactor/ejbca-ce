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

package org.ejbca.core.ejb.hardtoken;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing certificates placed on a token.
 * Information stored:
 * <pre>
 *  certificatefingerprint
 *  tokensn
 * </pre>
 *
 *
 * @ejb.bean
 *	 xxxgenerate="false"
 *   description="This enterprise bean entity represents a hard token to certificate mappings"
 *   display-name="HardTokenCertificateMapEB"
 *   name="HardTokenCertificateMap"
 *   jndi-name="HardTokenCertificateMap"
 *   local-jndi-name="HardTokenCertificateMapLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="HardTokenCertificateMapBean"
 *   primkey-field="certificateFingerprint"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.String"
 *
 * @ejb.persistence table-name = "HardTokenCertificateMap"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenCertificateMapLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenCertificateMapLocal"
 *
 * @ejb.finder
 *   description="findByTokenSN"
 *   signature="Collection findByTokenSN(java.lang.String sn)"
 *   query="SELECT OBJECT(a) from HardTokenCertificateMapBean a WHERE a.tokenSN=?1"
 *
 * @ejb.transaction
 *   type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *
 */
public abstract class HardTokenCertificateMapBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(HardTokenCertificateMapBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getCertificateFingerprint();

    /**
     * @ejb.persistence
     */
    public abstract void setCertificateFingerprint(String certificateFingerprint);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getTokenSN();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setTokenSN(String tokenSN);


    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of a certificate to hard token relation.
     *
     * @return null
     *
     * @ejb.create-method view-type="local"
	 */
    public String ejbCreate(String certificateFingerprint, String tokenSN) throws CreateException {
        setCertificateFingerprint(certificateFingerprint);
        setTokenSN(tokenSN);
        log.debug("Created HardTokenCertificateMap for token SN: "+ tokenSN );
        return certificateFingerprint;
    }

    public void ejbPostCreate(String certificateFingerprint, String tokenSN) {
        // Do nothing. Required.
    }
}
