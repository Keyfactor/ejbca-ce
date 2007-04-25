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

import java.util.Date;
import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.StringTools;


/**
 * Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a hard token in the ra.
 * Information stored:
 * <pre>
 *  tokenSN (Primary key)
 *  cTime (createtime)
 *  username (username)
 *  mTime (modifytime)
 *  tokenType  (tokentype)
 *  significantissuerdn (significantissuerdn), the CA the toke should belong to.
 *  data (Data saved concerning the hard token)
 * </pre>
 *
 *
 * @ejb.bean
 *	 xxxxgenerate="false"
 *   description="This enterprise bean entity represents a hard token with accompanying data"
 *   display-name="HardTokenDataEB"
 *   name="HardTokenData"
 *   jndi-name="HardTokenData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="HardTokenDataBean"
 *   primkey-field="tokenSN"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.String"
 *
 * @ejb.persistence table-name = "HardTokenData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenDataLocal"
 *
 * @ejb.finder
 *   description="findByUsername"
 *   signature="Collection findByUsername(java.lang.String username)"
 *   query="SELECT OBJECT(a) from HardTokenDataBean a WHERE a.username=?1"
 *
 * @ejb.transaction type="Required"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class HardTokenDataBean extends BaseEntityBean {


 
    private static final Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="tokenSN"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getTokenSN();

    /**
     */
    public abstract void setTokenSN(String tokensn);

    /**
     * @ejb.persistence column-name="username"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     * @see org.ejbca.util.StringTools
     * @ejb.interface-method view-type="local"
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence column-name="cTime"
     */
    public abstract long getCtime();

    /**
     */
    public abstract void setCtime(long createtime);

    /**
     * @ejb.persistence column-name="mTime"
     */
    public abstract long getMtime();

    /**
     */
    public abstract void setMtime(long modifytime);

    /**
     * @ejb.persistence column-name="tokenType"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getTokenType();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setTokenType(int tokentype);

    /**
     * @ejb.persistence column-name="significantIssuerDN"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getSignificantIssuerDN();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setSignificantIssuerDN(String significantissuerdn);

    /**
     * @ejb.persistence column-name="data"
     * @ejb.interface-method view-type="local"
     * @weblogic.ora.columntyp@
     */
    public abstract HashMap getData();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setData(HashMap data);

    /**
     * @ejb.interface-method view-type="local"
     */
    public Date getCreateTime(){ return new Date(getCtime()); }

    /**
     * @ejb.interface-method view-type="local"
     */
    public void setCreateTime(Date createtime){ setCtime(createtime.getTime()); }

    /**
     * @ejb.interface-method view-type="local"
     */
    public Date getModifyTime(){ return new Date(getCtime()); }

    /**
     * @ejb.interface-method view-type="local"
     */
    public void setModifyTime(Date modifytime){ setMtime(modifytime.getTime()); }

 


    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @return null
     * @ejb.create-method view-type="local"
	 */
    public String ejbCreate(Admin admin, String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, HashMap data) throws CreateException {
        setTokenSN(tokensn);
        setUsername(StringTools.strip(username));
        setCtime(createtime.getTime());
        setMtime(modifytime.getTime());
        setTokenType(tokentype);
        setSignificantIssuerDN(significantissuerdn);
        setData(data);

        log.debug("Created Hard Token "+ tokensn );
        return tokensn;
    }

    public void ejbPostCreate(Admin admin, String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, HashMap data) {
        // Do nothing. Required.
    }
}
