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

package org.ejbca.core.ejb.authorization;

import javax.ejb.CreateException;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.authorization.AdminEntity;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a admin entity in EJBCA authorization module
 * Information stored:
 * <pre>
 *   matchwith
 *   matchtype
 *   matchvalue
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a user entity"
 *   display-name="AdminEntityDataEB"
 *   name="AdminEntityData"
 *   jndi-name="AdminEntityData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="AdminEntityDataBean"
 *
 * @ejb.pk
 *   generate="false"
 *   class="org.ejbca.core.ejb.authorization.AdminEntityPK"
 *   extends="java.lang.Object"
 *   implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "AdminEntityData"
 * 
 * @ejb.transaction type="Required"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.authorization.AdminEntityDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.authorization.AdminEntityDataLocal"
 *
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *
 * @jboss.method-attributes
 *   pattern = "find*"
 *   read-only = "true"
 *
 */
public abstract class AdminEntityDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(AdminEntityDataBean.class);

    /**
     * @ejb.persistence column-name="pK"
     * @ejb.pk-field
     */
    public abstract int getPrimKey();

    /**
     */
    public abstract void setPrimKey(int primKey);

	/**
	 * @ejb.persistence column-name="matchWith"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getMatchWith();

    /**
	 * @ejb.persistence column-name="matchType"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getMatchType();

    /**
	 * @ejb.persistence column-name="matchValue"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getMatchValue();

    /**
     * @ejb.persistence column-name="cAId"
     * @ejb.interface-method view-type="local"
    */
    public abstract Integer getCaId();

    /**
	 */
    public abstract void setMatchWith(int matchwith);

    /**
	 */
    public abstract void setMatchType(int matchtype);

    /**
	 */
    public abstract void setMatchValue(String matchvalue);

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setCaId(Integer caid);

    /**
     * @ejb.interface-method view-type="local"
     */
    public AdminEntity getAdminEntity(){
      return new AdminEntity(getMatchWith(), getMatchType(), getMatchValue(), getCaId());
    }

	/**
	 *
     * @ejb.create-method
	 */
    public AdminEntityPK ejbCreate(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) throws CreateException {
        AdminEntityPK ret = new AdminEntityPK(admingroupname, caid, matchwith, matchtype, matchvalue);
        setPrimKey(ret.primKey);
        setMatchWith(matchwith);
        setMatchType(matchtype);
        setMatchValue(matchvalue);
        setCaId(caid);
        log.debug("Created admin entity "+ matchvalue);
        return ret;
    }

    public void ejbPostCreate(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) {
        // Do nothing. Required.
    }
}
