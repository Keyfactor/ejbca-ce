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

package se.anatom.ejbca.authorization;

import javax.ejb.CreateException;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

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
 *   view-type="local"
 *   type="CMP"
 *   reentrant="false"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="AdminEntityDataBean"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.pk
 *   class="se.anatom.ejbca.authorization.AdminEntityPK"
 *   extends="java.lang.Object"
 *   implements="java.io.Serializable"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.authorization.AdminEntityDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.authorization.AdminEntityDataLocal"
 *
 */
public abstract class AdminEntityDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(AdminEntityDataBean.class);

    public abstract int          getPK();

	/**
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
     * @ejb.pk-field
     */
    public abstract int          getMatchWith();

    /**
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
     * @ejb.pk-field
     */
    public abstract int          getMatchType();

    /**
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
     * @ejb.pk-field
     */
    public abstract String       getMatchValue();

    /**
	 * @ejb.persistence
	 */
    public abstract void setPK(int pK);

    /**
	 * @ejb.persistence
	 */
    public abstract void setMatchWith(int matchwith);

    /**
	 * @ejb.persistence
	 */
    public abstract void setMatchType(int matchtype);

    /**
	 * @ejb.persistence
	 */
    public abstract void setMatchValue(String matchvalue);


    /**
     * @ejb.interface-method view-type="local"
     */
    public AdminEntity getAdminEntity(int caid){
      return new AdminEntity(getMatchWith(), getMatchType(), getMatchValue(), caid);
    }


	/**
	 *
     * @ejb.create-method
	 */
    public AdminEntityPK ejbCreate(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) throws CreateException {

        AdminEntityPK pk = new AdminEntityPK(admingroupname, caid, matchwith,matchtype,matchvalue);
        setPK(pk.hashCode());
        setMatchWith(matchwith);
        setMatchType(matchtype);
        setMatchValue(matchvalue);

        log.debug("Created admin entity "+ matchvalue);
        return pk;
    }

    public void ejbPostCreate(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) {
        // Do nothing. Required.
    }
}
