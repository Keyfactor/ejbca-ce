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
 * Entity Bean representing  accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Access rule
 * rule (accept of decline)
 * isrecursive
 *
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents an access rule"
 *   display-name="AuthorizationTreeUpdateDataEB"
 *   name="AuthorizationTreeUpdateData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="false"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="AuthorizationTreeUpdateDataBean"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.pk
 *   generate="false"
 *   class="java.lang.Integer"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.authorization.AuthorizationTreeUpdateDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.authorization.AuthorizationTreeUpdateDataLocal"
 *
 */
public abstract class AuthorizationTreeUpdateDataBean extends BaseEntityBean
{

    private static Logger log = Logger.getLogger(AuthorizationTreeUpdateDataBean.class);

	/**
     * @ejb.pk-field
     */
    public abstract Integer getPK();

    public abstract void setPK(Integer pK);

	/**
     * @ejb.interface-method view-type="local"
     */
    public abstract int getAuthorizationTreeUpdateNumber();

    public abstract void setAuthorizationTreeUpdateNumber(int authorizationtreeupdatenumber);



	/**
	 *
     * @ejb.create-method
	 */
    public Integer ejbCreate() throws CreateException {
      setPK(new Integer(AuthorizationTreeUpdateDataLocalHome.AUTHORIZATIONTREEUPDATEDATA));
      setAuthorizationTreeUpdateNumber(0);
      return new Integer(AuthorizationTreeUpdateDataLocalHome.AUTHORIZATIONTREEUPDATEDATA);
    }

    public void ejbPostCreate() {
        // Do nothing. Required method.
    }

     /**
     * @see se.anatom.ejbca.authorization.AuthorizationTreeUpdateDataLocal
     * @ejb.interface-method view-type="local"
     */
    public boolean updateNeccessary(int currentauthorizationtreeupdatenumber){
      return getAuthorizationTreeUpdateNumber() != currentauthorizationtreeupdatenumber;
    } // updateNeccessary


     /**
     * @see se.anatom.ejbca.authorization.AuthorizationTreeUpdateDataLocal
     * @ejb.interface-method view-type="local"
     */
    public void incrementAuthorizationTreeUpdateNumber(){
      setAuthorizationTreeUpdateNumber(getAuthorizationTreeUpdateNumber() +1);
    }  // incrementAuthorizationTreeUpdateNumber

}
