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
 * @version $Id: AdminEntityDataBean.java,v 1.2 2004-04-16 07:38:57 anatom Exp $
 */
public abstract class AdminEntityDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(AdminEntityDataBean.class);

    public abstract int          getPK();
    public abstract int          getMatchWith();
    public abstract int          getMatchType();
    public abstract String       getMatchValue();

    public abstract void setPK(int pK);
    public abstract void setMatchWith(int matchwith);
    public abstract void setMatchType(int matchtype);
    public abstract void setMatchValue(String matchvalue);


    public AdminEntity getAdminEntity(int caid){
      return new AdminEntity(getMatchWith(), getMatchType(), getMatchValue(), caid);
    }


    //
    // Fields required by Container
    //


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
