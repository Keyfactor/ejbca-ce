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

/**
 * @version $Id: AdminEntityPK.java,v 1.6 2005-03-10 13:36:06 anatom Exp $
 */
public final class AdminEntityPK implements java.io.Serializable {

    public int PK;

    public AdminEntityPK(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) {
        this.PK =
        ((admingroupname==null?0:admingroupname.hashCode())
        ^
        ((int) caid)
        ^
        ((int) matchwith)
        ^
        (matchvalue==null?0:matchvalue.hashCode())
        ^
        ((int) matchtype));
    }

    public AdminEntityPK() {
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.authorization.AdminEntityPK)) {
            return false;
        }
        se.anatom.ejbca.authorization.AdminEntityPK other = (se.anatom.ejbca.authorization.AdminEntityPK) otherOb;
        return (this.PK == other.PK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.PK;
    }

}
