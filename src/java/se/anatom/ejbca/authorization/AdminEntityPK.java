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
 * @version $Id: AdminEntityPK.java,v 1.2 2004-04-16 07:38:57 anatom Exp $
 */

public final class AdminEntityPK implements java.io.Serializable {


    public int pK;


    public AdminEntityPK(java.lang.String admingroupname, int caid, int matchwith, int matchtype, java.lang.String matchvalue) {
        this.pK =
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
        return (this.pK == other.pK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {

        return this.pK;

    }

}
