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
 * The current pk in AdminEntityData and AccessRulesData is a mix of integer pk and 
 * constraints and actually works fine. 
 * It's used like a primitive int primary key in the db, but embeds logic for 
 * enforcing constraints, which would otherwise have to be programatically added to the beans.
 * If needed it can easily be replaced with an int pk and programatic logic to handle 
 * constraints. From the database view the pk is just an int.
 * 
 * @version $Id: AdminEntityPK.java,v 1.9 2005-04-29 08:16:11 anatom Exp $
 */
public final class AdminEntityPK implements java.io.Serializable {

    public int PK;

    public AdminEntityPK(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) {
        this.PK =
        ((admingroupname==null?0:admingroupname.hashCode())
        ^
        (caid)
        ^
        (matchwith)
        ^
        (matchvalue==null?0:matchvalue.hashCode())
        ^
        (matchtype));
    }

    public AdminEntityPK() {
    }

    public int getPK()
	{
    	return PK;
    }

    public void setPK(int PK)
	{
    	this.PK = PK;
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

    /** @return String representation of this pk in the form of [.field1.field2.field3]. */
    public String toString()
	{
    	StringBuffer toStringValue = new StringBuffer("[.");
    	toStringValue.append(this.PK).append('.');
    	toStringValue.append(']');
    	return toStringValue.toString();
    }
    
}
