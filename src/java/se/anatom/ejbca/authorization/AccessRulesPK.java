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
 * @version $Id: AccessRulesPK.java,v 1.7 2005-03-11 11:25:00 anatom Exp $
 */

public final class AccessRulesPK implements java.io.Serializable {

    public int PK;


    public AccessRulesPK(java.lang.String admingroupname, int caid, AccessRule accessrule) {
        this.PK =
        ((admingroupname==null?0:admingroupname.hashCode())
        ^
        ((int) caid)
        ^ 
        (accessrule.getAccessRule()==null?0:accessrule.getAccessRule().hashCode()));
    }

    public AccessRulesPK() {
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.authorization.AccessRulesPK)) {
            return false;
        }
        se.anatom.ejbca.authorization.AccessRulesPK other = (se.anatom.ejbca.authorization.AccessRulesPK) otherOb;
        return (this.PK==other.PK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.PK;
    }

}
