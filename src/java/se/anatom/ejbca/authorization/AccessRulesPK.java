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
 * @version $Id: AccessRulesPK.java,v 1.6 2005-03-10 13:36:06 anatom Exp $
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
