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

import java.io.Serializable;
import java.math.BigInteger;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.authorization.AccessRule;

/**
 * Representation of access rule in EJBCA authorization module.
 * 
 * @version $Id$
 */
@Entity
@Table(name = "AccessRulesData")
public class AccessRulesData implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AccessRulesData.class);

    private int pK;
    private String accessRule;
    private int rule;
    private Boolean isRecursiveBool;
    private Integer isRecursiveInt;
    private int rowVersion = 0;
    private String rowProtection;

    public AccessRulesData(final String admingroupname, final int caid, final String accessrule, final int rule, final boolean isrecursive) {
        setPrimKey(generatePrimaryKey(admingroupname, caid, new AccessRule(accessrule, rule, isrecursive)));
        setAccessRule(accessrule);
        setRule(rule);
        setIsRecursive(isrecursive);
        if (log.isDebugEnabled()) {
            log.debug("Created accessrule : " + accessrule);
        }
    }

    public AccessRulesData() {
    }

    // @Id @Column
    public int getPrimKey() {
        return pK;
    }

    public final void setPrimKey(final int primKey) {
        this.pK = primKey;
    }

    // @Column
    public String getAccessRule() {
        return accessRule;
    }

    public void setAccessRule(String accessRule) {
        this.accessRule = accessRule;
    }

    /** Return the status of the rule. One of AccessRule.RULE_... */
    // @Column "rule" is a reserved word on MS SQL Server and Sybase
    public int getRule() {
        return rule;
    }

    public void setRule(int rule) {
        this.rule = rule;
    }

    @Transient
    public boolean getIsRecursive() {
        final Boolean isRecB = getIsRecursiveBool();
        if (isRecB != null) {
            return isRecB.booleanValue();
        }
        final Integer isRecI = getIsRecursiveInt();
        if (isRecI != null) {
            return isRecI.intValue() == 1;
        }
        throw new RuntimeException("Could not retreive AccessRulesData.isRecursive from database.");
    }

    public final void setIsRecursive(final boolean isRecursive) {
        setIsRecursiveBool(Boolean.valueOf(isRecursive));
        setIsRecursiveInt(isRecursive ? 1 : 0);
    }

    /**
     * Use getIsRecursive() instead of this method! Ingres: Transient Non-ingres: Mapped to "isRecursive"
     */
    public Boolean getIsRecursiveBool() {
        return isRecursiveBool;
    }

    /** Use setIsRecursive(boolean) instead of this method! */
    public void setIsRecursiveBool(final Boolean isRecursiveBool) {
        this.isRecursiveBool = isRecursiveBool;
    }

    /**
     * Use getIsRecursive() instead of this method! Ingres: Mapped to "isRecursive" Non-ingres: Transient
     */
    public Integer getIsRecursiveInt() {
        return isRecursiveInt;
    }

    /** Use setIsRecursive(boolean) instead of this method! */
    public void setIsRecursiveInt(final Integer isRecursiveInt) {
        this.isRecursiveInt = isRecursiveInt;
    }

    // @Version @Column
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    // @Column @Lob
    public String getRowProtection() {
        return rowProtection;
    }

    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    /**
     * The current pk in AdminEntityData and AccessRulesData is a mix of integer pk and constraints and actually works fine. It's used like a
     * primitive int primary key in the db, but embeds logic for enforcing constraints, which would otherwise have to be programatically added to the
     * beans. If needed it can easily be replaced with an int pk and programatic logic to handle constraints. From the database view the pk is just an
     * int.
     */
    private static int generatePrimaryKey(final String admingroupname, final int caid, final AccessRule accessrule) {
        final int adminGroupNameHash = admingroupname == null ? 0 : admingroupname.hashCode();
        final int accessRuleHash = accessrule.getAccessRule() == null ? 0 : accessrule.getAccessRule().hashCode();
        return adminGroupNameHash ^ caid ^ accessRuleHash;
    }

    /**
     * Return the access rule transfer object
     * 
     * @return the access rule transfer object
     */
    @Transient
    public AccessRule getAccessRuleObject() {
        return new AccessRule(getAccessRule(), getRule(), getIsRecursive());
    }

    //
    // Search functions.
    //

    /** @return the found entity instance or null if the entity does not exist */
    public static AccessRulesData findByPrimeKey(final EntityManager entityManager, final String admingroupname, final int caid,
            final AccessRule accessrule) {
        return entityManager.find(AccessRulesData.class, generatePrimaryKey(admingroupname, caid, accessrule));
    }

    /** @return return the count. isRecursive should never be referenced in the WHERE clause. */
    public static long findCountByCustomQuery(final EntityManager entityManager, final String whereClause) {
        final Query query = entityManager.createNativeQuery("SELECT COUNT(*) FROM AccessRulesData a WHERE " + whereClause);
        final BigInteger v = (BigInteger) query.getSingleResult(); // Always returns a result
        return v.longValue();
    }

}
