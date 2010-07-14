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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.IdClass;
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
@Table(name="AccessRulesData")
@IdClass(AccessRulesDataPK.class)
public class AccessRulesData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(AccessRulesData.class);

	private int pK;
	private String accessRule;
	private int rule;
	private boolean isRecursive;
	
	public AccessRulesData(String admingroupname, int caid, String accessrule, int rule, boolean isrecursive) {
		AccessRulesDataPK accessRulesDataPK = new AccessRulesDataPK(admingroupname, caid, new AccessRule(accessrule, rule, isrecursive));
		setPrimKey(accessRulesDataPK.primKey);
		setAccessRule(accessrule);
		setRule(rule);
		setIsRecursive(isrecursive);
		log.debug("Created accessrule : "+ accessrule);
	}
	
	public AccessRulesData() { }
	
	@Id
	@Column(name="pK")
	public int getPrimKey() { return pK; }
	public void setPrimKey(int primKey) { this.pK = primKey; }

	@Column(name="accessRule")
	public String getAccessRule() { return accessRule; }
	public void setAccessRule(String accessRule) { this.accessRule = accessRule; }

	/** Return the status of the rule. One of AccessRule.RULE_... */
	// TODO: "rule" is a reserved word on MS SQL Server and Sybase. Perhaps we should rename this to "ruleStatus".
	@Column(name="rule", nullable=false)
	public int getRule() { return rule; }
	public void setRule(int rule) { this.rule = rule; }

	@Column(name="isRecursive", nullable=false)
	public boolean getIsRecursive() { return isRecursive; }
	public void setIsRecursive(boolean isRecursive) { this.isRecursive = isRecursive; }

	/**
	 * Return the access rule transfer object
	 * @return the access rule transfer object
	 */
	@Transient
	public AccessRule getAccessRuleObject() {
		return new AccessRule(getAccessRule(), getRule(), getIsRecursive());
	}

	//
	// Search functions. 
	//

	public static AccessRulesData findByPrimeKey(EntityManager entityManager, AccessRulesDataPK accessRulesDataPK) {
		return entityManager.find(AccessRulesData.class, accessRulesDataPK);
	}

	public static AccessRulesData findByPrimeKey(EntityManager entityManager, String admingroupname, int caid, AccessRule accessrule) {
		AccessRulesDataPK accessRulesDataPK = new AccessRulesDataPK(admingroupname, caid, accessrule); 
		return findByPrimeKey(entityManager, accessRulesDataPK);
	}

	
}
