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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.QueryResultWrapper;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;

/**
 * Representation of authorization admin group.
 * 
 * @version $Id$
 */
@Entity
@Table(name="AdminGroupData")
public class AdminGroupData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(AdminGroupData.class);
	
	private Integer pK;
	private String adminGroupName;
	private int cAId;
	private Set<AdminEntityData> adminEntityDatas;
	private Set<AccessRulesData> accessRulesDatas;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of admin profile groups.
	 * @param admingroupname
	 */
	public AdminGroupData(final Integer pk, final String admingroupname) {
		setPrimeKey(pk);
		setAdminGroupName(admingroupname);
		setCaId(0);
		setAdminEntities(new HashSet<AdminEntityData>());
		setAccessRules(new HashSet<AccessRulesData>());
		log.debug("Created admingroup : " + admingroupname);
	}

	public AdminGroupData() { }

	//@Id @Column
	public Integer getPrimeKey() { return pK; }
	public final void setPrimeKey(final Integer primeKey) { this.pK = primeKey; }

	//@Column
	public String getAdminGroupName() { return adminGroupName; }
	public void setAdminGroupName(String adminGroupName) { this.adminGroupName = adminGroupName; }

	@Deprecated
	//@Column
	public int getCaId() { return cAId; }
	@Deprecated
	public void setCaId(int cAId) { this.cAId = cAId; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(final int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(final String rowProtection) { this.rowProtection = rowProtection; }

	/*
	 * TODO: Mapping between admins and group ok?
	 * 
	 * 
	 * @ejb.relation name="AdminGroupDataToAdminEntities" role-name="AdminGroupData"
	 * target-role-name="AdminEntityData" target-ejb="AdminEntityData"
	 * 
	 * @jboss.target-relation
	 * related-pk-field="primKey"
	 * fk-column="AdminGroupData_adminEntities"  
	 * 
	 * @weblogic.target-column-map
	 * key-column="pK"
	 * foreign-key-column="AdminGroupData_adminEntities"
	 * 
	 * @sunone.relation
	 * column="AdminGroupData.pK"
	 * target="AdminEntityData.AdminGroupData_adminEntities"
	 */
	// If we use lazy fetching we have to take care so that the Entity is managed until we fetch the values. Set works better with eager fetching for Hibernate.
	//@OneToMany(cascade={CascadeType.ALL}, fetch=FetchType.EAGER) @JoinColumn(name="AdminGroupData_adminEntities")
	public Set<AdminEntityData> getAdminEntities() { return adminEntityDatas; }
	public void setAdminEntities(Set<AdminEntityData> adminEntityDatas) { this.adminEntityDatas = adminEntityDatas; }

	/*
	 * @ejb.relation
	 * name="AdminGroupDataToAccessRules" role-name="AdminGroupData"
	 * target-role-name="AccessRulesData" target-ejb="AccessRulesData"
	 * 
	 * @jboss.target-relation
	 * related-pk-field="primKey"
	 * fk-column="AdminGroupData_accessRules"
	 *      
	 * @weblogic.target-column-map
	 * key-column="pK"
	 * foreign-key-column="AdminGroupData_accessRules"
	 * 
	 * @sunone.relation
	 * column="AdminGroupData.pK"
	 * target="AccessRulesData.AdminGroupData_accessRules"
	 */
	// If we use lazy fetching we have to take care so that the Entity is managed until we fetch the values. Set works better with eager fetching for Hibernate.
	//@OneToMany(cascade={CascadeType.ALL}, fetch=FetchType.EAGER) @JoinColumn(name="AdminGroupData_accessRules")
	public Set<AccessRulesData> getAccessRules() { return accessRulesDatas; }
	public void setAccessRules(Set<AccessRulesData> accessRulesDatas) { this.accessRulesDatas = accessRulesDatas; }

	/**
	 * Adds a Collection of AccessRule to the database. Changing their values if they already exists
	 */
	public void addAccessRules(final EntityManager entityManager, final Collection<AccessRule> accessrules) {
		final Iterator<AccessRule> iter = accessrules.iterator();
		while (iter.hasNext()) {
			final AccessRule accessrule = iter.next();
			try {
				final AccessRulesData data = new AccessRulesData(getAdminGroupName(), 0, accessrule.getAccessRule(), accessrule.getRule(), accessrule.isRecursive());
				entityManager.persist(data);
				final Iterator<AccessRulesData> i = getAccessRules().iterator();
				while (i.hasNext()) {
					final AccessRulesData ar = i.next();
					if (ar.getAccessRuleObject().getAccessRule().equals(accessrule.getAccessRule())) {
						getAccessRules().remove(ar);
						entityManager.remove(ar);
						break;
					}
				}
				getAccessRules().add(data);
			} catch (Exception e) {
				log.error("Error adding AccessRules: ", e);
			}
		}
	}

	/**
	 * Removes a Collection of (String) accessrules from the database.
	 */
	public void removeAccessRules(final EntityManager entityManager, final Collection<String> accessrules) {
		final Iterator<String> iter = accessrules.iterator();
		while (iter.hasNext()) {
			final String accessrule = iter.next();
			final Iterator<AccessRulesData> i = getAccessRules().iterator();
			while (i.hasNext()) {
				final AccessRulesData ar = i.next();
				if (ar.getAccessRuleObject().getAccessRule().equals(accessrule)) {
					getAccessRules().remove(ar);
					entityManager.remove(ar);
					break;
				}
			}
		}
	}

	/**
     * Removes a Collection of (AccessRules) accessrules from the database.
     * Only used during upgrade.
     */
    public void removeAccessRulesObjects(final EntityManager entityManager, final Collection<AccessRule> accessrules) {
    	final Iterator<AccessRule> iter = accessrules.iterator();
		while (iter.hasNext()) {
			final AccessRule accessrule = iter.next();
			final Iterator<AccessRulesData> i = getAccessRules().iterator();
            while (i.hasNext()) {
            	final AccessRulesData ar = i.next();
                if (accessrule.getAccessRule().equals(ar.getAccessRule()) && accessrule.getRule() == ar.getRule() && accessrule.isRecursive() == ar.getIsRecursive()) {
                    getAccessRules().remove(ar);
					entityManager.remove(ar);
					break;
                }
            }
        }
    }

	/**
	 * Returns the number of access rules in admingroup
	 */
	@Transient
	public int getNumberOfAccessRules() {
		return getAccessRules().size();
	}

	/**
	 * Returns all the accessrules
	 */
	@Transient
	public Collection<AccessRule> getAccessRuleObjects() {
		final Collection<AccessRulesData> rules = getAccessRules();
		final ArrayList<AccessRule> objects = new ArrayList<AccessRule>(rules.size());
		final Iterator<AccessRulesData> i = rules.iterator();
		while (i.hasNext()) {
			final AccessRulesData ar = i.next();
			objects.add(ar.getAccessRuleObject());
		}
		return objects;
	}

	/**
	 * Adds a Collection of AdminEntity to the database. Changing their values if they already exists. 
	 * 
	 * FIXME: Move this method to AdminEntitySessionBean perhaps?
	 */
	public void addAdminEntities(final EntityManager entityManager, final Collection<AdminEntity> adminentities) {
		for(AdminEntity adminentity : adminentities) {	
			final AdminEntityData data = new AdminEntityData(getAdminGroupName(), adminentity.getCaId(), adminentity.getMatchWith(),adminentity.getMatchType(), adminentity.getMatchValue());
				entityManager.persist(data);
				final AdminEntityDataPK datapk = new AdminEntityDataPK(getAdminGroupName(), adminentity.getCaId(), adminentity.getMatchWith(), adminentity.getMatchType(), adminentity.getMatchValue());
				for(AdminEntityData aed : getAdminEntities()) {
					final AdminEntityDataPK uepk = new AdminEntityDataPK(getAdminGroupName(), aed.getCaId(), aed.getMatchWith(), aed.getMatchType(), aed.getMatchValue());
					if (uepk.equals(datapk)) {
						getAdminEntities().remove(aed);
						entityManager.remove(aed);
						break;
					}
				}
				getAdminEntities().add(data);
		}
	}

	/**
	 * Removes a Collection if AdminEntity from the database.
	 */
	public void removeAdminEntities(final EntityManager entityManager, final Collection<AdminEntity> adminentities) {
		final Iterator<AdminEntity> iter = adminentities.iterator();
		while (iter.hasNext()) {
			final AdminEntity adminentity = iter.next();
			final AdminEntityDataPK dataAdminEntityDataPK = new AdminEntityDataPK(getAdminGroupName(), adminentity.getCaId(), adminentity.getMatchWith(), adminentity.getMatchType(), adminentity.getMatchValue());
			final Iterator<AdminEntityData> i = getAdminEntities().iterator();
			while (i.hasNext()) {
				final AdminEntityData ue = i.next();
				final AdminEntityDataPK uepk = new AdminEntityDataPK(getAdminGroupName(), ue.getCaId(), ue.getMatchWith(), ue.getMatchType(), ue.getMatchValue());
				if (uepk.equals(dataAdminEntityDataPK)) {
					getAdminEntities().remove(ue);
					entityManager.remove(ue);
					break;
				}
			}
		}
	}

	/**
	 * Returns the number of user entities in admingroup
	 *
	 * @return the number of user entities in the database
	 */
	@Transient
	public int getNumberOfAdminEntities() {
		return getAdminEntities().size();
	}

	/**
	 * Returns all the adminentities as Collection of AdminEntity.
	 */
	@Transient
	public Collection<AdminEntity> getAdminEntityObjects() {
		final ArrayList<AdminEntity> returnval = new ArrayList<AdminEntity>();
		final Iterator<AdminEntityData> i = getAdminEntities().iterator();
		while (i.hasNext()) {
			returnval.add(i.next().getAdminEntity());
		}
		return returnval;
	}

	/**
	 * Returns the data in admingroup representation.
	 */
	@Transient
	public AdminGroup getAdminGroup() {
		final ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
		final ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
		final Iterator<AdminEntityData> i = getAdminEntities().iterator();
		while (i.hasNext()) {
			adminentities.add(i.next().getAdminEntity());
		}
		final Iterator<AccessRulesData> i2 = getAccessRules().iterator();
		while (i2.hasNext()) {
			accessrules.add(i2.next().getAccessRuleObject());
		}
		return new AdminGroup(getPrimeKey().intValue(), getAdminGroupName(), accessrules, adminentities);
	}

	/**
	 * Returns an AdminGroup object only containing name and caid and no access data.
	 */
	@Transient
	public AdminGroup getAdminGroupNames() {
		return new AdminGroup(getPrimeKey().intValue(), getAdminGroupName(), null, null);
	}
	
	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static AdminGroupData findByPrimeKey(final EntityManager entityManager, final Integer primeKey) {
		return entityManager.find(AdminGroupData.class, primeKey);
	}
	
	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static AdminGroupData findByGroupName(final EntityManager entityManager, final String adminGroupName) {
		final Query query = entityManager.createQuery("SELECT a FROM AdminGroupData a WHERE adminGroupName=:adminGroupName");
		query.setParameter("adminGroupName", adminGroupName);
		return (AdminGroupData) QueryResultWrapper.getSingleResult(query);
	}

	/** @return return the query results as a List. */
	public static List<AdminGroupData> findAll(final EntityManager entityManager) {
		final Query query = entityManager.createQuery("SELECT a FROM AdminGroupData a");
		return query.getResultList();
	}
}
