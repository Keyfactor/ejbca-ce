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
import java.util.Iterator;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.persistence.OneToMany;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
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
/*@SecondaryTables({
	@SecondaryTable(name="AdminEntityData", pkJoinColumns={@PrimaryKeyJoinColumn(name="AdminGroupData_adminEntities")}),
	@SecondaryTable(name="AccessRulesData", pkJoinColumns={@PrimaryKeyJoinColumn(name="AdminGroupData_accessRules")})
})*/
public class AdminGroupData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(AdminGroupData.class);
	
	private Integer pK;
	private String adminGroupName;
	private int cAId;
	private Collection<AdminEntityData> adminEntityDatas = new ArrayList<AdminEntityData>();
	private Collection<AccessRulesData> accessRulesDatas = new ArrayList<AccessRulesData>();
	
	/**
	 * Entity holding data of admin profile groups.
	 * @param admingroupname
	 */
	public AdminGroupData(Integer pk, String admingroupname) {
		setPrimeKey(pk);
		setAdminGroupName(admingroupname);
		setCaId(0);
		log.debug("Created admingroup : " + admingroupname);
	}

	public AdminGroupData() { }

	@Id
	@Column(name="pK")
	public Integer getPrimeKey() { return pK; }
	public void setPrimeKey(Integer primeKey) { this.pK = primeKey; }

	@Column(name="adminGroupName")
	public String getAdminGroupName() { return adminGroupName; }
	public void setAdminGroupName(String adminGroupName) { this.adminGroupName = adminGroupName; }

	@Deprecated
	@Column(name="cAId", nullable=false)
	public int getCaId() { return cAId; }
	@Deprecated
	public void setCaId(int cAId) { this.cAId = cAId; }

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
	@OneToMany(cascade={CascadeType.ALL})
	@JoinColumn(name="AdminGroupData_adminEntities")
	public Collection<AdminEntityData> getAdminEntities() { return adminEntityDatas; }
	public void setAdminEntities(Collection<AdminEntityData> adminEntityDatas) { this.adminEntityDatas = adminEntityDatas; }

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
	@OneToMany(cascade={CascadeType.ALL})
	@JoinColumn(name="AdminGroupData_accessRules")
	public Collection<AccessRulesData> getAccessRules() { return accessRulesDatas; }
	public void setAccessRules(Collection<AccessRulesData> accessRulesDatas) { this.accessRulesDatas = accessRulesDatas; }

	/**
	 * Adds a Collection of AccessRule to the database. Changing their values if they already exists
	 */
	public void addAccessRules(EntityManager entityManager, Collection<AccessRule> accessrules) {
		Iterator<AccessRule> iter = accessrules.iterator();
		while (iter.hasNext()) {
			AccessRule accessrule = iter.next();
			try {
				AccessRulesData data = new AccessRulesData(getAdminGroupName(), 0, accessrule.getAccessRule(), accessrule.getRule(), accessrule.isRecursive());
				entityManager.persist(data);
				Iterator<AccessRulesData> i = getAccessRules().iterator();
				while (i.hasNext()) {
					AccessRulesData ar = i.next();
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
	public void removeAccessRules(EntityManager entityManager, Collection<String> accessrules) {
		Iterator<String> iter = accessrules.iterator();
		while (iter.hasNext()) {
			String accessrule = iter.next();
			Iterator<AccessRulesData> i = getAccessRules().iterator();
			while (i.hasNext()) {
				AccessRulesData ar = i.next();
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
    public void removeAccessRulesObjects(EntityManager entityManager, Collection<AccessRule> accessrules) {
		Iterator<AccessRule> iter = accessrules.iterator();
		while (iter.hasNext()) {
			AccessRule accessrule = iter.next();
			Iterator<AccessRulesData> i = getAccessRules().iterator();
            while (i.hasNext()) {
				AccessRulesData ar = i.next();
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
		ArrayList<AccessRule> objects = new ArrayList<AccessRule>(rules.size());
		Iterator<AccessRulesData> i = rules.iterator();
		while (i.hasNext()) {
			AccessRulesData ar = i.next();
			objects.add(ar.getAccessRuleObject());
		}
		return objects;
	}

	/**
	 * Adds a Collection of AdminEntity to the database. Changing their values if they already exists
	 */
	public void addAdminEntities(EntityManager entityManager, Collection<AdminEntity> adminentities) {
		Iterator<AdminEntity> iter = adminentities.iterator();
		while (iter.hasNext()) {
			AdminEntity adminentity = iter.next();
			try {
				AdminEntityData data = new AdminEntityData(getAdminGroupName(), adminentity.getCaId(), adminentity.getMatchWith(),adminentity.getMatchType(), adminentity.getMatchValue());
				entityManager.persist(data);
				AdminEntityDataPK datapk = new AdminEntityDataPK(getAdminGroupName(), adminentity.getCaId(), adminentity.getMatchWith(), adminentity.getMatchType(), adminentity.getMatchValue());
				Iterator<AdminEntityData> i = getAdminEntities().iterator();
				while (i.hasNext()) {
					AdminEntityData aed = i.next();
					AdminEntityDataPK uepk = new AdminEntityDataPK(getAdminGroupName(), aed.getCaId(), aed.getMatchWith(), aed.getMatchType(), aed.getMatchValue());
					if (uepk.equals(datapk)) {
						getAdminEntities().remove(aed);
						entityManager.remove(aed);
						break;
					}
				}
				getAdminEntities().add(data);
			} catch (Exception e) {
				log.error("Error adding AdminEntities: ", e);
			}
		}
	}

	/**
	 * Removes a Collection if AdminEntity from the database.
	 */
	public void removeAdminEntities(EntityManager entityManager, Collection<AdminEntity> adminentities) {
		Iterator<AdminEntity> iter = adminentities.iterator();
		while (iter.hasNext()) {
			AdminEntity adminentity = iter.next();
			AdminEntityDataPK dataAdminEntityDataPK = new AdminEntityDataPK(getAdminGroupName(), adminentity.getCaId(), adminentity.getMatchWith(), adminentity.getMatchType(), adminentity.getMatchValue());
			Iterator<AdminEntityData> i = getAdminEntities().iterator();
			while (i.hasNext()) {
				AdminEntityData ue = i.next();
				AdminEntityDataPK uepk = new AdminEntityDataPK(getAdminGroupName(), ue.getCaId(), ue.getMatchWith(), ue.getMatchType(), ue.getMatchValue());
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
		ArrayList<AdminEntity> returnval = new ArrayList<AdminEntity>();
		Iterator<AdminEntityData> i = getAdminEntities().iterator();
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
		ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
		ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
		Iterator<AdminEntityData> i = getAdminEntities().iterator();
		while (i.hasNext()) {
			adminentities.add(i.next().getAdminEntity());
		}
		Iterator<AccessRulesData> i2 = getAccessRules().iterator();
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
	public static AdminGroupData findByPrimeKey(EntityManager entityManager, Integer primeKey) {
		return entityManager.find(AdminGroupData.class,  primeKey);
	}
	
	/**
	 * @throws NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static AdminGroupData findByGroupName(EntityManager entityManager, String adminGroupName) {
		AdminGroupData ret = null;
		try {
			Query query = entityManager.createQuery("from AdminGroupData a WHERE adminGroupName=:adminGroupName");
			query.setParameter("adminGroupName", adminGroupName);
			ret = (AdminGroupData) query.getSingleResult();
		} catch (NoResultException e) {
		}
		return ret;
	}

	/** @return return the query results as a List. */
	public static List<AdminGroupData> findAll(EntityManager entityManager) {
		Query query = entityManager.createQuery("from AdminGroupData a");
		return query.getResultList();
	}
}
