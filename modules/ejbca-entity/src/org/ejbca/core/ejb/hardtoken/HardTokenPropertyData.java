/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.hardtoken;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.NonUniqueResultException;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Complementary class used to assign extended properties like copyof to a hard
 * token.
 * 
 * Id is represented by primary key of hard token table.
 */
@Entity
@Table(name = "HardTokenPropertyData")
public class HardTokenPropertyData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;
    public static final String PROPERTY_COPYOF = "copyof=";

    private HardTokenPropertyDataPK hardTokenPropertyDataPK;
    
    private String value;
	private int rowVersion = 0;
	private String rowProtection;

    /**
     * Entity holding data of a hard token properties.
     */
    public HardTokenPropertyData(String id, String property, String value) {
    	setHardTokenPropertyDataPK(new HardTokenPropertyDataPK(id, property));
        setValue(value);
    }

    public HardTokenPropertyData() {
    }
    
    //@EmbeddedId
    public HardTokenPropertyDataPK getHardTokenPropertyDataPK() { return hardTokenPropertyDataPK; }
    public void setHardTokenPropertyDataPK(HardTokenPropertyDataPK hardTokenPropertyDataPK) { this.hardTokenPropertyDataPK = hardTokenPropertyDataPK; }

    @Transient
    public String getId() { return hardTokenPropertyDataPK.id; }

    //@Column
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }

    //@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getHardTokenPropertyDataPK().getId()).append(getHardTokenPropertyDataPK().getProperty()).append(getValue());
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
    	return new ProtectionStringBuilder().append(getHardTokenPropertyDataPK().getId()).append(getHardTokenPropertyDataPK()).toString();
    }

    //
    // End Database integrity protection methods
    //

    //
    // Search functions.
    //

    /** @return the found entity instance or null if the entity does not exist */
    public static HardTokenPropertyData findByPK(EntityManager entityManager, HardTokenPropertyDataPK pk) {
        return entityManager.find(HardTokenPropertyData.class, pk);
    }

    /**
     * @throws NonUniqueResultException
     *             if more than one entity with the name exists
     * @return the found entity instance or null if the entity does not exist
     */ 
    public static HardTokenPropertyData findByProperty(EntityManager entityManager, String id, String property) {
        HardTokenPropertyData ret = null;

        Query query = entityManager.createQuery("SELECT a FROM HardTokenPropertyData a WHERE a.hardTokenPropertyDataPK.id=:id AND a.hardTokenPropertyDataPK.property=:property");
        query.setParameter("id", id);
        query.setParameter("property", property);
        @SuppressWarnings("unchecked")
        List<HardTokenPropertyData> resultList = (List<HardTokenPropertyData>) query.getResultList();

        switch (resultList.size()) {
        case 0:
            ret = null;
            break;
        case 1:
            ret = resultList.get(0);
            break;
        default:
            throw new NonUniqueResultException("Several entries with the same primary key where found in the table HardTokenPropertyData.");
        }

        return ret;
    }

    /** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<HardTokenPropertyData> findIdsByPropertyAndValue(EntityManager entityManager, String property, String value) {
        Query query = entityManager.createQuery("SELECT a FROM HardTokenPropertyData a WHERE a.hardTokenPropertyDataPK.property=:property AND a.value=:value");
        query.setParameter("property", property);
        query.setParameter("value", value);
        return query.getResultList();
    }
}
