/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.validation;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.validation.BlacklistEntry;

/**
 * Representation of a public key blacklist entry.
 * 
 * @version $Id$
 */
@Entity
@Table(name = "BlacklistData")
public class BlacklistData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(BlacklistData.class);

    // data fields.
    private int id;
    private String type;
    private String value;
    private String data;
    private int updateCounter;
    private int rowVersion = 0;
    private String rowProtection;

    /**
     * Creates a new instance.
     */
    public BlacklistData() {
    }

    /**
     * Creates a new instance.
     * @param id the id.
     * @param fingerprint the unique fingerprint.
     * @param entry the public key blacklist domain object.
     */
    public BlacklistData(BlacklistEntry entry) {
        setBlacklistEntry(entry);
        setUpdateCounter(0);
    }

    /**
     * Creates a new instance.
     * @param id the id.
     * @param fingerprint the unique fingerprint.
     * @param entry the public key blacklist domain object.
     */
    @Transient
    public void setBlacklistEntry(BlacklistEntry entry) {
        if (log.isDebugEnabled()) {
            log.debug("Setting BlacklistData '" + entry.getValue() + "' (" + entry.getID() + ")");
        }
        setId(entry.getID());
        setType(entry.getType());
        setValue(entry.getValue());
        setData(entry.getData());
        setUpdateCounter(getUpdateCounter()+1);
    }

    /**
     * Gets a balacklist domain object.
     * @param id the id.
     * @param fingerprint the unique fingerprint.
     * @param entry the public key blacklist domain object.
     */
    @Transient
    public BlacklistEntry getBlacklistEntry() {
        final BlacklistEntry ret = new BlacklistEntry(getId(), getType(), getValue(), getData());
        return ret;
    }

    //@Id @Column
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    //@Column
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    //@Column
    /** See for instance {@link AlgorithmConstants#KEYALGORITHM_RSA} + length 'RSA2048' and others. */
    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    //@Column
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    //@Column
    public int getUpdateCounter() {
        return updateCounter;
    }

    public void setUpdateCounter(int updateCounter) {
        this.updateCounter = updateCounter;
    }

    //@Version @Column
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(int rowVersion) {
        this.rowVersion = rowVersion;
    }

    //@Column @Lob
    @Override
    public String getRowProtection() {
        return rowProtection;
    }

    @Override
    public void setRowProtection(String rowProtection) {
        this.rowProtection = rowProtection;
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    public String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getType()).append(getValue()).append(getData()).append(getUpdateCounter());
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
        return String.valueOf(getId());
    }

    //
    // End Database integrity protection methods
    //

    //
    // Search functions. 
    // 

    /** @return the found entity instance or null if the entity does not exist */
    public static BlacklistData findById(EntityManager entityManager, int id) {
        return entityManager.find(BlacklistData.class, id);
    }

    /**
     * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
     * @return the found entity instance or null if the entity does not exist
     */
    public static BlacklistData findByTypeAndValue(EntityManager entityManager, final String type, final String value) {
        final Query query = entityManager.createQuery("SELECT a FROM BlacklistData a WHERE a.type=:type and a.value=:value");
        query.setParameter("type", type);
        query.setParameter("value", value);
        return (BlacklistData) QueryResultWrapper.getSingleResult(query);
    }

    /** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<BlacklistData> findAll(EntityManager entityManager) {
        final Query query = entityManager.createQuery("SELECT a FROM BlacklistData a");
        return query.getResultList();
    }

    /** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<BlacklistData> findAllById(EntityManager entityManager, Collection<Integer> ids) {
        final Query query = entityManager.createQuery("SELECT a FROM BlacklistData a WHERE a.id IN (:ids)");
        query.setParameter("ids", ids);
        return query.getResultList();
    }
}
