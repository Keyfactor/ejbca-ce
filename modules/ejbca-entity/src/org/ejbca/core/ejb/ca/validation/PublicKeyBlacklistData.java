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
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashMap;
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
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.ca.validation.PublicKeyBlacklistEntry;

/**
 * Representation of a public key blacklist entry.
 * 
 * @version $Id: PublicKeyBlacklistData.java 25263 2017-04-01 12:12:00Z anjakobs $
 */
@Entity
@Table(name = "PublicKeyBlacklistData")
public class PublicKeyBlacklistData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(PublicKeyBlacklistData.class);

    /** Domain object reference. */
    private PublicKeyBlacklistEntry publicKeyBlacklist = null;

    // data fields.
    private int id;
    private int source;
    private String keyspec;
    private String fingerprint;
    private int updateCounter;
    private String data;
    private int rowVersion = 0;
    private String rowProtection;

    /**
     * Creates a new instance.
     */
    public PublicKeyBlacklistData() {
    }

    /**
     * Creates a new instance.
     * @param id the id.
     * @param fingerprint the unique fingerprint.
     * @param entry the public key blacklist domain object.
     */
    public PublicKeyBlacklistData(PublicKeyBlacklistEntry entry) {
        if (log.isDebugEnabled()) {
            log.debug("Creating PublicKeyBlacklistData '" + fingerprint + "' (" + id + ")");
        }
        setId(entry.getID());
        setSource(entry.getSource());
        setKeyspec(entry.getKeyspec());
        setFingerprint(entry.getFingerprint());
        if (entry != null) {
            setPublicKeyBlacklist(entry);
        }
        setUpdateCounter(0);
    }

    //@Id @Column
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    //@Column
    public int getSource() {
        return source;
    }

    public void setSource(int source) {
        this.source = source;
    }

    //@Column
    /** See for instance {@link AlgorithmConstants#KEYALGORITHM_RSA} + length 'RSA2048' and others. */
    public String getKeyspec() {
        return keyspec;
    }

    public void setKeyspec(String keyspec) {
        this.keyspec = keyspec;
    }

    //@Column
    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    //@Column
    public int getUpdateCounter() {
        return updateCounter;
    }

    public void setUpdateCounter(int updateCounter) {
        this.updateCounter = updateCounter;
    }

    //@Column @Lob
    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
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

    /**
     * Method that gets the cached public key blacklist, if any.
     */
    @Transient
    public PublicKeyBlacklistEntry getCachedPublicKeyBlacklistEntry() {
        return publicKeyBlacklist;
    }

    /**
     * Method that saves the public key blacklist data to database.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void setPublicKeyBlacklist(PublicKeyBlacklistEntry entry) {
        // We must base64 encode string for UTF safety
        final HashMap base64Map = new Base64PutHashMap();
        base64Map.putAll((HashMap) entry.saveData());
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(base64Map);
        encoder.close();
        try {
            if (log.isDebugEnabled()) {
                log.debug("Public key blacklist data: \n" + baos.toString("UTF8"));
            }
            setData(baos.toString("UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        this.publicKeyBlacklist = entry;
        setUpdateCounter(getUpdateCounter() + 1);
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    public String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getSource()).append(getKeyspec()).append(getFingerprint()).append(getUpdateCounter()).append(getData());
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
    public static PublicKeyBlacklistData findById(EntityManager entityManager, int id) {
        return entityManager.find(PublicKeyBlacklistData.class, id);
    }

    /**
     * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
     * @return the found entity instance or null if the entity does not exist
     */
    public static PublicKeyBlacklistData findByFingerprint(EntityManager entityManager, String fingerprint) {
        final Query query = entityManager.createQuery("SELECT a FROM PublicKeyBlacklistData a WHERE a.fingerprint=:fingerprint");
        query.setParameter("fingerprint", fingerprint);
        return (PublicKeyBlacklistData) QueryResultWrapper.getSingleResult(query);
    }

    /** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<PublicKeyBlacklistData> findAll(EntityManager entityManager) {
        final Query query = entityManager.createQuery("SELECT a FROM PublicKeyBlacklistData a");
        return query.getResultList();
    }

    /** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<PublicKeyBlacklistData> findAllById(EntityManager entityManager, Collection<Integer> ids) {
        final Query query = entityManager.createQuery("SELECT a FROM PublicKeyBlacklistData a WHERE a.id IN (:ids)");
        query.setParameter("ids", ids);
        return query.getResultList();
    }
}
