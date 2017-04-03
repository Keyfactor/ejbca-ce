/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.dbprotection;

import org.apache.log4j.Logger;


/**
 * Used as base class for JPA data beans that has a rowProtection column. The JPA class should extend this class and implement the simple methods:
 * 
 * <pre>
 * &#064;Transient
 * &#064;Override
 * String getProtectString(int version) {
 *   return &quot;concatenation of fields to be integrity protected. Must be deterministic and can change with different version of rowprotection.&quot;;
 *   // Example from CertificateProfileData
 *   // StringBuilder build = new StringBuilder();
 *   // What is important to protect here is the data that we define, id, name and certificate profile data
 *   // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
 *   // build.append(getId()).append(getCertificateProfileName()).append(getData());
 *   // return build.toString();
 * }
 * 
 * &#064;Transient
 * &#064;Override
 * int getProtectVersion() {
 *   return 1;
 * }
 * 
 * &#064;PrePersist
 * &#064;PreUpdate
 * &#064;Transient
 * &#064;Override
 * void protectData() {
 *   super.protectData();
 * }
 * 
 * &#064;PostLoad
 * &#064;Transient
 * &#064;Override
 * void verifyData() {
 *   super.verifyData();
 * }
 * 
 * &#064;Override
 * &#064;Transient
 * protected String getRowId() {
 *   return String.valueOf(getPrimaryKey());
 * }
 * </pre>
 * 
 * @version $Id$
 */
public abstract class ProtectedData {

    private static final Logger log = Logger.getLogger(ProtectedData.class);

    /** Implementation for the database protection method used */
    private ProtectedDataImpl impl;
    
    /** Definition of the optional database integrity protection implementation */
    private static final String implClassName = "org.cesecore.dbprotection.ProtectedDataIntegrityImpl";
    /** Cache class so we don't have to do Class.forName for every entity object created */
    private static volatile Class<?> implClass = null;
    
    /** Optimization variable so we don't have to check for existence of implClass for every construction of an entity object */
    private static volatile boolean integrityExists = true;
    
    /** A default constructor is needed by JPA.
     * This constructor initializes the available database integrity protection module, if any is available 
     */
    public ProtectedData() {
        if (integrityExists) {
            try {
                if (implClass == null) {
                    // We only end up here once, if the class does not exist, we will never end up here again (ClassNotFoundException) 
                    // and if the class exists we will never end up here again (it will not be null)
                    implClass = Class.forName(implClassName);
                    log.debug("ProtectedDataIntegrityImpl is available, and used, in this version of EJBCA.");
                }
                impl = (ProtectedDataImpl)implClass.newInstance();
                impl.setTableName(getTableName());
            } catch (ClassNotFoundException e) {
                // We only end up here once, if the class does not exist, we will never end up here again
                integrityExists = false;
                log.info("No database integrity protection available in this version of EJBCA.");
                impl = new ProtectedDataNoopImpl();         
            } catch (InstantiationException e) {
                log.error("Error intitilizing database integrity protection: ", e);
            } catch (IllegalAccessException e) {
                log.error("Error intitilizing database integrity protection: ", e);
            }           
        } else {
            impl = new ProtectedDataNoopImpl();         
        }
    }

    /**
     * asks the data class for the string to be protected. Version is -1 for a new row to be protected, and otherwise a version given earlier from the
     * data class when storing the row.
     * 
     * @param version the version of the string that is protected, used as input when verifying data. -1 when getting protection string for data to be
     *          inserted or updated. -1 means that the data class should use it's latest version of protect string
     * @return String to be integrity protected, i.e. input to hmac.
     */
    protected abstract String getProtectString(int rowversion);

    /**
     * asks the data class for the version of the string that is protected, used as input to getProtectString() when verifying data. This is used so
     * that the data class can alter itself with new fields, but still be backwards compatible and verify older database data. Called when getting the
     * version for inserts or updates.
     * 
     * @return int version the latest version of protection string.
     */
    protected abstract int getProtectVersion();

    /**
     * The extending class must have a database column "rowProtection" that can be read and set.
     */
    abstract public void setRowProtection(final String rowProtection);

    abstract public String getRowProtection();

    /**
     * Returns id of the row in the database, in case of failure we can see in the log which row failed to verify
     * 
     * @return id of database row, specific for implementing class.
     */
    protected abstract String getRowId();

    /** @return the database table name. Should be overridden by classes that does not share the same name as the database table it maps to (for example by subclassing). */
    protected String getTableName() {
        return this.getClass().getSimpleName();
    }

    /** Overridden by extending class to be able to use @PrePersist, overriding class calls super.protectData(). 
     * This method creates integrity protection for the specific entity in the database.
     * 
     * @throws DatabaseProtectionException (RuntimeException) on error creating integrity protection.
     */
    protected void protectData() {
        impl.protectData(this);
    }

    /** Overridden by extending class to be able to use @PostLoad, overriding class calls super.verifyData(). 
     * This method verifies integrity protection for the specific entity in the database.
     * 
     * @throws DatabaseProtectionException (RuntimeException) on verify error.
     */
    protected void verifyData() {
        impl.verifyData(this);
    }
    
    /** Method that calculates integrity protection of an entity, but does not store it anywhere. Used primarily to make test protection
     * in order to exercise the CryptoToken.
     * @return the calculated protection string
     */
    public String calculateProtection() {
        return impl.calculateProtection(this);
    }
}
