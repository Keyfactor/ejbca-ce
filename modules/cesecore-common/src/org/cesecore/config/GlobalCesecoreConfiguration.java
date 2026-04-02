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
package org.cesecore.config;

import java.io.Serializable;

import org.cesecore.configuration.ConfigurationBase;

import com.keyfactor.util.Base64;
import com.keyfactor.util.string.StringConfigurationCache;
/**
 * Handles global CESeCore configuration values. 
 * 
 */
public class GlobalCesecoreConfiguration extends ConfigurationBase implements Serializable {
    
    private static final long serialVersionUID = 1L;
        
    public static final int DEFAULT_QUERY_COUNT = 500;
    public static final long DEFAULT_QUERY_TIMEOUT = 10000L;
    public static final boolean DEFAULT_REDACT_PII_DATA_BY_DEFAULT = false;
    public static final boolean DEFAULT_REDACT_PII_DATA_ENFORCED = false;
    public static final char[] DEFAULT_FORBIDDEN_CHARACTERS = new char[] {'\n', '\r',';','!','\u0000','%','`', '?', '$', '~'};
    public static final int DEFAULT_DATABASE_CRL_FETCH_SIZE = 500000;
    public static final boolean DEFAULT_DATABASE_CRL_FETCH_ORDERED = false;
    
    
    /** A fixed maximum value to ensure that max query count does not exceed sane values  */
    private static final int FIXED_MAXIMUM_QUERY_COUNT = 25_000;
    
    public static final String CESECORE_CONFIGURATION_ID = "CESECORE_CONFIGURATION";
    
    private static final String MAXIMUM_QUERY_COUNT_KEY = "maximum.query.count";
    private static final String MAXIMUM_QUERY_TIMEOUT_KEY = "maximum.query.timeout";
    
    private static final String REDACT_PII_DATA_DEFAULT = "redact.pii.default";
    private static final String REDACT_PII_DATA_ENFORCED = "redact.pii.enforced";
    
    private static final String FORBIDDEN_CHARACTERS = "forbidden.characters";
    
    private static final String DATABASE_CRL_FETCH_SIZE = "database.crlgenfetchsize";
    private static final String DATABASE_CRL_FETCH_ORDERED = "database.crlgenfetchordered";
    
    @Deprecated(since = "9.4.0")
    private static final String CT_CACHE_ENABLED_KEY = "ct_cache_enabled";
    @Deprecated(since = "9.4.0")
    private static final String CT_CACHE_SIZE_KEY = "ct_cache_size";
    @Deprecated(since = "9.4.0")
    private static final String CT_CACHE_CLEANUP_INTERVAL_KEY = "ct_cache_cleanup_interval";
    @Deprecated(since = "9.4.0")
    private static final String CT_CACHE_FAST_FAIL_ENABLED_KEY = "ct_cache_fast_fail_enabled";
    @Deprecated(since = "9.4.0")
    private static final String CT_CACHE_FAST_FAIL_BACKOFF_KEY = "ct_cache_fast_fail_backoff";
    
    @Override
    public void upgrade() {
    }

    @Override
    public String getConfigurationId() {
        return CESECORE_CONFIGURATION_ID;
    }
    
    /** 
     * Use a default value when End entity profile redaction settings is not accessible e.g. 
     * in peers(RA/VA), EMPTY end entity profile, exception messages with multiple sources etc 
     */
    public boolean getRedactPiiByDefault() {
        final Object res = data.get(REDACT_PII_DATA_DEFAULT);
        return res == null ? DEFAULT_REDACT_PII_DATA_BY_DEFAULT : (boolean) res;
    }
    
    public void setRedactPiiByDefault(boolean redactPiiByDefault) {
        data.put(REDACT_PII_DATA_DEFAULT, redactPiiByDefault);
    }
    
    /** 
     * This flag may be enabled(true) to redact PII data irrespective of the setting at End entity profile
     * It will allow customer to redact data for a CA node without editing every single profile 
     */
    public boolean getRedactPiiEnforced() {
        final Object res = data.get(REDACT_PII_DATA_ENFORCED);
        return res == null ? DEFAULT_REDACT_PII_DATA_ENFORCED : (boolean) res;
    }
    
    public void setRedactPiiEnforced(boolean redactPiiEnforced) {
        data.put(REDACT_PII_DATA_ENFORCED, redactPiiEnforced);
    }
    
    /** @return the maximum size of the result from SQL select queries */
    public int getMaximumQueryCount() {
        final Object num = data.get(MAXIMUM_QUERY_COUNT_KEY);
        return num == null ? DEFAULT_QUERY_COUNT : (int) num;
    }
    
    /**
     * Set's the maximum query count
     * 
     * @param maximumQueryCount the maximum query count
     * @throws InvalidConfigurationException if value was negative or above the limit set by {@link GlobalCesecoreConfiguration#MAXIMUM_QUERY_COUNT_KEY}
     */
    public void setMaximumQueryCount(int maximumQueryCount) throws InvalidConfigurationException { 
        if (maximumQueryCount > FIXED_MAXIMUM_QUERY_COUNT) {
            throw new InvalidConfigurationException("Unable to set query size limit of " + maximumQueryCount +  ". System has a fixed limit of " + FIXED_MAXIMUM_QUERY_COUNT + ".");
        }
        if (maximumQueryCount < 1) {
            throw new InvalidConfigurationException("Minimum valid query size limit is 1.");
        }
        data.put(MAXIMUM_QUERY_COUNT_KEY, maximumQueryCount);
    }

    /** @return database dependent query timeout hint in milliseconds or 0 if this is disabled. */
    public long getMaximumQueryTimeout() {
        final Object num = data.get(MAXIMUM_QUERY_TIMEOUT_KEY);
        return num == null ? DEFAULT_QUERY_TIMEOUT : (long) num;
    }

    /** Set's the database dependent query timeout hint in milliseconds or 0 if this is disabled. 
     * @throws InvalidConfigurationException */
    public void setMaximumQueryTimeout(final long maximumQueryTimeoutMs) throws InvalidConfigurationException { 
        if(maximumQueryTimeoutMs < 0) {
            throw new InvalidConfigurationException("Maximum query timeout cannot be set to less than 0 (disabled).");
        }
        
        data.put(MAXIMUM_QUERY_TIMEOUT_KEY, Math.max(maximumQueryTimeoutMs, 0L));
    }
    
    public char[] getForbiddenCharacters() {
        Object databaseValue = data.get(FORBIDDEN_CHARACTERS);
        if (databaseValue != null) {
            return unescapeSqlChars(((String) databaseValue)).toCharArray();
        } else {
            return DEFAULT_FORBIDDEN_CHARACTERS;
        }
    }

    /**
     * 
     * @param forbiddenCharacters a char array containing all characters to be auto-escaped. Setting this to null will use the default value set in x509-common-utils
     */
    public void setForbiddenCharacters(char[] forbiddenCharacters) {
        if(forbiddenCharacters == null) {
            forbiddenCharacters = DEFAULT_FORBIDDEN_CHARACTERS;
        }
        data.put(FORBIDDEN_CHARACTERS, escapeSqlChars(new String(forbiddenCharacters) ));
    }
    
    private String escapeSqlChars(String input) {       
        return new String(Base64.encode(input.getBytes()));
    }
    
    private String unescapeSqlChars(String input) {
        return new String(Base64.decode(input.getBytes()));
    }
    
    /**
     *  When generating large CRLs, the RAM of the Java process will limit how many entries that can be fetched from the database at the time. A small value will lead to 
     *  multiple round-trips to the database and CRL generation will take more time.
     *  
     *  The heap usage can be estimated to roughly 600 bytes * rows per database read. The default of 0.5M revoked entries per database round trip will usually fit within 
     *  a 2GiB heap assigned to the application server. If multiple large CRLs are generated at the same time, the used heap will be the sum of the heap used by each CRL generation.
     *  
     *  If you have plenty of RAM assigned to the application server you should increase this value.
     */
    public int getCrlGenerationFetchSize() {
        Object databaseValue = data.get(DATABASE_CRL_FETCH_SIZE);
        if(databaseValue != null) {
            return (int) databaseValue;
        } else {
            return DEFAULT_DATABASE_CRL_FETCH_SIZE;
        }
    }
    
    public void setCrlGenerationFetchSize(int size) {
        data.put(DATABASE_CRL_FETCH_SIZE, size);
    }
    
    /**
     * Whether EJBCA should request ordered fetching of revoked certificates when generating CRLs. EJBCA relies on Hibernate to return data in batches (getCrlGenerationFetchSize to control 
     * the read batch size). However, Microsoft SQL Server 2016 is known to return duplicates and/or missing entries when multiple batches are read. The setting below is a workaround for 
     * this problem.
     */
    public boolean getCrlGenerationFetchOrdered() {
        Object databaseValue = data.get(DATABASE_CRL_FETCH_ORDERED);
        if(databaseValue != null) {
            return (boolean) databaseValue;
        } else {
            return DEFAULT_DATABASE_CRL_FETCH_ORDERED;
        }
    }
    
    public void setCrlGenerationFetchOrdered(boolean ordered) {
        data.put(DATABASE_CRL_FETCH_ORDERED, ordered);
    }
    
    
    @Deprecated(since = "9.4.0")
    public boolean getCtCacheEnabled() { return getBoolean(CT_CACHE_ENABLED_KEY, true); }
    @Deprecated(since = "9.4.0")
    public void setCtCacheEnabled(final boolean value) { data.put(CT_CACHE_ENABLED_KEY, value); } 
    
    @Deprecated(since = "9.4.0")
    public long getCtCacheSize() { 
        Long value = (Long) data.get(CT_CACHE_SIZE_KEY);
        if(value == null) {
            setCtCacheSize(1000000L);
        }
        return (Long) data.get(CT_CACHE_SIZE_KEY);
    }
    
    @Deprecated(since = "9.4.0")
    public void setCtCacheSize(final long ctCacheSize) {
        data.put(CT_CACHE_SIZE_KEY, ctCacheSize);
    }
    
    @Deprecated(since = "9.4.0")
    public long getCtCacheCleanupInterval() {
        Long value = (Long) data.get(CT_CACHE_CLEANUP_INTERVAL_KEY);
        if(value == null) {
            setCtCacheCleanupInterval(10000L);
        }
        return (Long) data.get(CT_CACHE_CLEANUP_INTERVAL_KEY);
    }
    
    @Deprecated(since = "9.4.0")
    public void setCtCacheCleanupInterval(final long interval) {
        data.put(CT_CACHE_CLEANUP_INTERVAL_KEY, interval);
    }
    
    @Deprecated(since = "9.4.0")
    public boolean getCtCacheFastFailEnabled() {
        return getBoolean(CT_CACHE_FAST_FAIL_ENABLED_KEY, true);
    }
    
    @Deprecated(since = "9.4.0")
    public void setCtCacheFastFailEnabled(final boolean fastFailEnabled) {
        data.put(CT_CACHE_FAST_FAIL_ENABLED_KEY, fastFailEnabled);
    }
    
    @Deprecated(since = "9.4.0")
    public long getCtCacheFastFailBackoff() {
        Long value = (Long) data.get(CT_CACHE_FAST_FAIL_BACKOFF_KEY);
        if(value == null) {
            setCtCacheFastFailBackoff(1000L);
        }
        return (Long) data.get(CT_CACHE_FAST_FAIL_BACKOFF_KEY);
    }
    
    @Deprecated(since = "9.4.0")
    public void setCtCacheFastFailBackoff(final long backoff) {
        data.put(CT_CACHE_FAST_FAIL_BACKOFF_KEY, backoff);
    }
    
    @Override
    public void updateExternalCaches() {
        StringConfigurationCache.INSTANCE.setForbiddenCharacters(getForbiddenCharacters());
    }
    
}
