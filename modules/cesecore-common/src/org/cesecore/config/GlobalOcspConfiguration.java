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
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.keybind.impl.OcspNonExistingBehavior;

import com.keyfactor.util.certificate.DnComponents;

/**
 * Contains global configuration values for OCSP and OCSP responders
 */

public class GlobalOcspConfiguration extends ConfigurationBase implements Serializable {

    public static final String OCSP_CONFIGURATION_ID = "OCSP";
   
    private static final long serialVersionUID = 1L;

    private static final String DEFAULT_OCSP_RESPONDER_REFERENCE = "defaultOcspResponderReference";
    private static final String OCSP_RESPONDER_ID_TYPE_REFERENCE = "ocspResponderIdType";
    private static final String DEFAULT_NONCE_ENABLED_REFERENCE = "defaultNonceEnabled";
    private static final String OCSP_SIGNING_CACHE_UPDATE_ENABLED = "ocspSigningCacheUpdateEnabled";
    private static final String EXPLICIT_NO_CACHE_UNAUTHORIZED_RESPONSES_ENABLED = "explicitNoCacheUnauthorizedResponsesEnabled";
    private static final String PROPERTY_IS_OCSP_TRANSACTION_LOGGING_ENABLED = "isOcspTransactionLoggingEnabled";
    private static final String PROPERTY_OCSP_TRANSACTION_LOG_PATTERN = "ocspTransactionLogPattern";
    private static final String PROPERTY_OCSP_TRANSACTION_LOG_VALUES = "ocspTransactionLogValues";
    private static final String PROPERTY_IS_OCSP_AUDIT_LOGGING_ENABLED = "ocspAuditLoggingEnabled";
    private static final String PROPERTY_OCSP_AUDIT_LOG_PATTERN = "ocspAuditLogPattern";
    private static final String PROPERTY_OCSP_AUDIT_LOG_VALUES = "ocspAuditLogValues";
    private static final String PROPERTY_OCSP_LOGGING_DATE_FORMAT = "ocspLoggingDateFormat";
    private static final String PROPERTY_OCSP_DEFAULT_RESPONSE_VALIDITY = "ocspDefaultResponseValidity";
    private static final String PROPERTY_OCSP_DEFAULT_RESPONSE_MAX_AGE = "ocspDefaultResponseMaxAge";
    private static final String PROPERTY_OCSP_USE_MAX_AGE_FOR_EXPIRATION = "useMaxValidityForExpiration";
    private static final String INCLUDE_SIGNING_CERTIFICATE = "includeSigningCertificate";
    private static final String INCLUDE_CERTIFICATE_CHAIN = "includeCertificateChain";
    private static final String NON_EXISTING_BEHAVIOR = "nonExistingBehavior";
    private static final String REQUEST_SIGNER_REVOCATION_STATUS_CACHE_TIME = "ocspRequestSignerRevocationStatusCacheTime";
    
    /**
     * 
     * @return the revocation status cache time, in milliseconds. 0 means no caching is performed.
     */
    public long getRequestSignserRevocationStatusCacheTime() {
        if(data.get(REQUEST_SIGNER_REVOCATION_STATUS_CACHE_TIME) == null) {
            //60 was the default value prior to this value being moved into the database in 9.4
            setRequestSignserRevocationStatusCacheTime(60000);
        }
        return (long) data.get(REQUEST_SIGNER_REVOCATION_STATUS_CACHE_TIME);
    }
    
    public void setRequestSignserRevocationStatusCacheTime(long cacheTimeInSeconds) {
        data.put(REQUEST_SIGNER_REVOCATION_STATUS_CACHE_TIME, cacheTimeInSeconds);
    }
    
    public boolean getIncludeSigningCertificate() {
        if(data.get(INCLUDE_SIGNING_CERTIFICATE) == null) {
            setIncludeSigningCertificate(true);
        }
        return (boolean) data.get(INCLUDE_SIGNING_CERTIFICATE);
    }
    
    public void setIncludeSigningCertificate(final boolean includeSigningCertificate) {
        data.put(INCLUDE_SIGNING_CERTIFICATE, includeSigningCertificate);
    }
    
    public boolean getIncludeCertificateChain() {
        if(data.get(INCLUDE_CERTIFICATE_CHAIN) == null) {
           setIncludeCertificateChain(true);
        }
        return (boolean) data.get(INCLUDE_CERTIFICATE_CHAIN);
    }
    
    public void setIncludeCertificateChain(final boolean includeCertificateChain) {
        data.put(INCLUDE_CERTIFICATE_CHAIN, includeCertificateChain);
    }

    // OCSP Cleanup
    private static final String PROPERTY_OCSP_CLEANUP_USE = "ocsp.cleanup.use";
    private static final boolean PROPERTY_OCSP_CLEANUP_USE_DEFAULT = false;
    private static final String PROPERTY_OCSP_CLEANUP_SCHEDULE = "ocsp.cleanup.schedule";
    private static final String PROPERTY_OCSP_CLEANUP_SCHEDULE_DEFAULT = "5";
    private static final String PROPERTY_OCSP_CLEANUP_SCHEDULE_UNIT = "ocsp.cleanup.schedule_unit";
    private static final String PROPERTY_OCSP_CLEANUP_SCHEDULE_UNIT_DEFAULT = TimeUnit.HOURS.toString();

    public boolean getExplicitNoCacheUnauthorizedResponsesEnabled() {
        if (Objects.isNull(data.get(EXPLICIT_NO_CACHE_UNAUTHORIZED_RESPONSES_ENABLED))) {
            setExplicitNoCacheUnauthorizedResponsesEnabled(false); // Put the default if not already present
        }
        return (Boolean) data.get(EXPLICIT_NO_CACHE_UNAUTHORIZED_RESPONSES_ENABLED);
    }

    public void setExplicitNoCacheUnauthorizedResponsesEnabled(final boolean cacheForUnknownStatusEnabled) {
        data.put(EXPLICIT_NO_CACHE_UNAUTHORIZED_RESPONSES_ENABLED, cacheForUnknownStatusEnabled);
    }

    public boolean getOcspSigningCacheUpdateEnabled() {
        if (Objects.isNull(data.get(OCSP_SIGNING_CACHE_UPDATE_ENABLED))) {
            setOcspSigningCacheUpdateEnabled(false); // Put the default if not already present 
        }
        return (Boolean) data.get(OCSP_SIGNING_CACHE_UPDATE_ENABLED);
    }
    
    public void setOcspSigningCacheUpdateEnabled(final boolean ocspSigningCacheUpdateEnable) {
        data.put(OCSP_SIGNING_CACHE_UPDATE_ENABLED, ocspSigningCacheUpdateEnable);
    }

    public String getOcspDefaultResponderReference() {
        return DnComponents.stringToBCDNString((String) data.get(DEFAULT_OCSP_RESPONDER_REFERENCE));
    }
    
    public void setOcspDefaultResponderReference(String reference) {
        data.put(DEFAULT_OCSP_RESPONDER_REFERENCE, reference);
    }
    
    public OcspKeyBinding.ResponderIdType getOcspResponderIdType() {
        OcspKeyBinding.ResponderIdType ocspResponderIdType = (ResponderIdType) data.get(OCSP_RESPONDER_ID_TYPE_REFERENCE);
        return ocspResponderIdType;
    }
    
    public void setOcspResponderIdType(OcspKeyBinding.ResponderIdType ocspResponderIdType) {
        data.put(OCSP_RESPONDER_ID_TYPE_REFERENCE, ocspResponderIdType);
    }

    // OCSP Cleanup
    public void setOcspCleanupUse(final boolean value) {
        putBoolean(PROPERTY_OCSP_CLEANUP_USE, value);
    }

    public boolean getOcspCleanupUse() {
        return getBoolean(PROPERTY_OCSP_CLEANUP_USE, PROPERTY_OCSP_CLEANUP_USE_DEFAULT);
    }

    public void setOcspCleanupSchedule(final String value) {
        data.put(PROPERTY_OCSP_CLEANUP_SCHEDULE, value);
    }

    public String getOcspCleanupSchedule() {
        return getString(PROPERTY_OCSP_CLEANUP_SCHEDULE, PROPERTY_OCSP_CLEANUP_SCHEDULE_DEFAULT);
    }

    public void setOcspCleanupScheduleUnit(final String value) {
        data.put(PROPERTY_OCSP_CLEANUP_SCHEDULE_UNIT, value);
    }

    public String getOcspCleanupScheduleUnit() { return getString(
            PROPERTY_OCSP_CLEANUP_SCHEDULE_UNIT, PROPERTY_OCSP_CLEANUP_SCHEDULE_UNIT_DEFAULT);
    }
    
    /**
     * 
     * @return true if CA's replying to their own OCSP requests should include NONCE's in the replies. 
     */
    public boolean getNonceEnabled() {
        // Lazy upgrade
        if (data.get(DEFAULT_NONCE_ENABLED_REFERENCE) == null) {
            setNonceEnabled(true);
        }
        return (Boolean) data.get(DEFAULT_NONCE_ENABLED_REFERENCE);
    }

    public void setIsOcspTransactionLoggingEnabled(final boolean isOcspTransactionLoggingEnabled) {
        data.put(PROPERTY_IS_OCSP_TRANSACTION_LOGGING_ENABLED, isOcspTransactionLoggingEnabled);
    }

    public boolean getIsOcspTransactionLoggingEnabled() {
        if (data.get(PROPERTY_IS_OCSP_TRANSACTION_LOGGING_ENABLED) == null) {
            return false;
        }
        return (Boolean) data.get(PROPERTY_IS_OCSP_TRANSACTION_LOGGING_ENABLED);
    }

    public void setOcspTransactionLogPattern(final String ocspTransactionLogPattern) {
        data.put(PROPERTY_OCSP_TRANSACTION_LOG_PATTERN, ocspTransactionLogPattern);
    }

    public String getOcspTransactionLogPattern() {
        if (data.get(PROPERTY_OCSP_TRANSACTION_LOG_PATTERN) == null) {
            return "\\$\\{(.+?)\\}";
        }
        return (String) data.get(PROPERTY_OCSP_TRANSACTION_LOG_PATTERN);
    }

    public void setOcspTransactionLogValues(final String ocspTransactionLogValues) {
        data.put(PROPERTY_OCSP_TRANSACTION_LOG_VALUES, ocspTransactionLogValues);
    }

    public String getOcspTransactionLogValues() {
        if (data.get(PROPERTY_OCSP_TRANSACTION_LOG_VALUES) == null) {
            return "${SESSION_ID};${LOG_ID};${STATUS};${REQ_NAME}\"${CLIENT_IP}\";\"${SIGN_ISSUER_NAME_DN}\";\"" +
                    "${SIGN_SUBJECT_NAME}\";${SIGN_SERIAL_NO};\"${LOG_TIME}\";${REPLY_TIME};${NUM_CERT_ID};0;" +
                    "0;0;0;0;0;0;\"${ISSUER_NAME_DN}\";${ISSUER_NAME_HASH};"
                    + "${ISSUER_KEY};\"${OCSP_CERT_ISSUER_NAME_DN}\";${DIGEST_ALGOR};" +
                    "${SERIAL_NOHEX};${CERT_STATUS};${CERT_PROFILE_ID};${FORWARDED_FOR}";
        }
        return (String) data.get(PROPERTY_OCSP_TRANSACTION_LOG_VALUES);
    }

    public void setIsOcspAuditLoggingEnabled(final boolean isOcspAuditLoggingEnabled) {
        data.put(PROPERTY_IS_OCSP_AUDIT_LOGGING_ENABLED, isOcspAuditLoggingEnabled);
    }

    public boolean getIsOcspAuditLoggingEnabled() {
        if (data.get(PROPERTY_IS_OCSP_AUDIT_LOGGING_ENABLED) == null) {
            return false;
        }
        return (Boolean) data.get(PROPERTY_IS_OCSP_AUDIT_LOGGING_ENABLED);
    }

    public void setOcspAuditLogPattern(final String ocspAuditLogPattern) {
        data.put(PROPERTY_OCSP_AUDIT_LOG_PATTERN, ocspAuditLogPattern);
    }

    public String getOcspAuditLogPattern() {
        if (data.get(PROPERTY_OCSP_AUDIT_LOG_PATTERN) == null) {
            return "\\$\\{(.+?)\\}";
        }
        return (String) data.get(PROPERTY_OCSP_AUDIT_LOG_PATTERN);
    }

    public void setOcspAuditLogValues(final String ocspAuditLogValues) {
        data.put(PROPERTY_OCSP_AUDIT_LOG_VALUES, ocspAuditLogValues);
    }

    public String getOcspAuditLogValues() {
        if (data.get(PROPERTY_OCSP_AUDIT_LOG_VALUES) == null) {
            return  "SESSION_ID:${SESSION_ID};LOG ID:${LOG_ID};\"${LOG_TIME}" +
                    "\";TIME TO PROCESS:${REPLY_TIME};\\nOCSP REQUEST:\\n\"${OCSPREQUEST}" +
                    "\";\\nOCSP RESPONSE:\\n\"${OCSPRESPONSE}\";\\nSTATUS:${STATUS}";
        }
        return (String) data.get(PROPERTY_OCSP_AUDIT_LOG_VALUES);
    }

    public void setOcspLoggingDateFormat(final String ocspLoggingDateFormat) {
        data.put(PROPERTY_OCSP_LOGGING_DATE_FORMAT, ocspLoggingDateFormat);
    }

    public String getOcspLoggingDateFormat() {
        if (data.get(PROPERTY_OCSP_LOGGING_DATE_FORMAT) == null) {
            return "yyyy-MM-dd HH:mm:ss.SSSZ";
        }
        return (String) data.get(PROPERTY_OCSP_LOGGING_DATE_FORMAT);
    }

    /**
     * 
     * @param enabled to true if CA's replying to their own OCSP requests should include NONCE's in the replies. 
     */
    public void setNonceEnabled(boolean enabled) {
        data.put(DEFAULT_NONCE_ENABLED_REFERENCE, enabled);
    }
    
    @Override
    public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION, LATEST_VERSION);          
        }
    }

    @Override
    public String getConfigurationId() {
        return OCSP_CONFIGURATION_ID;
    }
    
    /**
     * 
     * @return the default validity time, in seconds
     */
    public long getDefaultValidityTime() {
        if(data.get(PROPERTY_OCSP_DEFAULT_RESPONSE_VALIDITY) == null) {
            return 0L;
        } else {
            return (long) data.get(PROPERTY_OCSP_DEFAULT_RESPONSE_VALIDITY);
        }
    }
    
    /**
     * 
     * @param validityTime the default validity time, in seconds
     */
    public void setDefaultValidityTime(long validityTime) {
        data.put(PROPERTY_OCSP_DEFAULT_RESPONSE_VALIDITY, validityTime);
    }
    
    /**
     * 
     * @return the default validity time, in seconds
     */
    public long getDefaultResponseMaxAge() {
        if(data.get(PROPERTY_OCSP_DEFAULT_RESPONSE_MAX_AGE) == null) {
            //Default based on legacy configuration
            return 30L;
        } else {
            return (long) data.get(PROPERTY_OCSP_DEFAULT_RESPONSE_MAX_AGE);
        }
    }
    
    /**
     * 
     * @param responseMaxAge the default response max age, in seconds
     * 
     */
    public void setDefaultResponseMaxAge(long responseMaxAge) {        
        data.put(PROPERTY_OCSP_DEFAULT_RESPONSE_MAX_AGE, responseMaxAge);
    }
    
    /**
     * 
     * @return true for if expired OCSP replies should use Max Age as a validity instead of the validity time
     */
    public boolean getUseMaxValidityForExpiration() {

        if (data.get(PROPERTY_OCSP_USE_MAX_AGE_FOR_EXPIRATION) == null) {
            //Default based on legacy configuration
            return false;
        } else {
            return (boolean) data.get(PROPERTY_OCSP_USE_MAX_AGE_FOR_EXPIRATION);
        }
    }
    
    public void setUseMaxValidityForExpiration(boolean useMaxValidityForExpiration) {
        data.put(PROPERTY_OCSP_USE_MAX_AGE_FOR_EXPIRATION, useMaxValidityForExpiration);
    }

    /**
     * @return an enum describing how the CAs should (on a global level) react to being queried for a non-existent serial number
     */
    public OcspNonExistingBehavior getOcspNonExistingBehavior() {
        if(data.get(NON_EXISTING_BEHAVIOR) == null) {
            return OcspNonExistingBehavior.UNKNOWN;
        } else {
            return OcspNonExistingBehavior.fromLabel((String) data.get(NON_EXISTING_BEHAVIOR));
        }
    }
    
    public void setOcspNonExistingBehavior(final OcspNonExistingBehavior ocspNonExistingBehavior) {
        data.put(NON_EXISTING_BEHAVIOR, ocspNonExistingBehavior.getLabel());
    }
    
}
