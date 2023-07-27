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

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;

import com.keyfactor.util.CertTools;

import java.io.Serializable;
import java.util.Objects;

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
        return CertTools.stringToBCDNString((String) data.get(DEFAULT_OCSP_RESPONDER_REFERENCE));
    }
    
    public void setOcspDefaultResponderReference(String reference) {
        data.put(DEFAULT_OCSP_RESPONDER_REFERENCE, reference);
    }
    
    @SuppressWarnings("deprecation")
    public OcspKeyBinding.ResponderIdType getOcspResponderIdType() {
        OcspKeyBinding.ResponderIdType ocspResponderIdType = (ResponderIdType) data.get(OCSP_RESPONDER_ID_TYPE_REFERENCE);
        if(ocspResponderIdType == null) {
            //Lazy upgrade if running from versions prior to 6.7.0
            ocspResponderIdType = OcspKeyBinding.ResponderIdType.getFromNumericValue(OcspConfiguration.getResponderIdType());
            setOcspResponderIdType(ocspResponderIdType);
        }
        return ocspResponderIdType;
    }
    
    public void setOcspResponderIdType(OcspKeyBinding.ResponderIdType ocspResponderIdType) {
        data.put(OCSP_RESPONDER_ID_TYPE_REFERENCE, ocspResponderIdType);
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

}
