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
package org.cesecore.certificates.ca;

import java.io.Serializable;
import java.util.LinkedHashMap;

import org.cesecore.certificates.certificatetransparency.CTAuditLogCallback;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;

/**
 * Contains parameters and callbacks which is needed during certificate
 * generation in X509CA, e.g. by the CT extension. This can be used to access
 * session beans from this class, for instance the global configuration
 * or audit logging.
 * 
 * @note Since instances of this class may reference session beans, you must ensure
 * that instances of this interface are only used temporarily, e.g. as
 * functions arguments, and never as e.g. instance variables of non-temporary
 * classes.
 * 
 * @note Since it might not be possible to obtain the parameters, all methods that
 * accept objects of this class should also accept a null value, or null values
 * inside the CertificateGenerationParams object.
 * 
 * @see CTAuditLogCallback
 * 
 * @version $Id$
 */
public final class CertificateGenerationParams implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private LinkedHashMap<Integer,CTLogInfo> configuredCTLogs;
    private CTAuditLogCallback ctAuditLogCallback;
    
    /**
     * Set the CT logs from the system configuration.
     */
    public void setConfiguredCTLogs(LinkedHashMap<Integer,CTLogInfo> configuredCTLogs) {
        this.configuredCTLogs = configuredCTLogs;
    }
    
    /**
     * Set the a callback to be called after CT log submission.
     * This method is called automatically from CertificateCreateSession when generating a certificate.
     */
    public void setCTAuditLogCallback(CTAuditLogCallback ctAuditLogCallback) {
        this.ctAuditLogCallback = ctAuditLogCallback;
    }
    
    
    /* Package internal methods are called from X509CA */
    
    LinkedHashMap<Integer,CTLogInfo> getConfiguredCTLogs() {
        return configuredCTLogs;
    }
    
    CTAuditLogCallback getCTAuditLogCallback() {
        return ctAuditLogCallback;
    }
    
}
