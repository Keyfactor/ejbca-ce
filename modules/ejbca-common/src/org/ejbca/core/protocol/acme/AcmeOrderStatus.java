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
package org.ejbca.core.protocol.acme;

import org.cesecore.certificates.endentity.EndEntityConstants;

/**
 * @version $Id$
 *
 */
public enum AcmeOrderStatus {
    /** "The certificate will not be issued. Consider this order process abandoned." */
    INVALID(EndEntityConstants.STATUS_FAILED),
    /** 
     * "The server does not believe that the client has fulfilled the requirements.
     * Check the "authorizations" array for entries that are still pending."
     */
    PENDING(EndEntityConstants.STATUS_INITIALIZED),
    /** 
     * "The server agrees that the requirements have been fulfilled, and is awaiting finalization. 
     * Submit a finalization request." 
     */
    READY(EndEntityConstants.STATUS_INPROCESS),
    /**
     * "The certificate is being issued. Send a GET request after the time given in the "Retry-After" 
     * header field of the response, if any."
     */
    PROCESSING(EndEntityConstants.STATUS_NEW),
    /** 
     * "The server has issued the certificate and provisioned its URL to the "certificate" field of the order. 
     * Download the certificate." 
     */
    VALID(EndEntityConstants.STATUS_GENERATED);
    
    private final int endEntityStatus;
    
    private AcmeOrderStatus(final int endEntityStatus) {
        this.endEntityStatus = endEntityStatus;
    }

    /** @return the corresponding EJBCA end entity status */
    public int getEndEntityStatus() { return endEntityStatus; }
    public static AcmeOrderStatus fromEndEntityStatus(final int endEntityStatus) {
        for (final AcmeOrderStatus current : AcmeOrderStatus.values()) {
            if (current.getEndEntityStatus()==endEntityStatus) {
                return current;
            }
        }
        return null;
    }
    public String getJsonValue() { return this.name().toLowerCase(); }
    public static AcmeOrderStatus fromJsonValue(final String status) { return AcmeOrderStatus.valueOf(status.toUpperCase()); }
}
