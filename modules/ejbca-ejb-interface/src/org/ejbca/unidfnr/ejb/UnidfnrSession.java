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
package org.ejbca.unidfnr.ejb;

import org.cesecore.certificates.certificate.request.RequestMessage;


/**
 * Interface for handling unid-fnr logic.
 * @version $Id$
 *
 */
public interface UnidfnrSession {
    
    static final String UNIDFNR_MODULE = "unidfnr-ejb";
    
    /**
     * Called when the data handling should be done.
     * @param req Request to be modified.
     * @param otherData some other data
     * @return the modified request
     * @throws HandlerException The handle may throw this exception if some error occurs. Throwing it prevents the certificate creation.
     */
    RequestMessage processUnidfnrRequestMessage(RequestMessage req, String otherData, String unidDataSource) throws HandlerException;

    /**
     * Exception thrown by handler. No certificate should be created if this exception is thrown.
     *
     */
    class HandlerException extends Exception {

        private static final long serialVersionUID = 1L;

        public HandlerException(String message) {
            super(message);
        }
    }

}
