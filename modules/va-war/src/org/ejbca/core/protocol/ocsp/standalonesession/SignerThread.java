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

package org.ejbca.core.protocol.ocsp.standalonesession;

import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;

/**
 * Runnable that will do the response signing.
 * The signing is runned in a separate thread since it in rare occasion does not return.
 * 
 * @author primelars
 * @version  $Id$
 */
class SignerThread implements Runnable{
    final private SigningEntity se;
    final private OCSPCAServiceRequest request;
    private OCSPCAServiceResponse result = null;
    private ExtendedCAServiceRequestException extendedCAServiceRequestException = null;
    private IllegalExtendedCAServiceRequestException illegalExtendedCAServiceRequestException = null;
    SignerThread( SigningEntity _se, OCSPCAServiceRequest _request) {
        this.se = _se;
        this.request = _request;
    }
    /* (non-Javadoc)
     * @see java.lang.Runnable#run()
     */
    public void run() {
        OCSPCAServiceResponse _result = null;
        ExtendedCAServiceRequestException _extendedCAServiceRequestException = null;
        IllegalExtendedCAServiceRequestException _illegalExtendedCAServiceRequestException = null;
        try {
            _result = this.se.sign(this.request);
        } catch (ExtendedCAServiceRequestException e) {
            _extendedCAServiceRequestException = e;
        } catch (IllegalExtendedCAServiceRequestException e) {
            _illegalExtendedCAServiceRequestException = e;
        }
        synchronized(this) { // setting the results must be synchronized. The main thread may not access these attributes during this time.
            this.result = _result;
            this.extendedCAServiceRequestException = _extendedCAServiceRequestException;
            this.illegalExtendedCAServiceRequestException = _illegalExtendedCAServiceRequestException;
            this.notifyAll();
        }
    }
    /**
     * This method is called by the main thread to get the signing result. The method waits until the result is ready or until a timeout is reached.
     * @return the result
     * @throws ExtendedCAServiceRequestException
     * @throws IllegalExtendedCAServiceRequestException
     */
    synchronized OCSPCAServiceResponse getSignResult() throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException {
        final long HSM_TIMEOUT=30000; // in milliseconds
        if ( this.result==null && this.extendedCAServiceRequestException==null && this.illegalExtendedCAServiceRequestException==null ) {
            try {
                this.wait(HSM_TIMEOUT);
            } catch (InterruptedException e) {
                throw new Error(e);
            }
        }
        if ( this.illegalExtendedCAServiceRequestException!=null ) {
            throw this.illegalExtendedCAServiceRequestException;
        }
        if ( this.extendedCAServiceRequestException!=null ) {
            throw this.extendedCAServiceRequestException;
        }
        if ( this.result==null ) {
            throw new ExtendedCAServiceRequestException("HSM has not responded within time limit. The timeout is set to "+HSM_TIMEOUT/1000+" seconds.");
        }
        return this.result;
    }
}