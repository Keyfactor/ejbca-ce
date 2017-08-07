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
package org.cesecore.certificates.certificate;

import javax.ejb.ApplicationException;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * An exception thrown when a serious error happens creating a certificate. 
 * If this happens any transaction depending on this should be rolled back.
 * 
 * @version $Id$
 */
@ApplicationException(rollback = true)
public class CertificateCreateException extends CesecoreException {

    private static final long serialVersionUID = -642610825885468919L;

    /**
     * Creates a new instance of exception without detail message. Marked as rollback=true
     * 
     * @see CertificateCreateException
     */
    public CertificateCreateException() {
        super();
    }

    /**
     * Constructs an instance of exception with the specified detail message. Marked as rollback=true
     * 
     * @see CertificateCreateException
     * @param msg the detail message.
     */
    public CertificateCreateException(String msg) {
        super(msg);
    }

    /**
     * Marked as rollback=true
     * 
     * @see CertificateCreateException
     * @param e causing exception that will be wrapped
     */
    public CertificateCreateException(Exception e) {
        super(e);
    }

    /**
     * Marked as rollback=true
     * 
     * @see CertificateCreateException
     * @param errorCode defines the cause of the exception.
     * @param e causing exception that will be wrapped
     */
    public CertificateCreateException(ErrorCode errorCode, Exception e) {
        super(errorCode, e);
    }

    /**
     * Marked as rollback=true
     * 
     * @see CertificateCreateException
     * @param e causing exception that will be wrapped
     */
    public CertificateCreateException(String msg, Exception e) {
        super(msg, e);
    }

    /**
     * Marked as rollback=true
     *
     * @see CertificateCreateException
     * @param errorCode defines the cause of the exception.
     * @param message Human readable error message, can not be NULL.
     */
    public CertificateCreateException(ErrorCode errorCode, String msg) {
       super(errorCode, msg);
    }
}
