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
package org.ejbca.ui.web;

/**
 * Used by the RequestHelper.pkcs10CertRequest method and
 * as a HTTP parameter to result_download.jsp page
 * 
 * @version $Id$
 */
public enum CertificateResponseType {
    UNSPECIFIED(0),
    ENCODED_CERTIFICATE(1),
    ENCODED_PKCS7(2),
    BINARY_CERTIFICATE(3),
    ENCODED_CERTIFICATE_CHAIN(4);
    
    
    private final int number;
    
    private CertificateResponseType(int number) {
        this.number = number;
    }
    
    public int getNumber() {
        return number;
    }
    
    public static CertificateResponseType fromNumber(int number) {
        for (CertificateResponseType resptype : CertificateResponseType.values()) {
            if (resptype.getNumber() == number) {
                return resptype;
            }
        }
        throw new IllegalArgumentException("No such certificate response type: " + number);
    }
    
    public static CertificateResponseType fromNumber(String number) {
        return fromNumber(Integer.parseInt(number));
    }
}
