/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import java.security.PublicKey;
import java.util.Date;
import java.util.List;

import org.cesecore.certificates.certificateprofile.CertificateProfile;

/**
 * Base interface for key validators. All key validators must implement this interface.
 * 
 * @version $Id$
 *
 */
public interface KeyValidator extends Validator {
    
    /** List of accepted date formats for notBefore and notAfter filter. */
    static final String[] DATE_FORMAT = new String[] { "yyyy-MM-dd HH:mm:ssZZ", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd" };
    
    /**
     * Method that validates the public key.
     * 
     * @param publicKey the public key to validate.
     * @param certificateProfile the Certificate Profile as input for validation
     * @return the error messages or an empty list if the public key was validated successfully.
     * @throws ValidatorNotApplicableException when this validator is not applicable for the input, for example ECC keys as input to an RSA key validator
     * @throws ValidationException if the certificate issuance MUST be aborted.
     */
    List<String> validate(PublicKey publicKey, CertificateProfile certificateProfiles) throws ValidatorNotApplicableException, ValidationException;
    
    void setNotBefore(Date date);
    
    /**
     * Sets the BaseKeyValidator notBefore field.
     * @param formattedDate the formatted date string.
     */
    void setNotBeforeAsString(String formattedDate);
    
    Date getNotBefore();
    
    String getNotBeforeAsString();
    
    void setNotBeforeCondition(int index);
    
    int getNotBeforeCondition();
    
    void setNotAfter(Date date);
    
    /**
     * Sets the BaseKeyValidator notAfter field.
     * @param formattedDate the formatted date string.
     */
    void setNotAfterAsString(String formattedDate);
    
    Date getNotAfter();
    
    String getNotAfterAsString();
    
    int getNotAfterCondition();
    
    void setNotAfterCondition(int index);
    
}
