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
import java.util.List;

/**
 * Base interface for key validators. All key validators must implement this interface.
 * 
 * @version $Id$
 */

public interface IKeyValidator {

    /**
     * Gets the type of the key validator.
     * @return the type.
     */
    public Integer getType();

    /**
     * Gets the type of the key validator implementation class.
     * @return the type.
     */
    public Integer getKeyValidatorType();

    /**
     * Gets the failed action index {@link KeyValidationFailedActions}
     * @return the index.
     */
    public int getFailedAction();

    /**
     * Gets the key validators unique name.
     * @return
     */
    public String getName();

    /**
     * Method that is invoked before validation. This is the place to initialize resources such as crypto providers, custom data, etc.
     */
    public void before();

    /**
     * Method that validates the public key.
     * 
     * @param publicKey the public key to validate.
     * @return true if the public key was validated successfully and no error message was added.
     * @throws KeyValidationException if the certificate issuance MUST be aborted.
     * @throws Exception any technical motivated exception.
     */
    public boolean validate(PublicKey publicKey) throws KeyValidationException, Exception;

    /**
     * Method that is invoked after validation. This is a good place to clean up and finalize resources.
     */
    public void after();

    /**
     * Gets the error messages or an empty list.
     * @return the list.
     */
    public List<String> getMessages();

    /**
     * Gets the public key reference.
     * @return the public key.
     */
    public PublicKey getPublicKey();

    /**
     * Gets the XHTML template file in /WEB-INF/ca/editkeyvalidators.
     * @return the file path.
     */
    public abstract String getTemplateFile();
}
