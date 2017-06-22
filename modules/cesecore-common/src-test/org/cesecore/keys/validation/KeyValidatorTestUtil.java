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

/**
 * Static helper key validator tests.
 * 
 * @version $Id: KeyValidatorTestUtil.java 25500 2017-04-01 11:28:08Z anjakobs $
 */
package org.cesecore.keys.validation;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.ejbca.core.model.ca.validation.PublicKeyBlacklistKeyValidator;

public final class KeyValidatorTestUtil {

    /**
     * Factory method to create key validators.
     * 
     * @param type the key validator type (see {@link BaseKeyValidator#KEY_VALIDATOR_TYPE}
     * @param name the logical name
     * @param description the description text
     * @param notBefore the certificates validity not before
     * @param notBeforeCondition the certificates validity not before condition
     * @param notAfter the certificates validity not after
     * @param notAfterCondition the certificates validity not after condition
     * @param failedAction the failed action to be performed.
     * @param certificateProfileIds list of IDs of certificate profile to be applied to. 
     * @return the concrete key validator instance.
     */
    public static final BaseKeyValidator createKeyValidator(final int type, final String name, final String description, final Date notBefore,
            final int notBeforeCondition, final Date notAfter, final int notAfterCondition, final int failedAction,
            final Integer... certificateProfileIds) {
        BaseKeyValidator result;
        if (RsaKeyValidator.KEY_VALIDATOR_TYPE == type) {
            result = new RsaKeyValidator();
        } else if (EccKeyValidator.KEY_VALIDATOR_TYPE == type) {
            result = new EccKeyValidator();
        } else if (PublicKeyBlacklistKeyValidator.KEY_VALIDATOR_TYPE == type) {
            result = new PublicKeyBlacklistKeyValidator();
        } else {
            return null;
        }
        result.setName(name);
        if (null != description) {
            result.setDescription(description);
        }
        if (null != notBefore) {
            result.setNotBefore(notBefore);
        }
        if (-1 < notBeforeCondition) {
            result.setNotBeforeCondition(notBeforeCondition);
        }
        if (null != notAfter) {
            result.setNotAfter(notAfter);
        }
        if (-1 < notAfterCondition) {
            result.setNotAfterCondition(notAfterCondition);
        }
        if (-1 < failedAction) {
            result.setFailedAction(failedAction);
        }
        final List<Integer> ids = new ArrayList<Integer>();
        for (Integer id : certificateProfileIds) {
            ids.add(id);
        }
        result.setCertificateProfileIds(ids);
        return result;
    }

    /**
     * Avoid instantiation.
     */
    private KeyValidatorTestUtil() {
    }
}
