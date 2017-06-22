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

package org.ejbca.core.model.ca.keys.validation;

import java.util.List;

/**
 * A key validator that implements this interface should expose the configurable properties in such a
 * way that an UI can parse it.
 * 
 * @version $Id$
 */
public interface CustomKeyValidatorUiSupport {

    /** @return A list of the publisher's properties in such a way that a UI can parse the information. */
    public List<CustomKeyValidatorProperty> getCustomUiPropertyList();
}
