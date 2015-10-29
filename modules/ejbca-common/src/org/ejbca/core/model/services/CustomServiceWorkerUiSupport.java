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
package org.ejbca.core.model.services;

import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Interface that a custom service worker can implement to help UI rendering.
 * 
 * @version $Id$
 */
public interface CustomServiceWorkerUiSupport {

    /**
     * List of configurable properties that the custom service worker supports.
     * Note that the implementing class can only rely on the provided arguments for generating the list.
     * 
     * @param authenticationToken The admin that is configuring the properties.
     * @param currentProperties The current stored version of the properties for this worker.
     * @param languageResource A language resource where translatable keys can be looked up.
     * @return A list of properties in a format an UI can render nicely.
     */
    List<CustomServiceWorkerProperty> getCustomUiPropertyList(AuthenticationToken authenticationToken, Properties currentProperties, Map<String, String> languageResource);
}
