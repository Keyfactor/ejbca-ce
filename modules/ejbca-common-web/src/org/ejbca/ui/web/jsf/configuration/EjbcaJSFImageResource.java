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
package org.ejbca.ui.web.jsf.configuration;

import java.util.Map;

/**
 * Interface used to retrieve EJBCA image resources in JSF views
 *
 * Implements a Map used for retrieving resources.
 *
 * @version $Id: EjbcaJSFImageResourceImpl.java 31509 2019-02-15 12:30:22Z andrey_s_helmes $
 *
 * @see EjbcaWebBean#getImagefileInfix(String)
 */
public interface EjbcaJSFImageResource extends Map<String, String> {

}
