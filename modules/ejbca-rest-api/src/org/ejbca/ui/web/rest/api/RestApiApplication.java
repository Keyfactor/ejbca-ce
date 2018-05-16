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

package org.ejbca.ui.web.rest.api;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * EJBCA rest api application based on RESTEasy
 *  
 * @version $Id$
 *
 */
@ApplicationPath("/")
public class RestApiApplication extends Application {
    // Nothing here for now so RESTEasy takes care of registering end points automatically.
    // Later if manual control over some resources required those could be added here.
}
