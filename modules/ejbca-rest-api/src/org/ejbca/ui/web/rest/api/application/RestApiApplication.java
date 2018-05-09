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

package org.ejbca.ui.web.rest.api.application;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.ejbca.ui.web.rest.api.controllers.CaController;
import org.ejbca.ui.web.rest.api.controllers.CertificateController;

/**
 * EJBCA rest api application based on Easyrest
 *  
 * @version $Id$
 *
 */
public class RestApiApplication extends Application {

    private Set<Object> singletons = new HashSet<Object>();
    private Set<Class<?>> empty = new HashSet<Class<?>>();

    public RestApiApplication() {
        singletons.add(new CaController());
        singletons.add(new CertificateController());
    }

    @Override
    public Set<Class<?>> getClasses() {
        return empty;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }

}
