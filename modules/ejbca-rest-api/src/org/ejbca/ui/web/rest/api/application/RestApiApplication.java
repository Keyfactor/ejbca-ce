/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.application;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.ejbca.ui.web.rest.api.controllers.CaController;
import org.ejbca.ui.web.rest.api.controllers.CertificateController;

/**
 * Ejbca rest api application based on Easyrest
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
