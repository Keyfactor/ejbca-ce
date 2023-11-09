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

package org.ejbca.ra;

import org.ejbca.ui.web.StaticResourceVersioning;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import java.io.Serializable;

/**
 * Utility bean that provides a version string for static resource (JavaScript, CSS file) cache control in RA Web.
 */
@Named
@ApplicationScoped
public class RaStaticResourceVersionBean implements Serializable {

    private static final long serialVersionUID = 1L;

    public String getVersion() {
        return StaticResourceVersioning.VERSION;
    }
}
