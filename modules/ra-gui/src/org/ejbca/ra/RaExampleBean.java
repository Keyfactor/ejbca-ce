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

import java.io.Serializable;
import java.util.Random;

import javax.annotation.PostConstruct;
import javax.faces.view.ViewScoped;
import javax.inject.Named;

/**
 * Example of JSF Managed Bean for backing a page. 
 * 
 * @version $Id$
 */
@Named
@ViewScoped
public class RaExampleBean implements Serializable {

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(RaExampleBean.class);


    @PostConstruct
    private void postContruct() { }

    @Deprecated
    public void throwException() throws Exception {
        throw new Exception("RaErrorBean.throwException " + new Random().nextInt(100));
    }
}
