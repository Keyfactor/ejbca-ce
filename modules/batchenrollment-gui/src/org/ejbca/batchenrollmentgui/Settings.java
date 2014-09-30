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
package org.ejbca.batchenrollmentgui;

import java.io.File;
import java.io.Serializable;

/**
 * Holds settings.
 *
 * @author markus
 * @version $Id$
 */
public class Settings implements Serializable {

    private static final long serialVersionUID = 2L;

    private String truststorePath;

    public Settings() {
        this.truststorePath = new File("truststore.pem").getAbsolutePath();
    }

    public Settings(final Settings settings) {
        this();
        this.truststorePath = settings.truststorePath;
    }

    public String getTruststorePath() {
        return truststorePath;
    }

    public void setTruststorePath(String truststorePath) {
        this.truststorePath = truststorePath;
    }

}
