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
package org.ejbca.core.model;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;

/**
 * Class managing internal localization of texts such as notification messages
 * and log comments.
 * 
 * If fetched the resource files from the src/intresources directory and is
 * included in the file ejbca-properties.jar
 * 
 * @version $Id$
 */
public class InternalEjbcaResources extends InternalResources {

    private static final Logger log = Logger.getLogger(InternalEjbcaResources.class);

    /**
     * Determines if a de-serialized file is compatible with this class.
     * 
     * Maintainers must change this value if and only if the new version of this
     * class is not compatible with old versions. See Sun docs for <a
     * href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     * 
     */
    private static final long serialVersionUID = -1001L;

    public static final String PREFEREDINTERNALRESOURCES = CesecoreConfiguration.getInternalResourcesPreferredLanguage();
    public static final String SECONDARYINTERNALRESOURCES = CesecoreConfiguration.getInternalResourcesSecondaryLanguage();

    protected static InternalEjbcaResources instance = null;

    protected Properties primaryEjbcaResource = new Properties();
    protected Properties secondaryEjbcaResource = new Properties();

    private static final String RESOURCE_PATH = "/intresources";
    private static final String RESOURCE_NAME = "/ejbcaresources.";
    private static final String RESOURCE_LOCATION = RESOURCE_PATH+RESOURCE_NAME;

    /**
     * Method used to setup the Internal Resource management.
     * 
     * @param globalConfiguration
     *            used to retrieve the internal language of the application,
     *            configured in the System Configuration.
     * @throws IOException
     */
    protected InternalEjbcaResources() {
    	super();
        setupResources(RESOURCE_LOCATION);
    }

    protected InternalEjbcaResources(String resPath) {
    	super(resPath);
        setupResources(resPath+RESOURCE_NAME);
    }

    private void setupResources(String resLocation) {
        final String primaryLanguage = PREFEREDINTERNALRESOURCES.toLowerCase(Locale.ENGLISH);
        final String secondaryLanguage = SECONDARYINTERNALRESOURCES.toLowerCase(Locale.ENGLISH);
        // The test flag is defined when called from test code (junit)
        InputStream primaryStream = null;
        InputStream secondaryStream = null;
        try {
        	// We first check for presence of the file in the classpath, if it does not exist we also allow to have the
        	// the file in the filesystem
            primaryStream = InternalEjbcaResources.class.getResourceAsStream(resLocation + primaryLanguage + ".properties");
            if (primaryStream == null) {
            	try {
            		primaryStream = new FileInputStream(resLocation + primaryLanguage + ".properties");
                } catch (FileNotFoundException e) {
                    log.error("Localization files not found in InternalEjbcaResources: " +e.getMessage());
                }
            }
            secondaryStream = InternalEjbcaResources.class.getResourceAsStream(resLocation + secondaryLanguage + ".properties");
            if (secondaryStream == null) {
            	try {
            		secondaryStream = new FileInputStream(resLocation + secondaryLanguage + ".properties");
                } catch (FileNotFoundException e) {
                    log.error("Localization files not found in InternalEjbcaResources: " +  e.getMessage());
                }
            }

            try {
                if (primaryStream != null) {
                    primaryEjbcaResource.load(primaryStream);
                } else {
                    log.error("primaryResourse == null");
                }
                if (secondaryStream != null) {
                    secondaryEjbcaResource.load(secondaryStream);
                } else {
                    log.error("secondaryResource == null");
                }
            } catch (IOException e) {
                log.error("Error reading internal resourcefile", e);
            }
        } finally {
            try {
                if (primaryStream != null) {
                    primaryStream.close();
                }
                if (secondaryStream != null) {
                    secondaryStream.close();
                }
            } catch (IOException e) {
                log.error("Error closing internal resources language streams: ", e);
            }
        }
    }

    /** @return an instance of the InternalEjbcaResources. */
    public static synchronized InternalEjbcaResources getInstance() {
        if (instance == null) {
            instance = new InternalEjbcaResources();
        }
        return instance;
    }

    @Override
    public String getLocalizedMessage(final String key, final Object... params) {
        return getLocalizedMessageCs(key, params).toString();
    }

    @Override
    protected CharSequence getLocalizedMessageCs(final String key, final Object... params) {
        final StringBuilder sb = new StringBuilder();
        if (primaryEjbcaResource.containsKey(key)) {
            sb.append(primaryEjbcaResource.getProperty(key));
        } else if (secondaryEjbcaResource.containsKey(key)) {
            sb.append(secondaryEjbcaResource.getProperty(key));
        }
        return getLocalizedMessageInternal(sb, key, params);
    }
}
