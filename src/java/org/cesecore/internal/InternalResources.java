/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.internal;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Locale;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;

/**
 * Class managing internal localization of texts such as notification messages
 * and log comments.
 * 
 * If fetched the resource files from the src/intresources directory and is
 * included in the file cesecore-ejb.jar
 * 
 * Based on EJBCA version: 
 *      InternalResources.java 11076 2011-01-07 07:54:16Z anatom
 * CESeCore version:
 *      InternalResources.java 985 2011-08-10 13:19:09Z tomas
 * 
 * @version $Id$
 */
public class InternalResources implements Serializable {

    private static final Logger log = Logger.getLogger(InternalResources.class);

    /**
     * Determines if a de-serialized file is compatible with this class.
     * 
     * Maintainers must change this value if and only if the new version of this
     * class is not compatible with old versions. See Sun docs for <a
     * href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     * 
     */
    private static final long serialVersionUID = -1003L;

    protected static InternalResources instance = null;

    protected Properties primaryResource = new Properties();
    protected Properties secondaryResource = new Properties();

    private static final String RESOURCE_PATH = "/intresources";
    private static final String RESOURCE_NAME = "/intresources.";
    private static final String RESOURCE_LOCATION = RESOURCE_PATH+RESOURCE_NAME;

    /**
     * Method used to setup the Internal Resource management.
     * 
     * @param globalConfiguration
     *            used to retrieve the internal language of the application,
     *            configured in the System Configuration.
     * @throws IOException
     */
    protected InternalResources() {
        setupResources(RESOURCE_LOCATION);
    }

    protected InternalResources(String resPath) {
        setupResources(resPath+RESOURCE_NAME);
    }

    private void setupResources(String resLocation) {
        final String primaryLanguage = CesecoreConfiguration.getInternalResourcesPreferredLanguage().toLowerCase(Locale.ENGLISH);
        final String secondaryLanguage = CesecoreConfiguration.getInternalResourcesSecondaryLanguage().toLowerCase(Locale.ENGLISH);
        // The test flag is defined when called from test code (junit)
        InputStream primaryStream = null;
        InputStream secondaryStream = null;
        try {

            primaryStream = InternalResources.class.getResourceAsStream(resLocation + primaryLanguage + ".properties");
            if (primaryStream == null) {
            	try {
            		primaryStream = new FileInputStream(resLocation + primaryLanguage + ".properties");
                } catch (FileNotFoundException e) {
                    log.error("Localization files not found", e);
                }
            }
            secondaryStream = InternalResources.class.getResourceAsStream(resLocation + secondaryLanguage + ".properties");
            if (secondaryStream == null) {
            	try {
            		secondaryStream = new FileInputStream(resLocation + secondaryLanguage + ".properties");
                } catch (FileNotFoundException e) {
                    log.error("Localization files not found", e);
                }
            }

            try {
                if (primaryStream != null) {
                    primaryResource.load(primaryStream);
                } else {
                    log.warn("primaryResourse == null");
                }
                if (secondaryStream != null) {
                    secondaryResource.load(secondaryStream);
                } else {
                    log.warn("secondaryResource == null");
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

    /**
     * Metod that returs a instance of the InternalResources might be null if
     * load() haven't been called before this method.
     */
    public static synchronized InternalResources getInstance() {
        if (instance == null) {
            instance = new InternalResources();
        }
        return instance;
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "key" is returned.
     * 
     */
    public String getLocalizedMessage(final String key) {
    	final Object[] params = {};
        return getLocalizedMessage(key, params, 0);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0) {
    	final Object[] params = { param0 };
        return getLocalizedMessage(key, params, 1);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1) {
    	final Object[] params = { param0, param1 };
        return getLocalizedMessage(key, params, 2);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2) {
    	final Object[] params = { param0, param1, param2 };
        return getLocalizedMessage(key, params, 3);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2, final Object param3) {
    	final Object[] params = { param0, param1, param2, param3 };
        return getLocalizedMessage(key, params, 4);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2, final Object param3, final Object param4) {
    	final Object[] params = { param0, param1, param2, param3, param4 };
        return getLocalizedMessage(key, params, 5);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2, final Object param3, final Object param4, final Object param5) {
    	final Object[] params = { param0, param1, param2, param3, param4, param5 };
        return getLocalizedMessage(key, params, 6);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2, final Object param3, final Object param4, final Object param5, final Object param6) {
    	final Object[] params = { param0, param1, param2, param3, param4, param5, param6 };
        return getLocalizedMessage(key, params, 7);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2, final Object param3, final Object param4, final Object param5, final Object param6,
    		final Object param7) {
    	final Object[] params = { param0, param1, param2, param3, param4, param5, param6, param7 };
        return getLocalizedMessage(key, params, 8);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2, final Object param3, final Object param4, final Object param5, final Object param6,
    		final Object param7, final Object param8) {
    	final Object[] params = { param0, param1, param2, param3, param4, param5, param6, param7, param8 };
        return getLocalizedMessage(key, params, 9);
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param paramX
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(final String key, final Object param0, final Object param1, final Object param2, final Object param3, final Object param4, final Object param5, final Object param6,
    		final Object param7, final Object param8, final Object param9) {
    	final Object[] params = { param0, param1, param2, param3, param4, param5, param6, param7, param8, param9 };
        return getLocalizedMessage(key, params, 10);
    }

    /**
     * Method returning the message from the resource file for the given
     * resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "key" is returned.
     * 
     */
    protected String getMessageString(final String key) {
        String retval = primaryResource.getProperty(key);
        if (retval == null) {
            retval = secondaryResource.getProperty(key);
        }
        if (retval == null) {
            retval = key;
        }
        return retval.trim();
    }

    private String getLocalizedMessage(final String key, final Object[] params, final int numOfParams) {
        String localizedString = getMessageString(key);
        for (int i = 0; i < numOfParams; i++) {
        	final Object obj = params[i];
            String param = "";
            if (obj != null) {
                param = obj.toString();
            }
            try {
                localizedString = localizedString.replaceAll("\\{" + i + "\\}", param);
            } catch (IllegalArgumentException e) {
                // If "param" contains some specific things, regexp may fail
                // under some circumstances
                try {
                    localizedString = localizedString.replaceAll("\\{" + i + "\\}", e.getMessage());
                } catch (IllegalArgumentException e1) {
                    localizedString = localizedString.replaceAll("\\{" + i + "\\}", "IllegalArgumentException");
                }
            }
        }
        // Remove all remaining {} if any
        localizedString = localizedString.replaceAll("\\{\\d\\}", "");

        return localizedString;
    }
}
