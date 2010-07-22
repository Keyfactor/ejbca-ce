/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.io.Serializable;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Class managing internal localization of texts such as notification messages
 * and log comments.
 * 
 * If fetched the resource files from the src/intresources directory and is
 * included in the file ejbca-ejb.jar
 * 
 * @author Philip Vendil 2006 sep 24
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
    private static final long serialVersionUID = -1001L;

    public static final String PREFEREDINTERNALRESOURCES = EjbcaConfiguration.getInternalResourcesPreferredLanguage();
    public static final String SECONDARYINTERNALRESOURCES = EjbcaConfiguration.getInternalResourcesSecondaryLanguage();

    protected static InternalResources instance = null;

    protected Properties primaryResource = new Properties();
    protected Properties secondaryResource = new Properties();

    private static final String RESOURCE_LOCATION = "/intresources/intresources.";

    /**
     * Method used to setup the Internal Resource management.
     * 
     * @param globalConfiguration
     *            used to retrieve the internal language of the application,
     *            configured in the System Configuration.
     * @throws IOException
     */
    protected InternalResources() {
        setupResources();
    }

    private void setupResources() {
        String primaryLanguage = PREFEREDINTERNALRESOURCES.toLowerCase();
        String secondaryLanguage = SECONDARYINTERNALRESOURCES.toLowerCase();
        // The test flag is defined when called from test code (junit)
        InputStream primaryStream = null;
        InputStream secondaryStream = null;
        try {

            primaryStream = InternalResources.class.getResourceAsStream(RESOURCE_LOCATION + primaryLanguage + ".properties");
            secondaryStream = InternalResources.class.getResourceAsStream(RESOURCE_LOCATION + secondaryLanguage + ".properties");

            try {
                if (primaryStream != null) {
                    primaryResource.load(primaryStream);
                } else {
                    log.error("primaryResourse == null");
                }
                if (secondaryStream != null) {
                    secondaryResource.load(secondaryStream);
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
    public String getLocalizedMessage(String key) {
        Object[] params = {};
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0) {
        Object[] params = { param0 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1) {
        Object[] params = { param0, param1 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2) {
        Object[] params = { param0, param1, param2 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3) {
        Object[] params = { param0, param1, param2, param3 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4) {
        Object[] params = { param0, param1, param2, param3, param4 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5) {
        Object[] params = { param0, param1, param2, param3, param4, param5 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6) {
        Object[] params = { param0, param1, param2, param3, param4, param5, param6 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6,
            Object param7) {
        Object[] params = { param0, param1, param2, param3, param4, param5, param6, param7 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {1}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6,
            Object param7, Object param8) {
        Object[] params = { param0, param1, param2, param3, param4, param5, param6, param7, param8 };
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
     *            indicaties the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6,
            Object param7, Object param8, Object param9) {
        Object[] params = { param0, param1, param2, param3, param4, param5, param6, param7, param8, param9 };
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
    private String getMessageString(String key) {
        String retval = primaryResource.getProperty(key);
        if (retval == null) {
            retval = secondaryResource.getProperty(key);
        }
        if (retval == null) {
            retval = key;
        }
        return retval.trim();
    }

    private String getLocalizedMessage(String key, Object[] params, int numOfParams) {
        String localizedString = getMessageString(key);
        for (int i = 0; i < numOfParams; i++) {
            Object obj = params[i];
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
