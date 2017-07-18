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
    private static String[] placeHolders = null;

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
                    log.error("Localization files not found");
                }
            }
            secondaryStream = InternalResources.class.getResourceAsStream(resLocation + secondaryLanguage + ".properties");
            if (secondaryStream == null) {
            	try {
            		secondaryStream = new FileInputStream(resLocation + secondaryLanguage + ".properties");
                } catch (FileNotFoundException e) {
                    log.error("Localization files not found");
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

    /** @return an instance of the InternalResources. */
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
     * found in any of the resource file "no text" is returned.
     * <br/><br/>
     * NOTE: String is immutable and you will get a copy of the String instead
     * of a reference to it. This is more memory consuming than using
     * getLocalizedMessageCs(..) if you pass on the result to Log4J.
     * @see #getLocalizedMessageCs(String, Object...)
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param params
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     * @return The message as a String, not trimmed for whitespace
     */
    public String getLocalizedMessage(final String key, final Object... params) {
        return getLocalizedMessageCs(key, params).toString();
    }

    /**
     * Method returning the localized message for the given resource key.
     * 
     * It first looks up in the primary language then in the secondary If not
     * found in any of the resource file "no text" is returned.
     * 
     * @param key
     *            is the key searched for in the resource files
     * @param params
     *            indicates the parameter that will be replaced by {X} in the
     *            language resource, a maximum of 10 parameters can be given.
     * 
     *            Ex Calling the method with key = TEST and param0 set to "hi"
     *            and the resource file have "TEST = messages is {0}" will
     *            result in the string "message is hi".
     * 
     * @return The message as a CharSequence, the return value is not trimmed for whitespace. 
     */
    protected CharSequence getLocalizedMessageCs(final String key, final Object... params) {
        final StringBuilder sb = new StringBuilder();
        return getLocalizedMessageInternal(sb, key, params);
    }

    /** Lookup the default string if the StringBuilder is empty. Perform place holder replacement processing. */
    protected CharSequence getLocalizedMessageInternal(final StringBuilder sb, final String key, final Object... params) {
        if (sb.length()==0) {
            if (primaryResource.containsKey(key)) {
                sb.append(primaryResource.getProperty(key));
            } else if (secondaryResource.containsKey(key)) {
                sb.append(secondaryResource.getProperty(key));
            } else {
                sb.append(key);
                for(Object param : params) {
                    if (param != null) {
                        sb.append(", ").append(param.toString());
                    }
                }
            }
        }
        replacePlaceholders(sb, params);
        if (log.isTraceEnabled()) {
            log.trace(key + "=" + sb.toString());
        }
        return sb;
    }
    
    public static void replacePlaceholders(final StringBuilder sb, final Object... params) {
        for (int i=0; i<params.length; i++) {
            replaceAll(sb, i, params[i]);
        }
        removeUnusedPlaceHolders(sb, params.length);
    }
    
    /** @return a lazily instantiated array of place holders like "{number}". */
    private static String[] getPlaceHolders() {
        if (placeHolders==null) {
            final String[] arr = new String[100];
            for (int i=0; i<arr.length; i++) {
                arr[i] = new StringBuilder('{').append(i).append('}').toString();
            }
            placeHolders = arr;
        }
        return placeHolders;
    }
    
    /** Replace any "{placeHolderIndex}" String that is present in the StringBuilder with 'replacementObject'. */
    private static void replaceAll(final StringBuilder sb, final int placeHolderIndex, final Object replacementObject) {
        if (sb==null) {
            log.error("No StringBuilder. Unable to create localized message.");
            return;
        }
        final String[] placeHolders = getPlaceHolders();
        if (placeHolderIndex<0 || placeHolderIndex>(placeHolders.length-1)) {
            log.error("Place holder index out of range. Unable to create localized message.");
            return;
        }
        final String placeHolder = placeHolders[placeHolderIndex];
        final int placeHolderLength = placeHolder.length();
        int currentIndex = -placeHolderLength;
        int bar = 20; // never allow more than 20 placeholders to avoid recursion
        if (replacementObject==null) {
            while ((currentIndex=sb.indexOf(placeHolder, currentIndex+placeHolderLength))!=-1 && bar > 0) {
                sb.delete(currentIndex-1, currentIndex+placeHolderLength);
                bar--;
            }
        } else {
            final String replacement = replacementObject.toString();
            while ((currentIndex=sb.indexOf(placeHolder, currentIndex+placeHolderLength))!=-1 && bar > 0) {
                sb.replace(currentIndex-1, currentIndex+placeHolderLength, replacement);
                bar--;
            }
        }
    }

    /** Remove any "{number}" string that is still present in the StringBuilder where number starts with 'startPlaceHolderIndex'. */
    private static void removeUnusedPlaceHolders(final StringBuilder sb, final int startPlaceHolderIndex) {
        final String[] placeHolders = getPlaceHolders();
        if (startPlaceHolderIndex<0 || startPlaceHolderIndex>(placeHolders.length-1)) {
            log.error("Place holder index out of range. Unable to create localized message.");
            return;
        }
        for (int i=startPlaceHolderIndex; i<placeHolders.length; i++) {
            final String placeHolder = placeHolders[i];
            final int placeHolderLength = placeHolder.length();
            int currentIndex = -placeHolderLength;
            boolean someThingRemoved = false;
            while ((currentIndex=sb.indexOf(placeHolder, currentIndex+placeHolderLength))!=-1) {
                sb.delete(currentIndex-1, currentIndex+placeHolderLength);
                someThingRemoved = true;
            }
            if (!someThingRemoved) {
                // If a place holder with the current number didn't exist, we assume that the ones with higher doesn't either..
                break;
            }
        }
    }
}
