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

import java.io.IOException;

import org.apache.log4j.Logger;
import org.jdesktop.application.Application;
import org.jdesktop.application.SingleFrameApplication;

/**
 * The main class of the application.
 *
 * @author markus
 * @version $Id$
 */
public class BatchEnrollmentGUIApp extends SingleFrameApplication {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BatchEnrollmentGUIApp.class);

    private static final String SETTINGS_FILENAME = "settings";
    
    private Settings settings;

    /**
     * At startup create and show the main frame of the application.
     */
    @Override protected void startup() {
        show(new BatchEnrollmentGUIView(this));
    }

    /**
     * This method is to initialize the specified window by injecting resources.
     * Windows shown in our application come fully initialized from the GUI
     * builder, so this additional configuration is not needed.
     */
    @Override protected void configureWindow(java.awt.Window root) {
    }

    /**
     * A convenient static getter for the application instance.
     * @return the instance of DSEnrollmentGUIApp
     */
    public static BatchEnrollmentGUIApp getApplication() {
        return Application.getInstance(BatchEnrollmentGUIApp.class);
    }

    /**
     * Main method launching the application.
     */
    public static void main(String[] args) {
        launch(BatchEnrollmentGUIApp.class, args);
    }

    public Settings getSettings() {
        return settings;
    }

    public void setSettings(Settings settings) {
        this.settings = settings;
    }

    public void loadSettings() throws IOException {
        Object o = getContext().getLocalStorage().load(SETTINGS_FILENAME);
        if (o instanceof Settings) {
            settings = (Settings) o;
        } else {
            LOG.debug("No settings in file, using defaults.");
            settings = new Settings();
        }
    }

    public void saveSettings(final Settings settings) throws IOException {
        getContext().getLocalStorage().save(settings, SETTINGS_FILENAME);
        this.settings = settings;
    }

}
