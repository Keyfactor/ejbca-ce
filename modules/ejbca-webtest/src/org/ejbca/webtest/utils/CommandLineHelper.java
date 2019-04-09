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
package org.ejbca.webtest.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import org.apache.log4j.Logger;

/**
 * Helper class used for command line stuff. 
 * 
 * @version $Id$
 *
 */
public class CommandLineHelper {

    private static final Logger log = Logger.getLogger(CommandLineHelper.class);
    
    /**
     * Run the designated command line method.
     *
     * @param cmd command to run.
     * @return isSuccessful
     */
    public Boolean runCommand(final String cmd) {
        boolean isSuccessful = false;
        final String whichOS = System.getProperty("os.name");
        boolean isWindows = true;

        if (!whichOS.toLowerCase().startsWith("windows")) {
            isWindows = false;
        }

        Process process = null;
        try {
            if (isWindows) {
                process = Runtime.getRuntime()
                        .exec("cmd.exe " + cmd);
            } else {
                process = Runtime.getRuntime()
                        .exec(cmd);
            }
            StreamGobbler streamGobbler =
                    new StreamGobbler(process.getInputStream(), System.out::println);
            Executors.newSingleThreadExecutor().submit(streamGobbler);
            int exitCode = process.waitFor();
            log.info("Exit Code:  " + exitCode);
            
            if (exitCode == 0) {
                isSuccessful = true;
            }
            
        } catch (IOException | InterruptedException e) {
            log.info("Error happened while executing the command line", e);
        } 
        return isSuccessful;
    }

    private static class StreamGobbler implements Runnable {
        private InputStream inputStream;
        private Consumer<String> consumer;

        public StreamGobbler(InputStream inputStream, Consumer<String> consumer) {
            this.inputStream = inputStream;
            this.consumer = consumer;
        }

        @Override
        public void run() {
            new BufferedReader(new InputStreamReader(inputStream)).lines()
                    .forEach(consumer);
        }
    }

}
