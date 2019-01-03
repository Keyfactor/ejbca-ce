/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.io.File;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.StringTools;

/**
 * Class containing logic for a whitelist of scripts allowed to be executed by "External Command Validators".
 * @version $Id$
 */
public class ExternalScriptsWhitelist {
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalScriptsWhitelist.class);

    private final List<File> scripts;
    private final boolean isEnabled;

    /**
     * Creates a whitelist which permits all external commands to be executed.
     * @return a new empty whitelist marked as disabled
     */
    public static ExternalScriptsWhitelist permitAll() {
        return new ExternalScriptsWhitelist(new ArrayList<File>(), false);
    }

    /**
     * Create a new whitelist from text. The input should contain one path per line, lines beginning
     * with '#' are treated as comments.
     * @param text an input string containing the content of the whitelist
     * @param isEnabled true if the whitelist is enabled
     * @return an External Scripts Whitelist object constructed from the input
     * @throws ParseException if the whitelist is enabled and one of paths does not point to a file
     */
    public static ExternalScriptsWhitelist fromText(final String text, final boolean isEnabled) {
        final List<File> scripts = new ArrayList<>();
        final String[] lines = StringTools.splitByNewlines(text);
        for (int i = 0; i < lines.length; i++) {
            final String path = lines[i].trim();
            if (path.startsWith("#") || StringUtils.isBlank(path)) {
                // This is a comment or blank line
                continue;
            }
            final File script = new File(path);
            scripts.add(script);
        }
        return new ExternalScriptsWhitelist(scripts, isEnabled);
    }

    /**
     * Create a new whitelist from text marked as enabled. The input should contain one path per line,
     * lines beginning with '#' are treated as comments.
     * @param text an input string containing the content of the whitelist
     * @return an External Scripts Whitelist object constructed from the input
     * @throws ParseException if one of paths does not point to a file
     */
    public static ExternalScriptsWhitelist fromText(final String text) {
        return ExternalScriptsWhitelist.fromText(text, true);
    }

    /**
     * Create a new whitelist permitting execution of the scripts given as input.
     * @param scripts a list of files
     * @param isEnabled true if the whitelist is enabled
     */
    public ExternalScriptsWhitelist(final List<File> scripts, final boolean isEnabled) {
        this.scripts = scripts;
        this.isEnabled = isEnabled;
    }

    /**
     * Create a new enabled whitelist permitting execution of the scripts given as input.
     * @param scripts a list of path strings
     */
    public ExternalScriptsWhitelist(final String... paths) {
        this.scripts = new ArrayList<File>();
        this.isEnabled = true;
        for (final String path : paths) {
            scripts.add(new File(path));
        }
    }

    /**
     * Performs validation on the scripts in this whitelist. After invoking this
     * method, validation will be performed on each script present in the whitelist.
     * The result of the validation is a validation message which contains
     * a human-readable description of the validation outcome or null if no problem
     * was detected.
     * @return a map with a script as key and a validation message as value
     */
    public Map<File, String> validateScripts() {
        final Map<File, String> result = new LinkedHashMap<>();
        for (final File script : scripts) {
            try {
                if (!script.isFile()) {
                    result.put(script, "This file does not exist or is not a file.");
                    continue;
                }
                if (!script.canRead()) {
                    result.put(script, "This file cannot be read.");
                    continue;
                }
                if (!script.canExecute()) {
                    result.put(script, "This file cannot be executed.");
                    continue;
                }
                result.put(script, null);
            } catch (final SecurityException e) {
                result.put(script, e.getMessage());
            }
        }
        return result;
    }

    /**
     * Get the paths to the scripts in this whitelist.
     * @return the paths to the scripts in this whitelist
     */
    public List<String> getScriptsPaths() {
        final List<String> paths = new ArrayList<String>();
        for (final File script : scripts) {
            paths.add(script.getPath());
        }
        return paths;
    }

    /**
     * Returns the number of entries in this whitelist.
     * @return the number of entries in this whitelist
     */
    public int size() {
        return scripts.size();
    }

    /**
     * Check the paths stored in this whitelist.
     * @return true if one or more paths are invalid
     */
    public boolean hasInvalidPaths() {
        for (final File script : scripts) {
            if (!script.isFile()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determine if the command given as argument, e.g. <code>/usr/bin/foo</code> is permitted according to
     * this whitelist.
     * @param command the command to check
     * @return true if the command is permitted according to this whitelist, false otherwise
     */
    public boolean isPermitted(final String command) {
        if (!isEnabled) {
            // All commands are permitted if the whitelist is disabled
            return true;
        }
        for (final String path : getScriptsPaths()) {
            if (log.isDebugEnabled()) {
                log.debug( "Compare command '" + command + "' with whitlisted path '" + path + "'.");
            }
            if (StringUtils.equals(command, path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the contents of this whitelist in a debug-friendly format.
     * @return a string containing the contents of this whitelist
     */
    @Override
    public String toString() {
        return "# Is this whitelist enabled? " + isEnabled + System.lineSeparator() +
                StringUtils.join(getScriptsPaths(), System.lineSeparator());
    }
}
