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
package org.ejbca.ui.cli.jdbc;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.ClientToolBox;

/**
 * JDBC Tool for executing a SQL script file.
 * 
 * Executes commands terminated with ';' in an SQL script file or command(s) specified directly as arguments.
 * 
 * Exit codes:
 *  0: All ok.
 *  1: Bad CLI arguments
 *  2: Error during connect/disconnect
 *  3: Error during statement execution
 *  4: A single SELECT query was provided, but it did not match any result.
 * 
 * @version $Id$
 */
public class JdbcTool extends ClientToolBox {

    private static final Logger log = Logger.getLogger(JdbcTool.class);

    @Override
    protected String getName() {
        return "jdbc";
    }

    @Override
    protected void execute(final String[] args) {
        String jdbcUrl = null;
        String username = null;
        String password = null;
        final LinkedList<String> linesInFile = new LinkedList<>();
        // Parse command line arguments (excluding the first)
        List<String> parametersReversed = Arrays.asList(Arrays.copyOfRange(args, 1, args.length));
        Collections.reverse(parametersReversed);
        String potentialValue = null;
        for (final String current : parametersReversed) {
            if (log.isDebugEnabled()) {
                log.debug("current: '" + current + "' potentialValue: '" + potentialValue + "'");
            }
            if (current.equals("--url")) {
                jdbcUrl = potentialValue;
                potentialValue = null;
            } else if (current.equals("--username")) {
                username = potentialValue;
                potentialValue = null;
            } else if (current.equals("--password")) {
                password = potentialValue;
                potentialValue = null;
            } else if (current.equals("--password-prompt")) {
                handleUnusedPotentialValue(potentialValue);
                potentialValue = null;
                final Console console = System.console();
                if (console==null) {
                    log.error("Console is not available. Unable to use '--password-prompt'.");
                } else {
                    console.printf("Enter database password: ");
                    password = String.valueOf(console.readPassword());
                }
            } else if (current.equals("--file")) {
                final String sqlFile = potentialValue;
                potentialValue = null;
                try {
                    linesInFile.addAll(Files.readAllLines(Paths.get(sqlFile), StandardCharsets.UTF_8));
                    log.info("Loading SQL script '" + sqlFile + "' with " + linesInFile.size() + " lines.");
                } catch (IOException e) {
                    log.error("Failed to load SQL script '" + sqlFile + "': " + e.getMessage());
                }
            } else if (current.equals("--execute")) {
                linesInFile.add(0, potentialValue);
                potentialValue = null;
            } else {
                handleUnusedPotentialValue(potentialValue);
                potentialValue = current;
            }
        }
        handleUnusedPotentialValue(potentialValue);
        // Run command instance
        int errorCode = 0;
        if (jdbcUrl!=null && username!=null && password!=null && !linesInFile.isEmpty()) {
            errorCode = new JdbcTool().run(jdbcUrl, username, password, linesInFile);
            log.info("Done.");
        } else {
            log.info("Usage: " + args[0] + " --url <jdbcUrl> --username <username> [--password <password> | --password-prompt] [--file <sqlFile> | --execute \"<SQL-statement>\"]");
            log.info("You need to ensure that a suitable JDBC 4.0+ driver is available in the path of ClientToolBox by linking it from the 'ext/' directory.");
            errorCode = 1;
        }
        System.exit(errorCode); // NOPMD, this is not a JEE component
    }
    
    private void handleUnusedPotentialValue(final String potentialValue) {
        if (potentialValue!=null) {
            log.warn("Unrecognized argument '" + potentialValue + "'.");
        }
    }

    private int run(final String jdbcUrl, final String username, final String password, final List<String> linesInFile) {
        try (final Connection connection = DriverManager.getConnection(jdbcUrl, username, password);) {
            connection.setAutoCommit(true);
            log.info("Connected.");
            final StringBuilder sb = new StringBuilder();
            for (final String lineInFile : linesInFile) {
                final String line = lineInFile.trim();
                // Skip lines that are comments or empty
                if (line.isEmpty() || line.startsWith("--") || line.startsWith("#")) {
                    continue;
                }
                sb.append(line);
                // Assume a multi-line statement if line does not end with the ';' character
                if (!line.endsWith(";")) {
                    sb.append(" ");
                    continue;
                }
                // Remove the statement ending character ';'
                sb.deleteCharAt(sb.length()-1);
                try {
                    try (final Statement statement = connection.createStatement();) {
                        final String sqlStatement = sb.toString();
                        if (sqlStatement.toUpperCase().startsWith("SELECT")) {
                            try (final ResultSet resultSet = statement.executeQuery(sb.toString());) {
                                final boolean hasResult = resultSet!=null && resultSet.next();
                                log.info("'" + sqlStatement + "' -> " + (hasResult ? "hit" : "miss"));
                                if (linesInFile.size()==1 && !hasResult) {
                                    // Return a non-zero error code for easy scripting if we do a single select with no match
                                    return 4;
                                }
                            }
                        } else {
                            final int rowCount = statement.executeUpdate(sb.toString());
                            log.info("'" + sqlStatement + "' -> " + rowCount);
                        }
                    }
                } catch (SQLException e) {
                    log.error(e.getMessage());
                    return 3;
                }
                sb.setLength(0);
            }
        } catch (SQLException e) {
            log.error(e.getMessage());
            return 2;
        }
        return 0;
    }
}
