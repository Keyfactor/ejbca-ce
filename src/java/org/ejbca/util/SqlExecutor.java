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
 
package org.ejbca.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;

/** Class to execute a file full of sql commands. Useful for running update scripts.
 * @version $Id$
 */
public class SqlExecutor {
    static Logger log = Logger.getLogger(SqlExecutor.class);

    private Connection con = null;
    private int commands = 0;
    private int errors = 0;
    private boolean continueOnSqlError = false;
    public Connection getConnection() {
        return this.con;
    }
    public void setContinueOnSqlError(boolean cont) {
        this.continueOnSqlError = cont;
    }
    public int getErrors() {
        return this.errors;
    }
    /** Creates a new SqlExecutor. Caller is responsible for releasing the connection
     * @param connection
     * @param continueOnSQLError
     */
    public SqlExecutor(Connection connection, boolean continueOnSQLError) {
    	if (log.isTraceEnabled()) {
            log.trace("> SqlExecutor(" + connection + "," + continueOnSQLError+ ")");
    	}
        con = connection;
//        try {
//            con.setAutoCommit(false);            
//        } catch (SQLException ignore) {}
        this.continueOnSqlError = continueOnSQLError;
        log.trace("< SqlExecutor()");
    }
    
    /** Runs a single sql update command
     * 
     * @param command the sql command to execute
     * @return the result returned from executeUpdate
     * @throws SQLException
     */
    public int runCommand(String command) throws SQLException {
    	if (log.isTraceEnabled()) {
            log.trace("> runCommand: " + command);
    	}
        int res = executeCommand(command);
        log.debug(++commands + " commands executed with " + errors + " errors");
        commands = 0;
        errors = 0;
        log.trace("< runCommand");
        return res;
    }
    public void runCommandFile(File file) throws SQLException, FileNotFoundException, IOException {
    	if (log.isTraceEnabled()) {
            log.trace("> runCommandFile: " + file.getPath());
    	}
        Reader rdr = new FileReader(file);
        runCommands(rdr);
        log.trace("< runCommandFile()");
    }
    
    /** Reads sql statements from the Reader object aqnd executes one statement at a time.
     * Statements can be on one or more lines and must be terminated by ';'
     * 
     * @param rdr Reader object to read commends from.
     * @throws SQLException thrown on sql errors if continueOnSqlError is set to false.
     * @throws IOException if the reader object is invalid.
     */
    public void runCommands(Reader rdr) throws SQLException, IOException {
        log.trace(">runCommands");
        BufferedReader br = new BufferedReader(rdr);
        Timestamp start = new Timestamp(System.currentTimeMillis());
        try {
            String temp;
            final StringBuilder strBuf = new StringBuilder();
            commands = 0;
            List<String> list = new LinkedList<String>();
            while ((temp = br.readLine()) != null) {
            	if (!temp.startsWith("#") && !temp.startsWith("--")) { // Don't include comments and SQL comments
            		list.add(temp);
            	}
                if (!temp.endsWith(";")) {
                    continue;
                }
            }
            Iterator<String> it = list.iterator();
            while (it.hasNext()) {
                temp = it.next();
                temp = temp.trim();
                if (temp.length() != 0) {
                    strBuf.append(temp);
                    if (temp.endsWith(";")) {
                        // end of command, remove the ';' and execute
                        char ch = ' ';
                        strBuf.setCharAt(strBuf.length() - 1, ch);
                        executeCommand(strBuf.toString());
                        commands++;
                        strBuf.setLength(0);
                    } else {
                        // continue to read the command
                        strBuf.append(" ");
                    }
                }
            }            
        } finally {
            if (br != null) { br.close(); }            
        }
        Timestamp stop = new Timestamp(System.currentTimeMillis());
        log.debug("Execution started: " + start.toString());
        log.debug("Execution stopped: " + stop.toString());
        log.debug(commands + " commands executed with " + errors + " errors");
        commands = 0;
        errors = 0;
        log.trace("<runCommands");
    }
    
    /** Executes an sql update. 
     * SQL INSERT, UPDATE or DELETE statement; or an SQL statement that returns nothing, such as a DDL statement. 
     * 
     * @param command String holding the SQL.
     * @return number of rows updates (returned by executeUpdate)
     * @throws SQLException
     */
    private int executeCommand(String sql) throws SQLException {
    	if (log.isTraceEnabled()) {
            log.trace("> executeCommand: " + sql);
    	}
        Statement stmt = null;
        int res = 0;
        try {
            stmt = con.createStatement();
            res = stmt.executeUpdate(sql);
        } catch (SQLException exception) {
            log.error("Exception: " + exception.getMessage() + ", sql: "+ sql);
            if (!this.continueOnSqlError) {
                throw exception;
            }
            errors++;
        } finally {
            if (stmt != null) {
                stmt.close();
            }            
        }
        log.trace("< executeCommand");
        return res;
    } // executeCommand
    
  /* commit and rollback commands not needed when running inside a session bean that handles transactions for us */
  /*  
  public void commit() throws SQLException {
        log.trace("> commit");
        if (con != null)
            con.commit();
        else {
            log.error("Connection == null vid commit()");
        }
        log.trace("< commit");
    }
    
    public void rollback() throws SQLException {
        log.trace("> rollback");
        if (con != null)
            con.rollback();
        else {
            log.error("Connection == null vid rollback()");
        }
        log.trace("< rollback");
    }
    */    
}
