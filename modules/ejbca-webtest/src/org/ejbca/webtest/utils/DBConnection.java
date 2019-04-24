package org.ejbca.webtest.utils;

import java.sql.*;

public class DBConnection {

    private Connection conn = null;
    private static Statement stmt = null;
    private static PreparedStatement preparedStatement;
    private static CallableStatement callable;
    public DBConnection() {

    }

    /**
     * This method provides connection to any database.
     */
    public static DBConnection setupDB(String server, String instance, String userName, String password) {
        String connectionURL = "jdbc:mariadb://" + instance + "," + userName + ","
                + password + ";";

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            DBConnection dbConn = new DBConnection();
            dbConn.conn = DriverManager.getConnection("jdbc:mariadb://" + server + "/" + instance, userName, password);
            System.out.println("Database connection established successfully.");
            return dbConn;
        } catch (Exception e) {
            Exception ee = new Exception(e.getMessage() + " Full connection URL: '" + connectionURL + "'.");
            ee.setStackTrace(e.getStackTrace());
        }
        return null;
    }

    /**
     * This method provides connection to any database using
     * windows authentication.
     */
    public static DBConnection setupDB(String server, String instance) throws Exception {
        String connectionURL = "jdbc:mariadb://" + server + ";databaseName=" + instance + ";integratedSecurity=true;";
        Class.forName("org.mariadb.jdbc.Driver");
        try {
            DBConnection dbConn = new DBConnection();
            dbConn.conn = DriverManager.getConnection(connectionURL);
            return dbConn;
        } catch (Exception e) {
            Exception ee = new Exception(e.getMessage() + " Full connection URL: '" + connectionURL + "'.");
            ee.setStackTrace(e.getStackTrace());
            throw ee;
        }
    }


    /**
     * This method executes the given SQL statement, which returns a single ResultSet object.
     */
    public ResultSet executeQuery(String query) throws SQLException {
        stmt = conn.createStatement();
        ResultSet results = stmt.executeQuery(query);
        return results;
    }


    /**
     * Executes a database query that returns a single value (the first column value will be returned).
     */
    public Object query(String query) throws SQLException {
        ResultSet rs = executeQuery(query);
        if (!rs.next()) {
            return null;
        }
        return rs.getObject(1);

    }


    /**
     * This method executes the given SQL statement and indicates the form of the first result.
     */
    public boolean execute(String query) throws SQLException {
        stmt = conn.createStatement();
        boolean result = stmt.execute(query);
        return result;
    }


    /**
     * This method executes the given SQL statement, which may be an INSERT, UPDATE, or DELETE statement or an SQL statement that returns
     * nothing, such as an SQL DDL statement.
     */
    public int executeUpdate(String query) throws SQLException {
        stmt = conn.createStatement();
        int result = stmt.executeUpdate(query);
        return result;
    }


    /**
     * This method executes prepared statements and take parameters in the same order as are placeholders (?) which will be replaced in the
     * query.
     */
    public ResultSet executePreparedStatement(String query, Object... parameters) throws SQLException {
        preparedStatement = conn.prepareStatement(query);
        int index = 1;
        if (parameters != null) {
            for (Object object : parameters) {
                preparedStatement.setObject(index++, object);
            }
        }
        return preparedStatement.executeQuery();
    }

    /**
     * This only takes care of procedures without params and without return values
     */
    public void executeCallabeStmt(String st) throws Exception {
        callable = conn.prepareCall(st);
        callable.executeUpdate();
    }

    /**
     * This method is used to close the db connection.
     * query.
     */
    public void closeConnection() throws Exception {
        try {
            if (conn != null) {
                conn.close();
                conn = null;
            }
            if (stmt != null) {
                stmt.close();
            }
        } catch (Exception e) {
            throw new Exception(
                    "Cannot close database connections, has it been established. Check all execution properties and that the database servers is available. Original exception: "
                            + e.getMessage());
        }
    }



}
