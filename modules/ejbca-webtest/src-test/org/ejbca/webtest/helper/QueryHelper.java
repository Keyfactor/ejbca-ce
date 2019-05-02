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
package org.ejbca.webtest.helper;

/**
 * Helper class used to database level verifications
 *
 * @version $Id: QueryHelper.java 32091 2019-05-02 12:59:46Z margaret_d_thomas $
 *
 */
import org.ejbca.webtest.utils.DBConnection;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;

import java.sql.ResultSet;
import java.util.Map;

public class QueryHelper extends BaseHelper {

    public QueryHelper(final WebDriver webDriver) {
        super(webDriver);
    }


    /**
     * Assert CRL number in database in latest row is the same as in the UI
     *
     * @param db
     * @param dbName
     * @param caName
     */
    public void assertCrlNumberIncreased(Map db, String dbName, final String caName) {
        int crlNumberDB = 0;
        try {
            DBConnection conn = DBConnection.setupDB(db.get("host") + ":"
                            + db.get("port"),
                    dbName,
                    db.get("user").toString(),
                    db.get("password").toString());

            int crlNumber = new CaStructureHelper(webDriver).getCrlNumber(caName);
            ResultSet r = conn.executeQuery("select cRLNumber from CRLData where issuerDN = 'CN=" + caName + "' order by cRLNumber DESC;");
            r.next();
            crlNumberDB = Integer.valueOf(r.getString(1));

            Assert.assertEquals("Database value not equal to ui value for CRL", crlNumber, crlNumberDB);
            conn.closeConnection();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * On test conclusion, clean excess rows from database based on criteria
     *
     * @param db
     * @param dbName
     * @param tblName
     * @param whereCriteria
     */
    public void removeDatabaseRowsByColumnCriteria(Map db, String dbName, String tblName, String whereCriteria) {
        try {
            DBConnection conn = DBConnection.setupDB(db.get("host") + ":"
                            + db.get("port"),
                    dbName,
                    db.get("user").toString(),
                    db.get("password").toString());

            int i = conn.executeUpdate("delete from " + tblName + " where " + whereCriteria + ";");
            Assert.assertTrue("Error deleting from database", i > 0);
            conn.closeConnection();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Fetch certificate serial number from database
     *
     * @param db
     * @param dbName
     * @param username
     * @return
     */
    public String getCertificateSerialNumberByUsername(Map db, String dbName, String username) {
        try {
            DBConnection conn = DBConnection.setupDB(db.get("host") + ":"
                            + db.get("port"),
                    dbName,
                    db.get("user").toString(),
                    db.get("password").toString());

            ResultSet r = conn.executeQuery("select serialNumber from CertificateData where username = '" + username + "';");
            r.next();
            conn.closeConnection();
            return (r.getString("serialNumber"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
