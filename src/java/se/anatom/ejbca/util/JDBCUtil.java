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
 
package se.anatom.ejbca.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;


/**
 * @version $Id: JDBCUtil.java,v 1.3 2004-04-16 07:38:59 anatom Exp $
 */
public class JDBCUtil {

    public static void close(Connection con) {
        try {
            if (con != null) {
                con.close(); 
            }
        } catch (Exception ex) {
            // ignore
        }
    }

    public static void close(PreparedStatement ps) {
        try {
            if (ps != null) {
                ps.close(); 
            }
        } catch (Exception ex) {
            // ignore
        }
    }

    public static void close(ResultSet rs) {
        try {
            if (rs != null) {
                rs.close(); 
            }
        } catch (Exception ex) {
            // ignore
        }
    }
    
}
