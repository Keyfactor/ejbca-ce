package se.anatom.ejbca.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;


/**
 * @version $Id: JDBCUtil.java,v 1.2 2004-04-15 13:44:28 anatom Exp $
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
