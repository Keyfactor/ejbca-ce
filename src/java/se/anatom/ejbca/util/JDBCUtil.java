package se.anatom.ejbca.util;

import java.sql.Connection;
import java.sql.PreparedStatement;


/**
 * @version $Id: JDBCUtil.java,v 1.1 2004-04-12 16:16:21 anatom Exp $
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
}
