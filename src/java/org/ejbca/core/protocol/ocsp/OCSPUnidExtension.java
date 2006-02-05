package org.ejbca.core.protocol.ocsp;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Hashtable;

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;

/** OCSP extension used to map a UNID to a Fnr, OID for this extension is 2.16.578.1.16.3.2
 * 
 * @author tomas
 * @version $Id: OCSPUnidExtension.java,v 1.2 2006-02-05 17:13:52 anatom Exp $
 *
 */
public class OCSPUnidExtension implements IOCSPExtension {

    static private final Logger m_log = Logger.getLogger(OCSPUnidExtension.class);

    private String dataSourceJndi;
    private int errCode = OCSPUnidResponse.ERROR_NO_ERROR;
    
	/** Called after construction
	 * 
	 * @param config ServletConfig that can be used to read init-params from web-xml
	 */
	public void init(ServletConfig config) {
		// Datasource
		dataSourceJndi = config.getInitParameter("extensionDataSource");
	}
	
	/** Called by OCSP responder when the configured extension is found in the request.
	 * 
	 * @param request HttpServletRequest that can be used to find out information about caller, TLS certificate etc.
	 * @param cert X509Certificate the caller asked for in the OCSP request
	 * @return X509Extension that will be added to responseExtensions by OCSP responder, or null if an error occurs
	 */
	public Hashtable process(HttpServletRequest request, X509Certificate cert) {
        m_log.debug(">process()");
        // Check authorization first
        if (!checkAuthorization(request)) {
        	errCode = OCSPUnidResponse.ERROR_UNAUTHORIZED;
        	return null;
        }
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet result = null;
    	String fnr = null;
        try {
        	// The Unis is in the DN component serialNumber
        	String sn = CertTools.getPartFromDN(cert.getSubjectDN().getName(), "SN");
        	if (sn != null) {
        		m_log.debug("Found serialNumber: "+sn);
        		try {
        			con = ServiceLocator.getInstance().getDataSource(dataSourceJndi).getConnection();
        		} catch (SQLException e) {
        			m_log.error("Got SQL exception when looking up databasource for Unid-Fnr mapping: ", e);
        			errCode = OCSPUnidResponse.ERROR_SERVICE_UNAVAILABLE;
        			return null;
        		}
                ps = con.prepareStatement("select fnr from UnidFnrMapping where unid=?");
                ps.setString(1, sn);
                result = ps.executeQuery();
                if (result.next()) {
                    fnr = result.getString(1);
                }
        	} else {
        		m_log.error("Did not find a serialNumber in DN: "+cert.getSubjectDN().getName());
        		errCode = OCSPUnidResponse.ERROR_NO_SERIAL_IN_DN;
        		return null;
        	}
            m_log.debug("<process()");
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
        
        // Construct the response extentsion if we found a mapping
        if (fnr == null) {
        	errCode = OCSPUnidResponse.ERROR_NO_FNR_MAPPING;
        	return null;
        	
        }
        FnrFromUnidExtension ext = new FnrFromUnidExtension(fnr);
        Hashtable ret = new Hashtable();
        ret.put(FnrFromUnidExtension.FnrFromUnidOid, new X509Extension(false, new DEROctetString(ext)));
		return ret;
	}
	
	/** Returns the last error that occured during process(), when process returns null
	 * 
	 * @return error code as defined by implementing class
	 */
	public int getLastErrorCode() {
		return errCode;
	}
	
	// 
	// Private methods
	//
	boolean checkAuthorization(HttpServletRequest request) {
		// TODO:
		return true;
	}
}
