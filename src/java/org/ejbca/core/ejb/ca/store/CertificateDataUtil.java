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

package org.ejbca.core.ejb.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.StringTools;

/** Common code between CertificateStoreSessionBean and CertificateStoreOnlyDataSessionBean
 * 
 * @author lars
 * @version $Id: CertificateDataUtil.java,v 1.7 2006-07-18 16:49:43 anatom Exp $
 *
 */
public class CertificateDataUtil {
    public interface Adapter {
        void debug( String s );
        Logger getLogger();
        void log(Admin admin, int caid, int module, Date time, String username,
                 X509Certificate certificate, int event, String comment);
    }
    public static Certificate findCertificateByFingerprint(Admin admin, String fingerprint,
                                                           CertificateDataLocalHome certHome,
                                                           Adapter adapter) {
        adapter.debug(">findCertificateByFingerprint()");
        Certificate ret = null;

        try {
            CertificateDataLocal res = certHome.findByPrimaryKey(new CertificateDataPK(fingerprint));
            ret = res.getCertificate();
            adapter.debug("<findCertificateByFingerprint()");
        } catch (FinderException fe) {
            // Return null;
        } catch (Exception e) {
            adapter.getLogger().error("Error finding certificate with fp: " + fingerprint);
            throw new EJBException(e);
        }
        return ret;
    } // findCertificateByFingerprint

    public static Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno, CertificateDataLocalHome certHome, Adapter adapter) {
        if (adapter.getLogger().isDebugEnabled()) {
        	adapter.debug(">findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno);
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        dn = StringTools.strip(dn);
        if (adapter.getLogger().isDebugEnabled()) {
        	adapter.debug("Looking for cert with (transformed)DN: " + dn);
        }
        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            Certificate ret = null;
            if (coll != null) {
                if (coll.size() > 1)
                    adapter.log(admin, issuerDN.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_DATABASE, "Error in database, more than one certificate has the same Issuer : " + issuerDN + " and serialnumber "
                            + serno.toString(16) + ".");
                Iterator iter = coll.iterator();
                if (iter.hasNext()) {
                    ret = ((CertificateDataLocal) iter.next()).getCertificate();
                }
            }
            if (adapter.getLogger().isDebugEnabled()) {
            	adapter.debug("<findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno);
            }
            return ret;
        } catch (Exception fe) {
            throw new EJBException(fe);
        }
    } //findCertificateByIssuerAndSerno

    public static Collection findCertificatesByType(Admin admin, int type, String issuerDN,
                                                    CertificateDataLocalHome certHome,
                                                    Adapter adapter) {
        adapter.debug(">findCertificatesByType()");
        if (null == admin
                || type <= 0
                || type > CertificateDataBean.CERTTYPE_SUBCA + CertificateDataBean.CERTTYPE_ENDENTITY + CertificateDataBean.CERTTYPE_ROOTCA) {
            throw new IllegalArgumentException();
        }
        StringBuffer ctypes = new StringBuffer();
        if ((type & CertificateDataBean.CERTTYPE_SUBCA) > 0) {
            ctypes.append(CertificateDataBean.CERTTYPE_SUBCA);
        }
        if ((type & CertificateDataBean.CERTTYPE_ENDENTITY) > 0) {
            if (ctypes.length() > 0) {
                ctypes.append(", ");
            }
            ctypes.append(CertificateDataBean.CERTTYPE_ENDENTITY);
        }
        if ((type & CertificateDataBean.CERTTYPE_ROOTCA) > 0) {
            if (ctypes.length() > 0) {
                ctypes.append(", ");
            }
            ctypes.append(CertificateDataBean.CERTTYPE_ROOTCA);
        }

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        try {
            ArrayList vect;
            // Status 20 = CertificateDataBean.CERT_ACTIVE
            StringBuffer stmt = new StringBuffer("SELECT DISTINCT fingerprint FROM CertificateData WHERE status = "+CertificateDataBean.CERT_ACTIVE+" AND ");
            stmt.append(" type IN (");
            stmt.append(ctypes.toString());
            stmt.append(')');
            if (null != issuerDN && issuerDN.length() > 0) {
                String dn = CertTools.stringToBCDNString(issuerDN);
                dn = StringTools.strip(dn);
                if (adapter.getLogger().isDebugEnabled()) {
                    adapter.debug("findCertificatesByType() : Looking for cert with (transformed)DN: " + dn);
                }
                stmt.append(" AND issuerDN = '");
                stmt.append(dn);
                stmt.append('\'');
            }
            if (adapter.getLogger().isDebugEnabled()) {
                adapter.debug("findCertificatesByType() : executing SQL statement\n"
                        + stmt.toString());
            }
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement(stmt.toString());
            result = ps.executeQuery();

            vect = new ArrayList();
            while (result.next()) {
                Certificate cert = findCertificateByFingerprint(admin, result.getString(1),
                                                                certHome, adapter);
                if (cert != null) {
                    vect.add(cert);
                }
            }

            adapter.debug("<findCertificatesByType()");
            return vect;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    } // findCertificatesByType

    static public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno,
                                            CertificateDataLocalHome certHome, Adapter adapter) {
        if (adapter.getLogger().isDebugEnabled()) {
            adapter.debug(">isRevoked(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);

        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            if (coll != null) {
                if (coll.size() > 1)
                    adapter.log(admin, issuerDN.hashCode(), LogEntry.MODULE_CA, new java.util.Date(),
                                null, null, LogEntry.EVENT_ERROR_DATABASE,
                                "Error in database, more than one certificate has the same Issuer : " +
                                issuerDN + " and serialnumber " + serno.toString(16) + ".");
                Iterator iter = coll.iterator();
                if (iter.hasNext()) {
                    RevokedCertInfo revinfo = null;
                    CertificateDataLocal data = (CertificateDataLocal) iter.next();
                    revinfo = new RevokedCertInfo(serno, new Date(data.getRevocationDate()), data.getRevocationReason());
                    // Make sure we have it as NOT revoked if it isn't
                    if (data.getStatus() != CertificateDataBean.CERT_REVOKED) {
                        revinfo.setReason(RevokedCertInfo.NOT_REVOKED);
                    }
                    if (adapter.getLogger().isDebugEnabled()) {
                    	adapter.debug("<isRevoked() returned " + ((data.getStatus() == CertificateDataBean.CERT_REVOKED) ? "yes" : "no"));
                    }
                    return revinfo;
                }
            }
            if (adapter.getLogger().isDebugEnabled()) {
            	adapter.debug("<isRevoked() did not find certificate with dn "+dn+" and serno "+serno.toString(16));
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        return null;
    } //isRevoked
}
