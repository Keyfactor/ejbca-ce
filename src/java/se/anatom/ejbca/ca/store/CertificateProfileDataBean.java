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

package se.anatom.ejbca.ca.store;

import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.ca.store.certificateprofiles.CACertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.EndUserCertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.RootCACertificateProfile;

import javax.ejb.CreateException;
import java.util.HashMap;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * certificate type in the ra web interface. Information stored:
 * <pre>
 *  id (Primary key)
 * CertificateProfile name
 * CertificateProfile data
 * </pre>
 *
 * @version $Id: ProfileDataBean.java,v 1.4 2002/07/22 10:38:48 anatom Exp $
 *
 * @ejb.bean description="This enterprise bean entity represents a CRL with accompanying data"
 * display-name="CertificateProfileDataEB"
 * name="CertificateProfileData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="CertificateProfileDataBean"
 * primkey-field="id"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.pk class="java.lang.Integer"
 * generate="false"
 *
 * @ejb.home local-extends="javax.ejb.EJBLocalHome"
 * local-class="se.anatom.ejbca.ca.store.CertificateProfileDataLocalHome"
 *
 * @ejb.interface local-extends="javax.ejb.EJBLocalObject"
 * local-class="se.anatom.ejbca.ca.store.CertificateProfileDataLocal"
 *
 * @ejb.finder description="findByCertificateProfileName"
 * signature="CRLDataLocal findByCertificateProfileName(java.lang.String name)"
 * query="SELECT DISTINCT OBJECT(a) from CertificateProfileDataBean a WHERE a.certificateProfileName=?1"
 *
 * @ejb.finder description="findAll"
 * signature="Collection findAll()"
 * query="SELECT DISTINCT OBJECT(a) from CertificateProfileDataBean AS a"
 *
 * @ejb.transaction
 *   type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class CertificateProfileDataBean extends BaseEntityBean {
    private static final Logger log = Logger.getLogger(CertificateProfileDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract Integer getId();

    /**
     * @ejb.persistence
     */
    public abstract void setId(Integer id);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getCertificateProfileName();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setCertificateProfileName(String certificateprofilename);

    /**
     * @ejb.persistence
     */
    public abstract HashMap getData();

    /**
     * @ejb.persistence
     */
    public abstract void setData(HashMap data);

    /**
     * Method that returns the certificate profiles and updates it if nessesary.
     *
     * @ejb.interface-method
     */
    public CertificateProfile getCertificateProfile() {
        CertificateProfile returnval = null;

        switch (((Integer) (((HashMap) getData()).get(CertificateProfile.TYPE))).intValue()) {
            case CertificateProfile.TYPE_ROOTCA:
                returnval = new RootCACertificateProfile();

                break;
            case CertificateProfile.TYPE_SUBCA:
                returnval = new CACertificateProfile();
                break;
            case CertificateProfile.TYPE_ENDENTITY:
            default :
                returnval = new EndUserCertificateProfile();
        }

        returnval.loadData((Object) getData());

        return returnval;
    }

    /**
     * Method that saves the certificate profile to database.
     *
     * @ejb.interface-method
     */
    public void setCertificateProfile(CertificateProfile profile) {
        setData((HashMap) profile.saveData());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of a raadmin profile.
     *
     * @param certificateprofilename DOCUMENT ME!
     * @param certificateprofilename
     * @param certificateprofile     is the CertificateProfile.
     * @ejb.create-method
     */
    public Integer ejbCreate(Integer id, String certificateprofilename,
                             CertificateProfile certificateprofile) throws CreateException {
        setId(id);
        setCertificateProfileName(certificateprofilename);
        setCertificateProfile(certificateprofile);
        log.debug("Created certificateprofile " + certificateprofilename);

        return id;
    }

    public void ejbPostCreate(Integer id, String certificateprofilename,
                              CertificateProfile certificateprofile) {
        // Do nothing. Required.
    }
}
