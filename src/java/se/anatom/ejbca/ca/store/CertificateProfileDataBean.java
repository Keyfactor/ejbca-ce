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

import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.ca.store.certificateprofiles.*;


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
 */
public abstract class CertificateProfileDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(CertificateProfileDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public abstract void setId(Integer id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getCertificateProfileName();

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofilename DOCUMENT ME!
     */
    public abstract void setCertificateProfileName(String certificateprofilename);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract HashMap getData();

    /**
     * DOCUMENT ME!
     *
     * @param data DOCUMENT ME!
     */
    public abstract void setData(HashMap data);

    /**
     * Method that returns the certificate profiles and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile getCertificateProfile() {
        CertificateProfile returnval = null;

        switch (((Integer) (((HashMap) getData()).get(CertificateProfile.TYPE))).intValue()) {
        case CertificateProfile.TYPE_ROOTCA:
            returnval = new RootCACertificateProfile();

            break;
          case CertificateProfile.TYPE_SUBCA :
            returnval =  new CACertificateProfile();      
            break;  
          case CertificateProfile.TYPE_ENDENTITY  :
          default :
            returnval = new EndUserCertificateProfile();
        }

        returnval.loadData((Object) getData());

        return returnval;
    }

    /**
     * Method that saves the certificate profile to database.
     *
     * @param profile DOCUMENT ME!
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
     * @param certificateprofile is the CertificateProfile.
     *
     * @return null
     */
    public Integer ejbCreate(Integer id, String certificateprofilename,
        CertificateProfile certificateprofile) throws CreateException {
        setId(id);
        setCertificateProfileName(certificateprofilename);
        setCertificateProfile(certificateprofile);
        log.debug("Created certificateprofile " + certificateprofilename);

        return id;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     * @param certificateprofile DOCUMENT ME!
     */
    public void ejbPostCreate(Integer id, String certificateprofilename,
        CertificateProfile certificateprofile) {
        // Do nothing. Required.
    }
}
