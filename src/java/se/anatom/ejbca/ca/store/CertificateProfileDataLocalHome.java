package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

import se.anatom.ejbca.ca.store.certificateprofiles.*;

/**
 * For docs, see CertificateProfileDataBean
 *
 * @version $Id: CertificateProfileDataLocalHome.java,v 1.3 2002/07/22 10:38:48 herrvendil Exp $
 **/

public interface CertificateProfileDataLocalHome extends javax.ejb.EJBLocalHome {

    public CertificateProfileDataLocal create(Integer id, String certificateprofilename, CertificateProfile certificateprofile)
        throws CreateException;

    public CertificateProfileDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public CertificateProfileDataLocal findByCertificateProfileName(String name)
        throws FinderException;

    public Collection findAll()
        throws FinderException;
}

