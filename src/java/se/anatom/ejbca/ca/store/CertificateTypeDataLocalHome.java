package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

import se.anatom.ejbca.ca.store.certificatetypes.*;

/**
 * For docs, see UserPreferencesDataBean
 *
 * @version $Id: ProfileDataLocalHome.java,v 1.3 2002/07/22 10:38:48 anatom Exp $
 **/

public interface CertificateTypeDataLocalHome extends javax.ejb.EJBLocalHome {

    public CertificateTypeDataLocal create(Integer id, String certificatetypename, CertificateType certificatetype)
        throws CreateException;

    public CertificateTypeDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public CertificateTypeDataLocal findByCertificateTypeName(String name)
        throws FinderException;

    public Collection findAll()
        throws FinderException;
}

