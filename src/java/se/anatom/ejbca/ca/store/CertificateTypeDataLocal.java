package se.anatom.ejbca.ca.store;
import java.rmi.RemoteException;

import se.anatom.ejbca.ca.store.certificatetypes.*;

/**
 * For docs, see CertificateTypeDataBean
 *
 * @version $Id: CertificateTypeLocal.java,v 1.3 2002/07/22 10:38:48 tomselleck Exp $
 **/

public interface CertificateTypeDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public String getCertificateTypeName();

    public void setCertificateTypeName(String certificatetypename);

    public CertificateType getCertificateType();

    public void setCertificateType(CertificateType certificatetype);
}

