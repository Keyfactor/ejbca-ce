/*
 * Admin.java
 *
 * Created on den 25 august 2002, 10:02
 */
package se.anatom.ejbca.log;

import java.security.cert.X509Certificate;

import se.anatom.ejbca.ra.authorization.AdminEntity;
import se.anatom.ejbca.ra.authorization.AdminInformation;


/**
 * This is a class containing information about the administrator or admin preforming the event.
 * Data contained in the class is preferbly
 *
 * @author TomSelleck
 */
public class Admin implements java.io.Serializable {
    // Public Constants
    // Indicates the type of administrator.
    public static final int TYPE_CLIENTCERT_USER = 0;
    public static final int TYPE_PUBLIC_WEB_USER = 1;
    public static final int TYPE_RACOMMANDLINE_USER = 2;
    public static final int TYPE_CACOMMANDLINE_USER = 3;
    public static final int TYPE_BATCHCOMMANDLINE_USER = 4;
    public static final int TYPE_INTERNALUSER = 5;
    public static final int SPECIAL_ADMIN_BOUNDRARY = 100;
    public static final String[] ADMINTYPETEXTS = {
        "CLIENTCERT", "PUBLICWEBUSER", "RACMDLINE", "CACMDLINE", "BATCHCMDLINE", "INTERNALUSER"
    };
    private int[] ADMINTYPETOADMINENTIRY = {
        0, AdminEntity.SPECIALADMIN_PUBLICWEBUSER, AdminEntity.SPECIALADMIN_CACOMMANDLINEADMIN,
        AdminEntity.SPECIALADMIN_RACOMMANDLINEADMIN, AdminEntity.SPECIALADMIN_BATCHCOMMANDLINEADMIN,
        AdminEntity.SPECIALADMIN_INTERNALUSER
    };

    // Public Constructors
    public Admin(X509Certificate certificate) {
        this.type = TYPE_CLIENTCERT_USER;
        this.data = certificate.getSerialNumber().toString(16);
        this.certificate = certificate;
    }

    /**
     * Creates a new Admin object.
     *
     * @param type DOCUMENT ME!
     * @param ip DOCUMENT ME!
     */
    public Admin(int type, String ip) {
        this.type = type;
        this.data = ip;
    }

    /**
     * Creates a new Admin object.
     *
     * @param type DOCUMENT ME!
     */
    public Admin(int type) {
        this.type = type;
        this.data = null;
    }

    // Public Methods
    public int getAdminType() {
        return this.type;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAdminData() {
        return this.data;
    }

    // Method that takes the internal data and returns a AdminInformation object required by the Authorization module.
    public AdminInformation getAdminInformation() {
        if (type == TYPE_CLIENTCERT_USER) {
            return new AdminInformation(certificate);
        }

        return new AdminInformation(ADMINTYPETOADMINENTIRY[type]);
    }

    // Private Methods
    // Private fields
    private int type = 0;
    private String data = null;
    private X509Certificate certificate = null;
}
