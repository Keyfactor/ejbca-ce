package se.anatom.ejbca.ra;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a User.
 * Information stored:
 * <pre>
 * Username (username)
 * SHA1 hash of password (passwordHash)
 * Clear text password if neede (clearPassword)
 * Subject DN (subjectDN)
 * Subject Email (subjectEmail)
 * Status (status)
 * Type (type, from SecConst)
 * </pre>
 *
 * Passwords should me manipulated through helper functions setPassword() and setOpenPassword().
 * The setPassword() function sets the hashed password, while the setOpenPassword() method sets
 * both the hashed password and the clear text password.
 * The method comparePassword() is used to verify a password againts the hashed password.
 *
 * @version $Id: UserDataBean.java,v 1.10 2002-06-27 11:00:25 anatom Exp $
 **/
public abstract class UserDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance( UserDataBean.class.getName() );

    protected EntityContext  ctx;

    public abstract String getUsername();
    public abstract void setUsername(String username);
    public abstract String getSubjectDN();
    public abstract void setSubjectDN(String subjectDN);
    public abstract String getSubjectEmail();
    public abstract void setSubjectEmail(String subjectEmail);
    public abstract int getStatus();
    public abstract void setStatus(int status);
    public abstract int getType();
    public abstract void setType(int type);
    /** Returns clear text password or null. */
    public abstract String getClearPassword();
    /** Sets clear text password, the preferred method is setOpenPassword().
     * @see setOpenPassword
     */
    public abstract void setClearPassword(String clearPassword);
    /** Returns hashed password or null. */
    public abstract String getPasswordHash();
    /** Sets hash of password, this is the normal way to store passwords, but use the method setPassword() instead.
     * @see setPassword
     */
    public abstract void setPasswordHash(String passwordHash);

    //
    // Public methods used to help us manage passwords
    //

    /** Sets password in ahsed form in the database, this way it cannot be read in clear form */
    public void setPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
    }
    /** Sets the password in clear form in the database, needed for machine processing,
     * also sets the hashed password to the same value
     */
    public void setOpenPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(password);
    }
    /** Verifies password by verifying against passwordhash
     */
    public boolean comparePassword(String password) throws NoSuchAlgorithmException {
        log.debug(">comparePassword()");
        if (password == null)
            return false;
        log.debug("<comparePassword()");
        //log.debug("Newhash="+makePasswordHash(password)+", OldHash="+passwordHash);
        return (makePasswordHash(password).equals(getPasswordHash()));
    }


    //
    // Helper functions
    //

    /** Creates the hashed password
    */
    private String makePasswordHash(String password) throws NoSuchAlgorithmException {
        log.debug(">makePasswordHash()");
        if (password == null)
            return null;
        String ret = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] pwdhash = md.digest(password.trim().getBytes());
            ret = Hex.encode(pwdhash);
        } catch (NoSuchAlgorithmException nsae) {
            log.error("SHA1 algorithm not supported.", nsae);
            throw nsae;
        }
        log.debug("<makePasswordHash()");
        return ret;
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a User.
     * Create by sending in the instance, username, password and subject DN.
     * SubjectEmail, Status and Type are set to default values (null, STATUS_NEW, USER_INVALID).
     * and should be set using the respective set-methods. Clear text password is not set at all and must be set using setClearPassword();
     *
     * @param username the unique username used for authentication.
     * @param password the password used for authentication. This inly sets passwordhash, to set cleartext password, the setPassword() method must be used.
     * @param dn the DN the subject is given in his certificate.
     * @return UserDataPK primary key
     *
     **/
    public UserDataPK ejbCreate(String username, String password, String dn) throws CreateException, NoSuchAlgorithmException {

        setUsername(username);
        setClearPassword(null);
        setPasswordHash(makePasswordHash(password));
        setSubjectDN(CertTools.stringToBCDNString(dn));
        setSubjectEmail(null);
        setStatus(UserData.STATUS_NEW);
        setType(SecConst.USER_INVALID);

        UserDataPK pk = new UserDataPK(username);
        log.debug("Created user "+username);
        return pk;
    }
    public void ejbPostCreate(String username, String password, String dn) {
        // Do nothing. Required.
    }
    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }
    public void unsetEntityContext() {
        this.ctx = null;
    }
    public void ejbActivate() {
        // Not implemented.
    }
    public void ejbPassivate() {
        // Not implemented.
    }
    public void ejbLoad() {
        // Not implemented.
    }
    public void ejbStore() {
        // Not implemented.
    }
    public void ejbRemove() {
        // Not implemented.
    }
}
