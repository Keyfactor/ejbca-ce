package se.anatom.ejbca.ra;

import javax.ejb.EntityContext;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;


/**
 * Entity Bean representing a User.
 * Information stored:
 * <pre>
 * Username (username)
 * SHA1 hash of password (passwordhash)
 * Subject DN (subjectDN)
 * Subject Email (subjectEmail)
 * Status (status)
 * Type (type, from SecConst)
 * </pre>
 **/
public class UserDataBean implements javax.ejb.EntityBean {

    private static Category cat = Category.getInstance( UserDataBean.class.getName() );
    private EntityContext  ctx;

    public String username;
    public String password;
    public String passwordHash;
    public String subjectDN;
    public String subjectEmail;
    public int status;
    public int type;

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
    public UserDataPK ejbCreate(String username, String password, String dn) throws NoSuchAlgorithmException {

        this.username = username;
        this.password = null;
        this.passwordHash = makePasswordHash(password);
        this.subjectDN = CertTools.stringToBCDNString(dn);
        this.subjectEmail = null;
        this.status = UserData.STATUS_NEW;
        this.type = SecConst.USER_INVALID;

        UserDataPK pk = new UserDataPK();
        pk.username = username;
        cat.debug("Created user "+username);
        return pk;
    }
    public void ejbPostCreate(String username, String password, String dn) {
        // Do nothing. Required.
    }

    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    /** Verifies password by verifying agains passwordhash
    */
    public boolean comparePassword(String password) throws NoSuchAlgorithmException {
        cat.debug(">comparePassword()");
        if (password == null)
            return false;
        cat.debug("<comparePassword()");
        //System.out.println("Newhash="+makePasswordHash(password)+", OldHash="+passwordHash);
        return (makePasswordHash(password).equals(passwordHash));
    }
    /** Creates the hashed password
    */
    private String makePasswordHash(String password) throws NoSuchAlgorithmException {
        if (password == null)
            return null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] pwdhash = md.digest(password.trim().getBytes());
            return Hex.encode(pwdhash);
        } catch (NoSuchAlgorithmException nsae) {
            cat.error("SHA1 algorithm not supported.", nsae);
            throw nsae;
        }
    }
    /** Returns password or null.
     * NOTE: To set clear text password setClearPassword() must be used.
     */
    public String getPassword() {
        return password;
    }
    /** Sets passwordhash
    */
    public void setPassword(String password) throws NoSuchAlgorithmException {
        this.passwordHash = makePasswordHash(password);
    }
    /** Sets password AND passwordhash
    */
    public void setClearPassword(String password) throws NoSuchAlgorithmException {
        this.password = password;
        this.passwordHash = makePasswordHash(password);
    }
    public String getSubjectDN() {
        return subjectDN;
    }
    public void setSubjectDN(String dn) {
        subjectDN = CertTools.stringToBCDNString(dn);
    }
    public String getSubjectEmail() {
        return subjectEmail;
    }
    public void setSubjectEmail(String email) {
        this.subjectEmail = email;
    }
    public int getStatus() {
        return status;
    }
    public void setStatus(int st) {
        status = st;
    }
    public int getType() {
        return type;
    }
    public void setType(int t) {
        type = t;
    }
    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }
    public void unsetEntityContext() {
        this.ctx = null;
    }
    public EntityContext getEntityContext() {
        return this.ctx;
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
