package se.anatom.ejbca.webdist.rainterface;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.util.StringTools;

import java.util.Date;


/**
 * A class representing a web interface view of a user in the ra user database.
 *
 * @version $Id: UserView.java,v 1.14 2003-06-26 11:43:26 anatom Exp $
 */
public class UserView implements java.io.Serializable, Cloneable, Comparable {
    // Public constants.
    public UserView() {
        userdata = new UserAdminData();
        userdata.setType(1);
        subjectdnfields = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDN);
        subjectaltnames = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTALTNAME);
    }

    /**
     * Creates a new UserView object.
     *
     * @param newuserdata DOCUMENT ME!
     */
    public UserView(UserAdminData newuserdata) {
        userdata = newuserdata;

        subjectdnfields = new DNFieldExtractor(userdata.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
        subjectaltnames = new DNFieldExtractor(userdata.getSubjectAltName(),
                DNFieldExtractor.TYPE_SUBJECTALTNAME);
        setCommonName();

        cleartextpwd = userdata.getPassword() != null;
    }

    /**
     * DOCUMENT ME!
     *
     * @param user DOCUMENT ME!
     */
    public void setUsername(String user) {
        userdata.setUsername(StringTools.strip(user));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername() {
        return userdata.getUsername();
    }

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     */
    public void setSubjectDN(String dn) {
        userdata.setDN(dn);
        subjectdnfields.setDN(dn, DNFieldExtractor.TYPE_SUBJECTDN);

        setCommonName();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectDN() {
        return userdata.getDN();
    }

    /**
     * DOCUMENT ME!
     *
     * @param subjectaltname DOCUMENT ME!
     */
    public void setSubjectAltName(String subjectaltname) {
        userdata.setSubjectAltName(subjectaltname);
        subjectaltnames.setDN(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectAltName() {
        return userdata.getSubjectAltName();
    }

    /**
     * DOCUMENT ME!
     *
     * @param email DOCUMENT ME!
     */
    public void setEmail(String email) {
        userdata.setEmail(email);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getEmail() {
        return userdata.getEmail();
    }

    /**
     * DOCUMENT ME!
     *
     * @param pwd DOCUMENT ME!
     */
    public void setPassword(String pwd) {
        userdata.setPassword(pwd);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getPassword() {
        return userdata.getPassword();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getClearTextPassword() {
        return cleartextpwd;
    }

    /**
     * DOCUMENT ME!
     *
     * @param cleartextpwd DOCUMENT ME!
     */
    public void setClearTextPassword(boolean cleartextpwd) {
        this.cleartextpwd = cleartextpwd;
    }

    /**
     * DOCUMENT ME!
     *
     * @param status DOCUMENT ME!
     */
    public void setStatus(int status) {
        userdata.setStatus(status);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getStatus() {
        return userdata.getStatus();
    }

    /**
     * DOCUMENT ME!
     *
     * @param type DOCUMENT ME!
     */
    public void setType(int type) {
        userdata.setType(type);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getType() {
        return userdata.getType();
    }

    /**
     * DOCUMENT ME!
     *
     * @param admin DOCUMENT ME!
     */
    public void setAdministrator(boolean admin) {
        userdata.setAdministrator(admin);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getAdministrator() {
        return userdata.getAdministrator();
    }

    /**
     * DOCUMENT ME!
     *
     * @param keyrecoverable DOCUMENT ME!
     */
    public void setKeyRecoverable(boolean keyrecoverable) {
        userdata.setKeyRecoverable(keyrecoverable);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getKeyRecoverable() {
        return userdata.getKeyRecoverable();
    }

    /**
     * DOCUMENT ME!
     *
     * @param sendnotification DOCUMENT ME!
     */
    public void setSendNotification(boolean sendnotification) {
        userdata.setSendNotification(sendnotification);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getSendNotification() {
        return userdata.getSendNotification();
    }

    /**
     * DOCUMENT ME!
     *
     * @param profileid DOCUMENT ME!
     */
    public void setEndEntityProfileId(int profileid) {
        userdata.setEndEntityProfileId(profileid);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getEndEntityProfileId() {
        return userdata.getEndEntityProfileId();
    }

    /**
     * DOCUMENT ME!
     *
     * @param profileid DOCUMENT ME!
     */
    public void setCertificateProfileId(int profileid) {
        userdata.setCertificateProfileId(profileid);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getCertificateProfileId() {
        return userdata.getCertificateProfileId();
    }

    /**
     * DOCUMENT ME!
     *
     * @param timecreated DOCUMENT ME!
     */
    public void setTimeCreated(Date timecreated) {
        userdata.setTimeCreated(timecreated);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getTimeCreated() {
        return userdata.getTimeCreated();
    }

    /**
     * DOCUMENT ME!
     *
     * @param timemodified DOCUMENT ME!
     */
    public void setTimeModified(Date timemodified) {
        userdata.setTimeModified(timemodified);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getTimeModified() {
        return userdata.getTimeModified();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getTokenType() {
        return userdata.getTokenType();
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     */
    public void setTokenType(int tokentype) {
        userdata.setTokenType(tokentype);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getHardTokenIssuerId() {
        return userdata.getHardTokenIssuerId();
    }

    /**
     * DOCUMENT ME!
     *
     * @param hardtokenissuerid DOCUMENT ME!
     */
    public void setHardTokenIssuerId(int hardtokenissuerid) {
        userdata.setHardTokenIssuerId(hardtokenissuerid);
    }

    /**
     * DOCUMENT ME!
     *
     * @param parameter DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectDNField(int parameter, int number) {
        return subjectdnfields.getField(parameter, number);
    }

    /**
     * DOCUMENT ME!
     *
     * @param parameter DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectAltNameField(int parameter, int number) {
        return subjectaltnames.getField(parameter, number);
    }

    /**
     * getCommonName is a special function used in list end entity gui to display names in cases
     * not a CN field exists in dn only, surname and givennamn
     *
     * @return DOCUMENT ME!
     */
    public String getCommonName() {
        return commonname;
    }

    private void setCommonName() {
        commonname = getSubjectDNField(DNFieldExtractor.CN, 0);

        if (commonname.equals("")) {
            commonname = getSubjectDNField(DNFieldExtractor.GIVENNAME, 0) + " " +
                getSubjectDNField(DNFieldExtractor.SURNAME, 0);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param obj DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int compareTo(Object obj) {
        int returnvalue = -1;
        int sortby = this.sortby.getSortBy();

        switch (sortby) {
        case SortBy.USERNAME:
            returnvalue = getUsername().compareTo(((UserView) obj).getUsername());

            break;

        case SortBy.COMMONNAME:
            returnvalue = this.commonname.compareTo(((UserView) obj).getCommonName());

            break;

        case SortBy.SERIALNUMBER:
            returnvalue = getSubjectDNField(DNFieldExtractor.SN, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.SN, 0));

            break;

        case SortBy.TITLE:
            returnvalue = getSubjectDNField(DNFieldExtractor.T, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.T, 0));

            break;

        case SortBy.ORGANIZATIONUNIT:
            returnvalue = getSubjectDNField(DNFieldExtractor.OU, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.OU, 0));

            break;

        case SortBy.ORGANIZATION:
            returnvalue = getSubjectDNField(DNFieldExtractor.O, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.O, 0));

            break;

        case SortBy.LOCALE:
            returnvalue = getSubjectDNField(DNFieldExtractor.L, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.L, 0));

            break;

        case SortBy.STATE:
            returnvalue = getSubjectDNField(DNFieldExtractor.ST, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.ST, 0));

            break;

        case SortBy.DOMAINCOMPONENT:
            returnvalue = getSubjectDNField(DNFieldExtractor.DC, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.DC, 0));

            break;

        case SortBy.COUNTRY:
            returnvalue = getSubjectDNField(DNFieldExtractor.C, 0).compareTo(((UserView) obj).getSubjectDNField(
                        DNFieldExtractor.C, 0));

            break;

        case SortBy.EMAIL:
            returnvalue = getEmail().compareTo(((UserView) obj).getEmail());

            break;

        case SortBy.STATUS:
            returnvalue = (new Integer(getStatus())).compareTo(new Integer(
                        ((UserView) obj).getStatus()));

            break;

        case SortBy.TIMECREATED:
            returnvalue = getTimeCreated().compareTo(((UserView) obj).getTimeCreated());

            break;

        case SortBy.TIMEMODIFIED:
            returnvalue = getTimeModified().compareTo(((UserView) obj).getTimeModified());

            break;

        default:
            returnvalue = getUsername().compareTo(((UserView) obj).getUsername());
        }

        if (this.sortby.getSortOrder() == SortBy.DECENDING) {
            returnvalue = 0 - returnvalue;
        }

        return returnvalue;
    }

    /**
     * DOCUMENT ME!
     *
     * @param sortby DOCUMENT ME!
     */
    public void setSortBy(SortBy sortby) {
        this.sortby = sortby;
    }

    // Private constants.
    // Private methods.
    private SortBy sortby;
    private UserAdminData userdata;
    private DNFieldExtractor subjectdnfields;
    private DNFieldExtractor subjectaltnames;
    private String commonname = "";
    private boolean cleartextpwd;
}
