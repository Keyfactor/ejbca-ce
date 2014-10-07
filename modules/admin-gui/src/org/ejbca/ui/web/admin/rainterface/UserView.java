/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.StringTools;

/**
 * A class representing a web interface view of a user in the ra user database.
 *
 * @version $Id$
 */
public class UserView implements Serializable, Comparable<UserView> {

    private static final long serialVersionUID = 2390294870669249774L;

    private SortBy sortby;
    private EndEntityInformation userdata;
    private DNFieldExtractor subjectdnfields;
    private DNFieldExtractor subjectaltnames;
    private DNFieldExtractor subjectdirattrs;
    private String commonname = "";
    private String caname;
    private boolean cleartextpwd;

    public UserView() {
        userdata = new EndEntityInformation();
        userdata.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        subjectdnfields = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDN);
        subjectaltnames = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTALTNAME);
        subjectdirattrs = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    }

    public UserView(EndEntityInformation newuserdata, Map<Integer, String> caidtonamemap) {
        userdata = newuserdata;
        this.caname = caidtonamemap.get(Integer.valueOf(newuserdata.getCAId()));
        subjectdnfields = new DNFieldExtractor(userdata.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
        subjectaltnames = new DNFieldExtractor(userdata.getSubjectAltName(), DNFieldExtractor.TYPE_SUBJECTALTNAME);
        String dirattrs = userdata.getExtendedinformation() != null ? userdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
        subjectdirattrs = new DNFieldExtractor(dirattrs, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
        setCommonName();

        cleartextpwd = userdata.getPassword() != null;
    }

    public void setUsername(String user) {
        userdata.setUsername(StringTools.stripUsername(user));
    }

    public String getUsername() {
        return userdata.getUsername();
    }

    public void setSubjectDN(String dn) {
        userdata.setDN(dn);
        subjectdnfields.setDN(dn, DNFieldExtractor.TYPE_SUBJECTDN);

        setCommonName();
    }

    public String getSubjectDN() {
        return userdata.getDN();
    }

    public void setSubjectAltName(String subjectaltname) {
        userdata.setSubjectAltName(subjectaltname);
        subjectaltnames.setDN(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    }

    public String getSubjectAltName() {
        return userdata.getSubjectAltName();
    }

    public void setSubjectDirAttributes(String subjectdirattr) {
        ExtendedInformation ext = userdata.getExtendedinformation();
        if (ext == null) {
            ext = new ExtendedInformation();
        }
        ext.setSubjectDirectoryAttributes(subjectdirattr);
        userdata.setExtendedinformation(ext);
        subjectdirattrs.setDN(subjectdirattr, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    }

    public String getSubjectDirAttributes() {
        return userdata.getExtendedinformation() != null ? userdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
    }

    public void setEmail(String email) {
        userdata.setEmail(email);
    }

    public String getEmail() {
        return userdata.getEmail();
    }

    public void setPassword(String pwd) {
        userdata.setPassword(pwd);
    }

    public String getPassword() {
        return userdata.getPassword();
    }

    public boolean getClearTextPassword() {
        return cleartextpwd;
    }

    public void setClearTextPassword(boolean cleartextpwd) {
        this.cleartextpwd = cleartextpwd;
    }

    public void setStatus(int status) {
        userdata.setStatus(status);
    }

    public int getStatus() {
        return userdata.getStatus();
    }

    public void setType(EndEntityType type) {
        userdata.setType(type);
    }

    public EndEntityType getType() {
        return userdata.getType();
    }

    public void setKeyRecoverable(boolean keyrecoverable) {
        userdata.setKeyRecoverable(keyrecoverable);
    }

    public boolean getKeyRecoverable() {
        return userdata.getKeyRecoverable();
    }

    public void setCardNumber(String cardNumber) {
        userdata.setCardNumber(cardNumber);
    }

    public String getCardNumber() {
        return userdata.getCardNumber();
    }

    public void setSendNotification(boolean sendnotification) {
        userdata.setSendNotification(sendnotification);
    }

    public boolean getSendNotification() {
        return userdata.getSendNotification();
    }

    public void setPrintUserData(boolean printUserData) {
        userdata.setPrintUserData(printUserData);
    }

    public boolean getPrintUserData() {
        return userdata.getPrintUserData();
    }

    public void setEndEntityProfileId(int profileid) {
        userdata.setEndEntityProfileId(profileid);
    }

    public int getEndEntityProfileId() {
        return userdata.getEndEntityProfileId();
    }

    public void setCertificateProfileId(int profileid) {
        userdata.setCertificateProfileId(profileid);
    }

    public int getCertificateProfileId() {
        return userdata.getCertificateProfileId();
    }

    public void setTimeCreated(Date timecreated) {
        userdata.setTimeCreated(timecreated);
    }

    public Date getTimeCreated() {
        return userdata.getTimeCreated();
    }

    public void setTimeModified(Date timemodified) {
        userdata.setTimeModified(timemodified);
    }

    public Date getTimeModified() {
        return userdata.getTimeModified();
    }

    public int getTokenType() {
        return userdata.getTokenType();
    }

    public void setTokenType(int tokentype) {
        userdata.setTokenType(tokentype);
    }

    public int getHardTokenIssuerId() {
        return userdata.getHardTokenIssuerId();
    }

    public void setHardTokenIssuerId(int hardtokenissuerid) {
        userdata.setHardTokenIssuerId(hardtokenissuerid);
    }

    public int getCAId() {
        return userdata.getCAId();
    }

    public void setCAId(int caid) {
        userdata.setCAId(caid);
    }

    public String getCAName() {
        return caname;
    }

    public void setExtendedInformation(ExtendedInformation extinfo) {
        userdata.setExtendedinformation(extinfo);
    }

    public ExtendedInformation getExtendedInformation() {
        return userdata.getExtendedinformation();
    }

    public String getSubjectDNField(int parameter, int number) {
        // We don't need to htmlescape the output, because we use JSTL output stuff in JSP pages that does it for us 
        // in the output shown in browser
        return subjectdnfields.getField(parameter, number);
    }

    public String getSubjectAltNameField(int parameter, int number) {
        return subjectaltnames.getField(parameter, number);
    }

    public String getSubjectDirAttributeField(int parameter, int number) {
        return subjectdirattrs.getField(parameter, number);
    }

    /**
     * getCommonName is a special function used in list end entity gui to display names in cases not a CN field exists in dn only, surname and givenname
     */
    public String getCommonName() {
        return commonname;
    }

    private void setCommonName() {
        commonname = getSubjectDNField(DNFieldExtractor.CN, 0);
        if (commonname.equals("")) {
            commonname = getSubjectDNField(DNFieldExtractor.GIVENNAME, 0) + " " + getSubjectDNField(DNFieldExtractor.SURNAME, 0);
        }
    }

    public int compareTo(UserView obj) {
        int returnvalue = -1;
        int sortby = this.sortby.getSortBy();
        switch (sortby) {
        case SortBy.USERNAME:
            returnvalue = getUsername().compareTo(obj.getUsername());
            break;
        case SortBy.COMMONNAME:
            returnvalue = this.commonname.compareTo(obj.getCommonName());
            break;
        case SortBy.DNSERIALNUMBER:
            returnvalue = getSubjectDNField(DNFieldExtractor.SN, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.SN, 0));
            break;
        case SortBy.TITLE:
            returnvalue = getSubjectDNField(DNFieldExtractor.T, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.T, 0));
            break;
        case SortBy.ORGANIZATIONALUNIT:
            returnvalue = getSubjectDNField(DNFieldExtractor.OU, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.OU, 0));
            break;
        case SortBy.ORGANIZATION:
            returnvalue = getSubjectDNField(DNFieldExtractor.O, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.O, 0));
            break;
        case SortBy.LOCALITY:
            returnvalue = getSubjectDNField(DNFieldExtractor.L, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.L, 0));
            break;
        case SortBy.STATEORPROVINCE:
            returnvalue = getSubjectDNField(DNFieldExtractor.ST, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.ST, 0));
            break;
        case SortBy.DOMAINCOMPONENT:
            returnvalue = getSubjectDNField(DNFieldExtractor.DC, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.DC, 0));
            break;
        case SortBy.COUNTRY:
            returnvalue = getSubjectDNField(DNFieldExtractor.C, 0).compareTo(obj.getSubjectDNField(DNFieldExtractor.C, 0));
            break;
        case SortBy.EMAIL:
            returnvalue = getEmail().compareTo(obj.getEmail());
            break;
        case SortBy.STATUS:
            returnvalue = (Integer.valueOf(getStatus())).compareTo(Integer.valueOf(obj.getStatus()));
            break;
        case SortBy.TIMECREATED:
            returnvalue = getTimeCreated().compareTo(obj.getTimeCreated());
            break;
        case SortBy.TIMEMODIFIED:
            returnvalue = getTimeModified().compareTo(obj.getTimeModified());
            break;
        case SortBy.CA:
            returnvalue = getCAName().compareTo(obj.getCAName());
            break;
        default:
            returnvalue = getUsername().compareTo(obj.getUsername());

        }
        if (this.sortby.getSortOrder() == SortBy.DECENDING) {
            returnvalue = 0 - returnvalue;
        }
        return returnvalue;
    }

    public void setSortBy(SortBy sortby) {
        this.sortby = sortby;
    }

}
