package se.anatom.ejbca.ra.authorization;

import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.util.CertTools;

import java.io.Serializable;

import java.security.cert.X509Certificate;

import java.util.regex.Pattern;


/**
 * A class representing a admin entity. It can be set to match one admins dn or an entire
 * organization by matching against o. The class main method is match() which takes a
 * X509Certificate and tries to see if it fullfills set matching requirements. Matchwith constants
 * points to which part of the certificate to match with. Matchtype constants tells under which
 * contitions the match shall be performed.
 *
 * @author Philip Vendil
 * @version $Id: AdminEntity.java,v 1.10 2003-06-26 11:43:24 anatom Exp $
 */
public class AdminEntity implements Serializable, Comparable {
    // Special Users. (Constants cannot have 0 value).
    public static final int SPECIALADMIN_PUBLICWEBUSER = 2000;
    public static final int SPECIALADMIN_CACOMMANDLINEADMIN = 2001;
    public static final int SPECIALADMIN_RACOMMANDLINEADMIN = 2002;
    public static final int SPECIALADMIN_BATCHCOMMANDLINEADMIN = 2003;
    public static final int SPECIALADMIN_INTERNALUSER = 2004;
    public static final int SPECIALADMIN_NOUSER = 2005;

    // Match type constants.
    public static final int TYPE_EQUALCASE = 1000;
    public static final int TYPE_EQUALCASEINS = 1001;
    public static final int TYPE_NOT_EQUALCASE = 1002;
    public static final int TYPE_NOT_EQUALCASEINS = 1003;

    // Match with constants.
    // OBSERVE These constants is also used as a priority indicator for access rules.
    // The higher values the higher priority.
    public static final int WITH_COUNTRY = 1;
    public static final int WITH_DOMAINCOMPONENT = 2;
    public static final int WITH_STATE = 3;
    public static final int WITH_LOCALE = 4;
    public static final int WITH_ORGANIZATION = 5;
    public static final int WITH_ORGANIZATIONUNIT = 6;
    public static final int WITH_TITLE = 7;
    public static final int WITH_COMMONNAME = 8;
    public static final int WITH_UID = 9;
    public static final int WITH_DNSERIALNUMBER = 10;
    public static final int WITH_SERIALNUMBER = 11;
    private static final Pattern serialPattern = Pattern.compile("\\bSERIALNUMBER=",
            Pattern.CASE_INSENSITIVE);

    /**
     * Creates a new instance of AdminEntity
     *
     * @param matchwith DOCUMENT ME!
     * @param matchtype DOCUMENT ME!
     * @param matchvalue DOCUMENT ME!
     */
    public AdminEntity(int matchwith, int matchtype, String matchvalue) {
        this.matchwith = matchwith;
        this.matchtype = matchtype;
        this.matchvalue = matchvalue;
    }

    /**
     * Creates a new AdminEntity object.
     *
     * @param specialadmin DOCUMENT ME!
     */
    public AdminEntity(int specialadmin) {
        this.matchtype = specialadmin;
        this.matchwith = WITH_SERIALNUMBER;
    }

    // Public methods.

    /**
     * Matches the given client X509Certificate to see if it matches it's requirements.
     *
     * @param admininformation DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean match(AdminInformation admininformation) {
        boolean returnvalue = false;

        if (admininformation.isSpecialUser()) {
            if (this.matchtype == admininformation.getSpecialUser()) {
                // There is a match of special admin return true;
                returnvalue = true;
            }
        } else {
            X509Certificate certificate = admininformation.getX509Certificate();
            String certstring = CertTools.getSubjectDN(certificate);

            //String serialnumber = certificate.getSerialNumber().toString(16);
            certstring = serialPattern.matcher(certstring).replaceAll("SN=");

            int parameter;
            int size = 0;
            String[] clientstrings = null;

            // Determine part of certificate to match with.
            DNFieldExtractor dn = new DNFieldExtractor(certstring, DNFieldExtractor.TYPE_SUBJECTDN);

            if (matchwith == WITH_SERIALNUMBER) {
                if (certificate != null) {
                    switch (matchtype) {
                    case TYPE_EQUALCASE:
                    case TYPE_EQUALCASEINS:

                        try {
                            returnvalue = (new java.math.BigInteger(matchvalue, 16)).equals(certificate.getSerialNumber());
                        } catch (java.lang.NumberFormatException nfe) {
                        }

                        break;

                    case TYPE_NOT_EQUALCASE:
                    case TYPE_NOT_EQUALCASEINS:

                        try {
                            returnvalue = !(new java.math.BigInteger(matchvalue, 16)).equals(certificate.getSerialNumber());
                        } catch (java.lang.NumberFormatException nfe) {
                        }

                        break;

                    default:}
                }
            } else {
                parameter = DNFieldExtractor.CN;

                switch (matchwith) {
                case WITH_COUNTRY:
                    parameter = DNFieldExtractor.C;

                    break;

                case WITH_DOMAINCOMPONENT:
                    parameter = DNFieldExtractor.DC;

                    break;

                case WITH_STATE:
                    parameter = DNFieldExtractor.L;

                    break;

                case WITH_LOCALE:
                    parameter = DNFieldExtractor.ST;

                    break;

                case WITH_ORGANIZATION:
                    parameter = DNFieldExtractor.O;

                    break;

                case WITH_ORGANIZATIONUNIT:
                    parameter = DNFieldExtractor.OU;

                    break;

                case WITH_TITLE:
                    parameter = DNFieldExtractor.T;

                    break;

                case WITH_DNSERIALNUMBER:
                    parameter = DNFieldExtractor.SN;

                    break;

                case WITH_COMMONNAME:
                    parameter = DNFieldExtractor.CN;

                    break;

                case WITH_UID:
                    parameter = DNFieldExtractor.UID;

                    break;

                default:}

                size = dn.getNumberOfFields(parameter);
                clientstrings = new String[size];

                for (int i = 0; i < size; i++) {
                    clientstrings[i] = dn.getField(parameter, i);
                }

                // Determine how to match.
                if (clientstrings != null) {
                    switch (matchtype) {
                    case TYPE_EQUALCASE:

                        for (int i = 0; i < size; i++) {
                            returnvalue = clientstrings[i].equals(matchvalue);

                            if (returnvalue) {
                                break;
                            }
                        }

                        break;

                    case TYPE_EQUALCASEINS:

                        for (int i = 0; i < size; i++) {
                            returnvalue = clientstrings[i].equalsIgnoreCase(matchvalue);

                            if (returnvalue) {
                                break;
                            }
                        }

                        break;

                    case TYPE_NOT_EQUALCASE:

                        for (int i = 0; i < size; i++) {
                            returnvalue = !clientstrings[i].equals(matchvalue);

                            if (returnvalue) {
                                break;
                            }
                        }

                        break;

                    case TYPE_NOT_EQUALCASEINS:

                        for (int i = 0; i < size; i++) {
                            returnvalue = !clientstrings[i].equalsIgnoreCase(matchvalue);

                            if (returnvalue) {
                                break;
                            }
                        }

                        break;

                    default:}
                }
            }
        }

        return returnvalue;
    }

    // Methods to get and set the individual variables.
    public int getMatchWith() {
        return matchwith;
    }

    /**
     * DOCUMENT ME!
     *
     * @param matchwith DOCUMENT ME!
     */
    public void setMatchWith(int matchwith) {
        this.matchwith = matchwith;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getMatchType() {
        return matchtype;
    }

    /**
     * DOCUMENT ME!
     *
     * @param matchtype DOCUMENT ME!
     */
    public void setMatchType(int matchtype) {
        this.matchtype = matchtype;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getMatchValue() {
        return matchvalue;
    }

    /**
     * DOCUMENT ME!
     *
     * @param matchvalue DOCUMENT ME!
     */
    public void setMatchValue(String matchvalue) {
        this.matchvalue = matchvalue;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getSpecialUser() {
        return this.matchtype;
    }

    /**
     * DOCUMENT ME!
     *
     * @param specialadmin DOCUMENT ME!
     */
    public void setSpecialUser(int specialadmin) {
        this.matchtype = specialadmin;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isSpecialUser() {
        return (this.matchtype >= 2000) && (this.matchtype <= 2999);
    }

    /**
     * Method used by the access tree to determine the priority. The priority is the same as match
     * with value.
     *
     * @return DOCUMENT ME!
     */
    public int getPriority() {
        return matchwith;
    }

    /**
     * DOCUMENT ME!
     *
     * @param obj DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int compareTo(Object obj) {
        return matchvalue.compareTo(((AdminEntity) obj).getMatchValue());
    }

    // Private methods.
    // Private fields.
    private int matchwith;
    private int matchtype;
    private String matchvalue;
}
