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

package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.model.SecConst;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.HTMLTools;

/**
 * A class representing a view of a CA Information view..
 */
public class CAInfoView implements Serializable, Cloneable {

	private static final long serialVersionUID = -5154282635821412670L;
    // Public constants.

   public static final int NAME                    = 0;
   public static final int SUBJECTDN               = 1;
   public static final int SUBJECTALTNAME          = 2;
   public static final int CATYPE                  = 3;

   private static final int SECTION_CA             = 4;

   public static final int EXPIRETIME              = 5;
   public static final int STATUS                  = 6;
   @Deprecated
   public static final int CATOKEN_STATUS          = 7;
   public static final int DESCRIPTION             = 8;

   private static final int SECTION_CRL            = 9;

   public static final int CRLPERIOD               = 10;
   public static final int CRLISSUEINTERVAL        = 11;
   public static final int CRLOVERLAPTIME          = 12;
   public static final int DELTACRLPERIOD          = 13;
   public static final int GENERATECRLUPONREVOCATION = 14;
   public static final int CRLPUBLISHERS           = 15;
   public static final int VALIDATORS              = 16;

   private static final int SECTION_SERVICE        = 17;

   public static final int OCSP                    = 18;

   /** A info text strings must contain:
    * CANAME, CERT_SUBJECTDN, EXT_ABBR_SUBJECTALTNAME, CATYPE, EXPIRES, STATUS, DESCRIPTION, CRL_CA_CRLPERIOD, CRL_CA_ISSUEINTERVAL, CRL_CA_OVERLAPTIME, CRL_CA_DELTACRLPERIOD, GENERATECRLUPONREVOCATION, PUBLISHERS, VALIDATORS
    * It must also have CADATA in position n° 4 (CA data)
    * It must also have CRLSPECIFICDATA in position n° 9 (CRL Specific Data)
    * It must also have SERVICES in position n° 16 (Services), if exists
    */
   public static String[] X509CA_CAINFODATATEXTS = {
           "CANAME",
           "CERT_SUBJECTDN",
           "EXT_ABBR_SUBJECTALTNAME",
           "CATYPE",
           "CADATA",               /* CA data */
           "EXPIRES",
           "STATUS",               /*"CATOKENSTATUS"*/
           "",
           "DESCRIPTION",
           "CRLSPECIFICDATA",      /* CRL Specific Data */
           "CRL_CA_CRLPERIOD",
           "CRL_CA_ISSUEINTERVAL",
           "CRL_CA_OVERLAPTIME",
           "CRL_CA_DELTACRLPERIOD",
           "CRL_CA_GENERATECRLUPONREVOCATION",
           "PUBLISHERS",
           "VALIDATORS",
           "SERVICES",             /* Services */
           "OCSPSERVICE"
   };

   public static String[] CVCCA_CAINFODATATEXTS = {
        "NAME",
        "CERT_SUBJECTDN",
        "",
        "CATYPE",
        "CADATA",           /* CA data */
        "EXPIRES",
        "STATUS",           /*"CATOKENSTATUS"*/
        "",
        "DESCRIPTION",
        "CRLSPECIFICDATA",  /* CRL Specific Data */
        "CRL_CA_CRLPERIOD",
        "CRL_CA_ISSUEINTERVAL",
        "CRL_CA_OVERLAPTIME",
        "CRL_CA_DELTACRLPERIOD",
        "CRL_CA_GENERATECRLUPONREVOCATION"
   };

   private String[] caInfoData = null;
   private String[] caInfoDataTexts = null;

   private final CAInfo cainfo;

   public CAInfoView(final CAInfo caInfo, final EjbcaWebBean ejbcaWebBean, final Map<Integer, String> publishersIdToNameMap, final Map<Integer, String> keyValidatorsIdToNameMap) {
      this.cainfo = caInfo;

      if (caInfo instanceof X509CAInfo) {
        buildCaInformation(caInfo, ejbcaWebBean);

        addX509CAInformation(caInfo, ejbcaWebBean, publishersIdToNameMap, keyValidatorsIdToNameMap);

        setupGeneralInfo(X509CA_CAINFODATATEXTS, caInfo, ejbcaWebBean);

        caInfoData[SUBJECTALTNAME] = HTMLTools.htmlescape(((X509CAInfo) caInfo).getSubjectAltName());

		caInfoData[CRLPUBLISHERS] = "";
        final Iterator<Integer> publisherIds = caInfo.getCRLPublishers().iterator();
        if(publisherIds.hasNext()) {
        	caInfoData[CRLPUBLISHERS] = publishersIdToNameMap.get(publisherIds.next());
        } else {
        	caInfoData[CRLPUBLISHERS] = ejbcaWebBean.getText("NONE");
        }
        while(publisherIds.hasNext()) {
			caInfoData[CRLPUBLISHERS] = caInfoData[CRLPUBLISHERS] + ", " + publishersIdToNameMap.get(publisherIds.next());
        }

        caInfoData[VALIDATORS] = StringUtils.EMPTY;

        final Iterator<Integer> keyValidatorIds = caInfo.getValidators().iterator();
        if(keyValidatorIds.hasNext()) {
            caInfoData[VALIDATORS] = keyValidatorsIdToNameMap.get(keyValidatorIds.next());
        } else {
            caInfoData[VALIDATORS] = ejbcaWebBean.getText("NONE");
        }
        while(keyValidatorIds.hasNext()) {
            caInfoData[VALIDATORS] = caInfoData[VALIDATORS] + ", " + keyValidatorsIdToNameMap.get(keyValidatorIds.next());
        }

		caInfoData[SECTION_SERVICE]          = "&nbsp;"; // Section row

      } else if (caInfo instanceof CVCCAInfo) {
          buildCaInformation(caInfo, ejbcaWebBean);
          setupGeneralInfo(CVCCA_CAINFODATATEXTS, caInfo, ejbcaWebBean);
      }
   }

	private void setupGeneralInfo(final String[] strings, final CAInfo cainfo, final EjbcaWebBean ejbcawebbean) {
		caInfoDataTexts = new String[strings.length];
        caInfoData = new String[strings.length];

		for(int i=0; i < strings.length; i++){
          if(strings[i].equals("")) {
              caInfoDataTexts[i]="&nbsp;";
          } else {
              caInfoDataTexts[i] = ejbcawebbean.getText(strings[i]);
          }
        }

        caInfoData[SUBJECTDN]  = HTMLTools.htmlescape(cainfo.getSubjectDN());
        caInfoData[NAME]       = HTMLTools.htmlescape(cainfo.getName());
        final int catype = cainfo.getCAType();
        if (catype == CAInfo.CATYPE_CVC) {
            caInfoData[CATYPE]     = ejbcawebbean.getText("CVCCA");
        } else {
            caInfoData[CATYPE]     = ejbcawebbean.getText("X509");
        }
        caInfoData[SECTION_CA]          = "&nbsp;"; // Section row
        if(cainfo.getExpireTime() == null) {
		  caInfoData[EXPIRETIME] = "";
        } else {
          caInfoData[EXPIRETIME] = ejbcawebbean.formatAsISO8601(cainfo.getExpireTime());
        }

        caInfoData[STATUS] = getStatus(cainfo, ejbcawebbean);

        caInfoData[DESCRIPTION] = HTMLTools.htmlescape(cainfo.getDescription());

        caInfoData[SECTION_CRL]          = "&nbsp;"; // Section row

        caInfoData[CRLPERIOD] = SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        caInfoData[CRLISSUEINTERVAL] = SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
        caInfoData[CRLOVERLAPTIME] = SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
        caInfoData[DELTACRLPERIOD] = SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        caInfoData[GENERATECRLUPONREVOCATION] = Boolean.toString(cainfo.isGenerateCrlUponRevocation());
	}

    private void buildCaInformation(final CAInfo cainfo, final EjbcaWebBean ejbcawebbean) {
        caGuiInfo = new CaGuiInfo();

        final String subjectDnText = ejbcawebbean.getText("CERT_SUBJECTDN");
        final String subjectDn = HTMLTools.htmlescape(cainfo.getSubjectDN());
        caGuiInfo.setSubjectDn(new CaInfoProperty(subjectDnText, subjectDn));

        final String caNameText = ejbcawebbean.getText("CANAME");
        final String caName = HTMLTools.htmlescape(cainfo.getName());
        caGuiInfo.setCaName(new CaInfoProperty(caNameText, caName));

        final String caTypeText = ejbcawebbean.getText("CATYPE");
        final int caType = cainfo.getCAType();
        final String caTypeValue;
        switch(caType) {
        case CAInfo.CATYPE_CVC:
            caTypeValue = ejbcawebbean.getText("CVCCA");
            break;
        case CAInfo.CATYPE_X509:
            caTypeValue = ejbcawebbean.getText("X509");
            break;
        case CAInfo.CATYPE_SSH:
            caTypeValue = "SSH";
            break;
        case CAInfo.CATYPE_CITS:
            caTypeValue = "ECA";
            break;
        default:
            caTypeValue = "";
            break;
        }
        caGuiInfo.setCaType(new CaInfoProperty(caTypeText, caTypeValue));

        final String expireTimeText = ejbcawebbean.getText("EXPIRES");
        final String expireTime = (cainfo.getExpireTime() == null) ? "" : ejbcawebbean.formatAsISO8601(cainfo.getExpireTime());
        caGuiInfo.setExpireTime(new CaInfoProperty(expireTimeText, expireTime));

        final String statusText = ejbcawebbean.getText("STATUS");
        final String caTokenStatus = getStatus(cainfo, ejbcawebbean);
        caGuiInfo.setStatus(new CaInfoProperty(statusText, caTokenStatus));

        final String descriptionText = ejbcawebbean.getText("DESCRIPTION");
        final String description = HTMLTools.htmlescape(cainfo.getDescription());
        caGuiInfo.setDescription(new CaInfoProperty(descriptionText, description));

        final String crlPeriodText = ejbcawebbean.getText("CRL_CA_CRLPERIOD");
        final String crlPeriod = SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        caGuiInfo.setCrlPeriod(new CaInfoProperty(crlPeriodText, crlPeriod));

        final String issueIntervalText = ejbcawebbean.getText("CRL_CA_ISSUEINTERVAL");
        final String issueInterval = SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
        caGuiInfo.setCrlIssueInterval(new CaInfoProperty(issueIntervalText, issueInterval));

        final String overlapTimeText = ejbcawebbean.getText("CRL_CA_OVERLAPTIME");
        final String overlapTime = SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
        caGuiInfo.setCrlOverlapTime(new CaInfoProperty(overlapTimeText, overlapTime));

        final String deltaCrlPeriodText = ejbcawebbean.getText("CRL_CA_DELTACRLPERIOD");
        final String deltaCrlPeriod = SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        caGuiInfo.setDeltaCrlPeriod(new CaInfoProperty(deltaCrlPeriodText, deltaCrlPeriod));
        
        final String generateCrlUponRevocationTest = ejbcawebbean.getText("CRL_CA_GENERATEUPONREVOCATION");
        final boolean generateCrlUponRevocation = cainfo.isGenerateCrlUponRevocation();
        caGuiInfo.setGenerateCrlUponRevocation(new CaInfoProperty(generateCrlUponRevocationTest, Boolean.toString(generateCrlUponRevocation)));
    }

    private void addX509CAInformation(final CAInfo cainfo, final EjbcaWebBean ejbcawebbean,
            final Map<Integer, String> publishersidtonamemap, final Map<Integer, String> keyValidatorsIdToNameMap) {
        final String alternativeNameText = ejbcawebbean.getText("EXT_ABBR_SUBJECTALTNAME");
        final String alternativeName = HTMLTools.htmlescape(((X509CAInfo) cainfo).getSubjectAltName());
        caGuiInfo.setAlternativeName(new CaInfoProperty(alternativeNameText, alternativeName));

        final String publishersText = ejbcawebbean.getText("PUBLISHERS");
        final String publishers = getPublishers(cainfo, ejbcawebbean, publishersidtonamemap);
        caGuiInfo.setCrlPublishers(new CaInfoProperty(publishersText, publishers));

        final String validatorsText = ejbcawebbean.getText("VALIDATORS");
        final String validators = getValidarors(cainfo, ejbcawebbean, keyValidatorsIdToNameMap);
        caGuiInfo.setValidators(new CaInfoProperty(validatorsText, validators));

        final String ocspText = ejbcawebbean.getText("OCSPSERVICE");
        final String ocsp = ((X509CAInfo)cainfo).getDefaultOCSPServiceLocator();
        caGuiInfo.setOcsp(new CaInfoProperty(ocspText, ocsp));
    }

    private String getValidarors(final CAInfo caInfo, final EjbcaWebBean ejbcaWebBean, final Map<Integer, String> keyValidatorsIdToNameMap) {
        String result;

        final Iterator<Integer> keyValidatorIds = caInfo.getValidators().iterator();
        if(keyValidatorIds.hasNext()) {
            result = keyValidatorsIdToNameMap.get(keyValidatorIds.next());
        } else {
            result = ejbcaWebBean.getText("NONE");
        }
        while(keyValidatorIds.hasNext()) {
            result += ", " + keyValidatorsIdToNameMap.get(keyValidatorIds.next());
        }
        return result;
    }

    private String getPublishers(final CAInfo caInfo, final EjbcaWebBean ejbcaWebBean, final Map<Integer, String> publishersIdToNameMap) {
        String result;
        final Iterator<Integer> publisherIds = caInfo.getCRLPublishers().iterator();

        if(publisherIds.hasNext()) {
            result = publishersIdToNameMap.get(publisherIds.next());
        } else {
            result = ejbcaWebBean.getText("NONE");
        }
        while(publisherIds.hasNext()) {
            result += ", " + publishersIdToNameMap.get(publisherIds.next());
        }
        return result;
    }

    private String getStatus(final CAInfo cainfo, final EjbcaWebBean ejbcawebbean) {
        switch(cainfo.getStatus()) {
            case CAConstants.CA_ACTIVE :
              return ejbcawebbean.getText("ACTIVE");
            case CAConstants.CA_EXPIRED :
              return ejbcawebbean.getText("EXPIRED");
            case CAConstants.CA_OFFLINE :
              return ejbcawebbean.getText("OFFLINE");
            case CAConstants.CA_REVOKED :
              return ejbcawebbean.getText("CAREVOKED") + "<br>&nbsp;&nbsp;" +
                    ejbcawebbean.getText("REASON") + " : <br>&nbsp;&nbsp;&nbsp;&nbsp;" +
                    ejbcawebbean.getText(SecConst.reasontexts[cainfo.getRevocationReason()]) + "<br>&nbsp;&nbsp;" +
                    ejbcawebbean.getText("CRL_ENTRY_REVOCATIONDATE") + "<br>&nbsp;&nbsp;&nbsp;&nbsp;" +
                    ejbcawebbean.formatAsISO8601(cainfo.getRevocationDate());
            case CAConstants.CA_WAITING_CERTIFICATE_RESPONSE :
              return ejbcawebbean.getText("WAITINGFORCERTRESPONSE");
            case CAConstants.CA_EXTERNAL :
              return ejbcawebbean.getText("EXTERNALCA");
        }
        return "";
    }

    private CaGuiInfo caGuiInfo;

    public CaGuiInfo getCaGuiInfo() {
        return caGuiInfo;
    }

    // TODO cleanup those getters later
    public String[] getCAInfoData(){ return caInfoData;}
    public String[] getCAInfoDataText(){ return caInfoDataTexts;}



    public CAInfo getCAInfo() { return cainfo;}
    public CAToken getCAToken() { return cainfo.getCAToken(); }
    public Collection<Certificate> getCertificateChain() { return cainfo.getCertificateChain(); }
}
