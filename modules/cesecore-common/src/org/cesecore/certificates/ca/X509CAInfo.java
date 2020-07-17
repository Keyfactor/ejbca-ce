/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.IntRange;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;


/**
 * Holds non-sensitive information about a X509CA.
 *
 * @version $Id$
 */
public class X509CAInfo extends CAInfo {

    private static final Logger log = Logger.getLogger(X509CAInfo.class);
    
	private static final long serialVersionUID = 2L;
	private List<CertificatePolicy> policies;
	private boolean useauthoritykeyidentifier;
	private boolean authoritykeyidentifiercritical;
	private boolean usecrlnumber;
	private boolean crlnumbercritical;
	private String defaultcrldistpoint;
	private String defaultcrlissuer;
	private String defaultocsplocator;
	private String cadefinedfreshestcrl;
	private String subjectaltname;
	private boolean useUTF8PolicyText;
	private boolean usePrintableStringSubjectDN;
	private boolean useLdapDNOrder;
	private boolean useCrlDistributionPointOnCrl;
	private boolean crlDistributionPointOnCrlCritical;
	private String cmpRaAuthSecret = "";
	private List<String> authorityInformationAccess;
	private List<String> certificateAiaDefaultCaIssuerUri;
	private List<String> nameConstraintsPermitted;
	private List<String> nameConstraintsExcluded;
	private String externalCdp;
	private boolean nameChanged;
	private int caSerialNumberOctetSize;
	private boolean doPreProduceOcspResponses;
	private boolean doStoreOcspResponsesOnDemand;
	private boolean usePartitionedCrl;
	private int crlPartitions;
	private int suspendedCrlPartitions;
	private String requestPreProcessor;

    /**
     * This constructor can be used when creating a CA.
     * This constructor uses defaults for the fields that are not specified.
     */
    public static X509CAInfo getDefaultX509CAInfo(final String subjectdn, final String name, final int status,
            final int certificateProfileId, final String encodedValidity, int signedby, final Collection<Certificate> certificatechain, final CAToken catoken) {
        X509CAInfoBuilder caInfoBuilder = new X509CAInfoBuilder()
                .setSubjectDn(subjectdn)
                .setName(name)
                .setStatus(status)
                .setUpdateTime(new Date())
                .setSubjectAltName("")
                .setCertificateProfileId(certificateProfileId)
                .setDefaultCertProfileId(0)
                .setUseNoConflictCertificateData(false)
                .setEncodedValidity(encodedValidity)
                .setExpireTime(null)
                .setCaType(CAInfo.CATYPE_X509)
                .setSignedBy(signedby)
                .setCertificateChain(certificatechain)
                .setCaToken(catoken)
                .setDescription("")
                .setCaSerialNumberOctetSize(CesecoreConfiguration.getSerialNumberOctetSizeForNewCa())
                .setRevocationReason(-1)
                .setRevocationDate(null)
                .setPolicies(null)
                .setCrlPeriod(1 * SimpleTime.MILLISECONDS_PER_DAY)
                .setCrlIssueInterval(0L)
                .setCrlOverlapTime(10 * SimpleTime.MILLISECONDS_PER_MINUTE)
                .setDeltaCrlPeriod(0L)
                .setCrlPublishers(new ArrayList<>())
                .setValidators(new ArrayList<>())
                .setUseAuthorityKeyIdentifier(true)
                .setAuthorityKeyIdentifierCritical(false)
                .setUseCrlNumber(true)
                .setCrlNumberCritical(false)
                .setDefaultCrlDistPoint(null)
                .setDefaultCrlIssuer(null)
                .setDefaultOcspCerviceLocator(null)
                .setAuthorityInformationAccess(null)
                .setCertificateAiaDefaultCaIssuerUri(null)
                .setNameConstraintsPermitted(null).setNameConstraintsExcluded(null)
                .setCaDefinedFreshestCrl(null)
                .setFinishUser(true)
                .setExtendedCaServiceInfos(new ArrayList<>())
                .setUseUtf8PolicyText(false)
                .setApprovals(new HashMap<>())
                .setUsePrintableStringSubjectDN(false)
                .setUseLdapDnOrder(true)
                .setUseCrlDistributionPointOnCrl(false)
                .setCrlDistributionPointOnCrlCritical(false)
                .setIncludeInHealthCheck(true)
                .setDoEnforceUniquePublicKeys(true)
                .setDoEnforceKeyRenewal(false)
                .setDoEnforceUniqueDistinguishedName(true)
                .setDoEnforceUniqueSubjectDNSerialnumber(false)
                .setUseCertReqHistory(false)
                .setUseUserStorage(true)
                .setUseCertificateStorage(true)
                .setDoPreProduceOcspResponses(false)
                .setDoStoreOcspResponsesOnDemand(false)
                .setAcceptRevocationNonExistingEntry(false)
                .setCmpRaAuthSecret(null)
                .setKeepExpiredCertsOnCRL(false)
                .setUsePartitionedCrl(false)
                .setCrlPartitions(0)
                .setSuspendedCrlPartitions(0)
                .setRequestPreProcessor(null)
                ;
         return caInfoBuilder.build();
    }

    /** Constructor that should be used when updating CA data. */
    private X509CAInfo(final String encodedValidity, final CAToken catoken, final String description, final int caSerialNumberOctetSize,
                      final long crlperiod, final long crlIssueInterval, final long crlOverlapTime, final long deltacrlperiod, final Collection<Integer> crlpublishers,
                      final Collection<Integer> keyValidators, final boolean useauthoritykeyidentifier, final boolean authoritykeyidentifiercritical,
                      final boolean usecrlnumber, final boolean crlnumbercritical, final String defaultcrldistpoint, final String defaultcrlissuer,
                      final String defaultocspservicelocator, final List<String> crlAuthorityInformationAccess,
                      final List<String> certificateAiaDefaultCaIssuerUri, final List<String> nameConstraintsPermitted,
                      final List<String> nameConstraintsExcluded, final String cadefinedfreshestcrl, final boolean finishuser,
                      final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos, final boolean useUTF8PolicyText,
                      final Map<ApprovalRequestType, Integer> approvals, final boolean usePrintableStringSubjectDN, final boolean useLdapDnOrder,
                      final boolean useCrlDistributionPointOnCrl, final boolean crlDistributionPointOnCrlCritical, final boolean includeInHealthCheck,
                      final boolean doEnforceUniquePublicKeys, final boolean doEnforceKeyRenewal, final boolean doEnforceUniqueDistinguishedName,
                      final boolean doEnforceUniqueSubjectDNSerialnumber, final boolean useCertReqHistory, final boolean useUserStorage,
                      final boolean useCertificateStorage, final boolean doPreProduceOcspResponses, final boolean doStoreOcspResponsesOnDemand, final boolean acceptRevocationNonExistingEntry, 
                      final String cmpRaAuthSecret, final boolean keepExpiredCertsOnCRL, final int defaultCertprofileId, 
                      final boolean useNoConflictCertificateData, final boolean usePartitionedCrl, final int crlPartitions, final int suspendedCrlPartitions, final String requestPreProcessor) {
        this.encodedValidity = encodedValidity;
        this.catoken = catoken;
        this.description = description;
        this.caSerialNumberOctetSize = caSerialNumberOctetSize;
        this.crlperiod = crlperiod;
        this.crlIssueInterval = crlIssueInterval;
        this.crlOverlapTime = crlOverlapTime;
        this.deltacrlperiod = deltacrlperiod;
        this.crlpublishers = crlpublishers;
        this.validators = keyValidators;
        this.useauthoritykeyidentifier = useauthoritykeyidentifier;
        this.authoritykeyidentifiercritical = authoritykeyidentifiercritical;
        this.usecrlnumber = usecrlnumber;
        this.crlnumbercritical = crlnumbercritical;
        this.defaultcrldistpoint = defaultcrldistpoint;
        this.defaultcrlissuer = defaultcrlissuer;
        this.defaultocsplocator = defaultocspservicelocator;
        this.cadefinedfreshestcrl = cadefinedfreshestcrl;
        this.finishuser = finishuser;
        this.extendedcaserviceinfos = extendedcaserviceinfos;
        this.useUTF8PolicyText = useUTF8PolicyText;
        setApprovals(approvals);
        this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
        this.useLdapDNOrder = useLdapDnOrder;
        this.useCrlDistributionPointOnCrl = useCrlDistributionPointOnCrl;
        this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
        this.includeInHealthCheck = includeInHealthCheck;
        this.doEnforceUniquePublicKeys = doEnforceUniquePublicKeys;
        this.doEnforceKeyRenewal = doEnforceKeyRenewal;
        this.doEnforceUniqueDistinguishedName = doEnforceUniqueDistinguishedName;
        this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSerialnumber;
        this.useCertReqHistory = useCertReqHistory;
        this.useUserStorage = useUserStorage;
        this.useCertificateStorage = useCertificateStorage;
        this.doPreProduceOcspResponses = doPreProduceOcspResponses;
        this.doStoreOcspResponsesOnDemand = doStoreOcspResponsesOnDemand;
        this.acceptRevocationNonExistingEntry = acceptRevocationNonExistingEntry;
        setCmpRaAuthSecret(cmpRaAuthSecret);
        this.keepExpiredCertsOnCRL = keepExpiredCertsOnCRL;
        this.authorityInformationAccess = crlAuthorityInformationAccess;
        this.certificateAiaDefaultCaIssuerUri = certificateAiaDefaultCaIssuerUri;
        this.nameConstraintsPermitted = nameConstraintsPermitted;
        this.nameConstraintsExcluded = nameConstraintsExcluded;
        this.defaultCertificateProfileId = defaultCertprofileId;
        this.useNoConflictCertificateData = useNoConflictCertificateData;
        this.usePartitionedCrl = usePartitionedCrl;
        this.crlPartitions = crlPartitions;
        this.suspendedCrlPartitions = suspendedCrlPartitions;
        setRequestPreProcessor(requestPreProcessor);
    }

  public List<CertificatePolicy> getPolicies() {
	  return this.policies;
  }
  public void setPolicies(final List<CertificatePolicy> policies) {
      this.policies = policies;
  }
  public boolean getUseCRLNumber(){ return usecrlnumber;}
  public void setUseCRLNumber(boolean usecrlnumber){ this.usecrlnumber=usecrlnumber;}

  public boolean getCRLNumberCritical(){ return crlnumbercritical;}
  public void setCRLNumberCritical(boolean crlnumbercritical){ this.crlnumbercritical=crlnumbercritical;}

  public boolean getUseAuthorityKeyIdentifier(){ return useauthoritykeyidentifier;}
  public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) {this.useauthoritykeyidentifier=useauthoritykeyidentifier;}

  public boolean getAuthorityKeyIdentifierCritical(){ return authoritykeyidentifiercritical;}
  public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical)
                {this.authoritykeyidentifiercritical=authoritykeyidentifiercritical;}

  public String getDefaultCRLDistPoint(){ return defaultcrldistpoint; }

  public void setDefaultCRLDistPoint(String defaultCRLDistPoint) {
      this.defaultcrldistpoint = defaultCRLDistPoint;
  }
 
  /**
   * A method returning all CDP URLs to currently used CRL partitions for this CA  
   * @param crlUrl is the URL to the CRL CDP for this CA, in the format "http://example.com/CA*.crl", 
   * where any '*' will be replaced by an index number (or removed for the first partition)
   * @return a list of CDP URLs with index numbers for currently used CRL partitions for this CA 
   */
  public List<String> getAllCrlPartitionUrls(final String crlUrl) {
      List<String> crlUrlsReturned = new ArrayList<>();
      if (getUsePartitionedCrl()) {
          int partitionUrlsToGenerate = (getCrlPartitions() - getSuspendedCrlPartitions());
          crlUrlsReturned.add(crlUrl.replace("*", ""));
          Integer partitionIndex = getSuspendedCrlPartitions() < 1 ? 1 : 1 + getSuspendedCrlPartitions();  
          for (int generatedUrls = 0; generatedUrls < partitionUrlsToGenerate; generatedUrls++) {
              crlUrlsReturned.add(crlUrl.replace("*", partitionIndex.toString()));
              partitionIndex++;
          }
      } else {
          crlUrlsReturned.add(crlUrl.replace("*", ""));
      }
      return crlUrlsReturned;
  }

  /**
   * A method returning a CDP URL with the given CRL partition index number for this CA 
   * @param crlUrl is the URL to the CRL CDP for this CA, in the format "http://example.com/CA*.crl", 
   * where any '*' will be replaced by given index number (or removed for the first partition)
   * @param index is the index of the CRL partition asked for
   * @return the URL for the specific CRL partition CDP with the given index number 
   */
  public String getCrlPartitionUrl(final String crlUrl, final int index) {
      Integer partitionIndex = index;
      if (index == 0 || !getUsePartitionedCrl()) {
          return crlUrl.replace("*", "");
      }
      return crlUrl.replace("*", partitionIndex.toString());
  }

  /**
   * Determines which CRL Partition Index a given certificate belongs to. This check is based on the URI in the CRL Distribution Point extension.
   * @param cert Certificate
   * @return Partition number, or {@link CertificateConstants#NO_CRL_PARTITION} if partitioning is not enabled / not applicable.
   */
  @Override
  public int determineCrlPartitionIndex(final Certificate cert) {
      if (getUsePartitionedCrl() && cert instanceof X509Certificate) {
          final Collection<String> uris = CertTools.getCrlDistributionPoints((X509Certificate) cert);
          return determineCrlPartitionIndex(uris);
      }
      return CertificateConstants.NO_CRL_PARTITION;
  }

  /**
   * Determines which CRL Partition Index a given CRL belongs to. This check is based on the URI in the Issuing Distribution Point extension.
   * @param crl CRL
   * @return Partition number, or {@link CertificateConstants#NO_CRL_PARTITION} if partitioning is not enabled / not applicable.
   */
  @Override
  public int determineCrlPartitionIndex(final X509CRL crl) {
      if (getUsePartitionedCrl()) {
          final Collection<String> uris = CertTools.getCrlDistributionPoints(crl);
          return determineCrlPartitionIndex(uris);
      }
      return CertificateConstants.NO_CRL_PARTITION;
  }

  private int determineCrlPartitionIndex(final Collection<String> uris) {
      for (final String uri : uris) {
          final int partition = determineCrlPartitionIndex(uri);
          if (partition != CertificateConstants.NO_CRL_PARTITION) {
              return partition;
          }
      }
      return CertificateConstants.NO_CRL_PARTITION;
  }

  /** Creates a regex that matches all Default CRL Distribution Points. Partition numbers (if any) are matched in groups. */
  private String getRegexForCrlDistPoints() {
      // \E and \Q are "end quote" and "start quote", see the javadoc of Pattern
      return Pattern.quote(StringUtils.trim(defaultcrldistpoint))
              .replace("*", "\\E(\\d+)\\Q") // match digits where there is a "*"
              .replaceAll("\\s*;\\s*", "\\\\E|\\\\Q"); // match multiple different URIs separated with ";"
  }

  /**
   * Determines which CRL Partition Index by a CRL Distribution Point URIs.
   * @param uri URI to extract partition index from.
   * @return Partition number, or {@link CertificateConstants#NO_CRL_PARTITION} if partitioning is not enabled / not applicable.
   */
  protected int determineCrlPartitionIndex(final String uri) {
      if (!getUsePartitionedCrl() || StringUtils.isBlank(defaultcrldistpoint)) {
          return CertificateConstants.NO_CRL_PARTITION;
      }
      final String regex = getRegexForCrlDistPoints();
      if (log.isTraceEnabled()) {
          log.trace("Using regex '" + regex +"' to match URI '" + uri + "'");
      }
      final Matcher matcher = Pattern.compile(regex).matcher(uri);
      if (!matcher.matches()) {
          final String msg = "CRL Distribution Point URI '" + uri + "' does not match '" + defaultcrldistpoint + "'";
          log.debug(msg);
          return CertificateConstants.NO_CRL_PARTITION;
      }
      final int groupCount = matcher.groupCount();
      int partition = CertificateConstants.NO_CRL_PARTITION;
      try {
          for (int i = 1; i <= groupCount; i++) {
              if (matcher.group(i) != null) {
                  final int numberFromUri = Integer.parseInt(matcher.group(i));
                  if (partition != CertificateConstants.NO_CRL_PARTITION && numberFromUri != partition) {
                      log.info("Ambiguous CRL Partition Indexes in URI: " + uri);
                      return CertificateConstants.NO_CRL_PARTITION;
                  }
                  partition = numberFromUri;
              }
          }
          return partition;
      } catch (NumberFormatException e) {
          final String msg = "Bad number format in CRL Partition Indexes in URI: " + uri;
          log.info(msg);
          return CertificateConstants.NO_CRL_PARTITION;
      }
  }

  @Override
  public IntRange getAllCrlPartitionIndexes() {
      if (!getUsePartitionedCrl()) {
          return null;
      }
      return new IntRange(1, getCrlPartitions());
  }

  public String getDefaultCRLIssuer(){ return defaultcrlissuer; }
  public void setDefaultCRLIssuer(String defaultcrlissuer) {
      this.defaultcrlissuer = defaultcrlissuer;
  }

  public String getDefaultOCSPServiceLocator(){ return defaultocsplocator; }
  public void setDefaultOCSPServiceLocator(String defaultocsplocator) {
      this.defaultocsplocator = defaultocsplocator;
  }

  public String getCADefinedFreshestCRL(){ return this.cadefinedfreshestcrl; }

  public void setCADefinedFreshestCRL(String cADefinedFreshestCRL) {
      this.cadefinedfreshestcrl = cADefinedFreshestCRL;
  }

  public String getSubjectAltName(){ return subjectaltname; }
  public void setSubjectAltName(final String subjectaltname) {
      this.subjectaltname = subjectaltname;
  }
  public boolean getUseUTF8PolicyText() { return useUTF8PolicyText; }
  public void setUseUTF8PolicyText(final boolean useUTF8PolicyText) {
      this.useUTF8PolicyText = useUTF8PolicyText;
  }

  public boolean getUsePrintableStringSubjectDN() { return usePrintableStringSubjectDN; }
  public void setUsePrintableStringSubjectDN(final boolean usePrintableStringSubjectDN) {
      this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
  }

  public boolean getUseLdapDnOrder() { return useLdapDNOrder; }
  public void setUseLdapDnOrder(final boolean useLdapDNOrder) {
      this.useLdapDNOrder = useLdapDNOrder;
  }

  public boolean getUseCrlDistributionPointOnCrl() {
      return this.useCrlDistributionPointOnCrl;
  }

  public void setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl) {
      this.useCrlDistributionPointOnCrl = useCrlDistributionPointOnCrl;
  }

  public boolean getCrlDistributionPointOnCrlCritical() {
      return this.crlDistributionPointOnCrlCritical;
  }
  public void setCrlDistributionPointOnCrlCritical(boolean crlDistributionPointOnCrlCritical) {
      this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
  }

  public String getCmpRaAuthSecret() { return cmpRaAuthSecret; }
  public void setCmpRaAuthSecret(String cmpRaAuthSecret) { this.cmpRaAuthSecret = cmpRaAuthSecret == null ? "" : cmpRaAuthSecret; }

    public List<String> getAuthorityInformationAccess() {
        return authorityInformationAccess;
    }

    public void setAuthorityInformationAccess(List<String> list) {
        this.authorityInformationAccess = list;
    }

    /** @return the certificateAiaDefaultCaIssuerUri */
    public List<String> getCertificateAiaDefaultCaIssuerUri() {
        return certificateAiaDefaultCaIssuerUri;
    }

    /** @param list the certificateAiaDefaultCaIssuerUri to set */
    public void setCertificateAiaDefaultCaIssuerUri(List<String> list) {
        this.certificateAiaDefaultCaIssuerUri = list;
    }

    /** @return a list of encoded names of the permitted names in issued certificates */
    public List<String> getNameConstraintsPermitted() {
        return nameConstraintsPermitted;
    }

    public void setNameConstraintsPermitted(List<String> encodedNames) {
        nameConstraintsPermitted = encodedNames;
    }

    /** @return a list of encoded names of the forbidden names in issued certificates */
    public List<String> getNameConstraintsExcluded() {
        return nameConstraintsExcluded;
    }

    public void setNameConstraintsExcluded(List<String> encodedNames) {
        nameConstraintsExcluded = encodedNames;
    }

    /** @return what should be a String formatted URL pointing to an external CA's CDP. */
    public String getExternalCdp() {
        return externalCdp;
    }

    /** Set what should be a String formatted URL pointing to an external CA's CDP. */
    public void setExternalCdp(final String externalCdp) {
        this.externalCdp = externalCdp;
    }

    /** @return true if CA has undergone through name change at some renewal process, otherwise false. */
    public boolean getNameChanged() {
        return nameChanged;
    }

    /** NameChanged attribute should only be set when X509CA is retrieved from DB */
    void setNameChanged(final boolean value){
        nameChanged = value;
    }

    public int getCaSerialNumberOctetSize() {
        return caSerialNumberOctetSize;
    }

    public void setCaSerialNumberOctetSize(int caSerialNumberOctetSize) {
        this.caSerialNumberOctetSize = caSerialNumberOctetSize;
    }
    
    /** @return true if CA should pre-produce OCSP responses, otherwise false. */
    public boolean isDoPreProduceOcspResponses() {
        return doPreProduceOcspResponses;
    }
    
    /** Set whether the CA should pre-produce OCSP responses. */
    public void setDoPreProduceOcspResponses(boolean doPreProduceOcspResponses) {
        this.doPreProduceOcspResponses = doPreProduceOcspResponses;
    }

    /** @return true if OCSP responses be stored upon request */
    public boolean isDoStoreOcspResponsesOnDemand() {
        return doStoreOcspResponsesOnDemand;
    }

    /** Set whether OCSP responses should be stored upon request */
    public void setDoStoreOcspResponsesOnDemand(boolean doStoreOcspResponsesOnDemand) {
        this.doStoreOcspResponsesOnDemand = doStoreOcspResponsesOnDemand;
    }

    /** 
     * Partitioned crls are used by CAs with very large crls.  
     * It is CA specific configuration using multiple partitions to which certificates randomly are assigned. 
     * @return true if a partitioned crl is used 
     */
    public boolean getUsePartitionedCrl() {
        return this.usePartitionedCrl;
    }
    
    /** 
     *  Set use partitioned crl for this ca.
     *  @see #getUsePartitionedCrl() 
     */
    public void setUsePartitionedCrl(final boolean usePartitionedCrl) {
        this.usePartitionedCrl = usePartitionedCrl;  
    }
    
    /** 
     * @return how many crl partitions are being used in total by this ca 
     *  @see #getUsePartitionedCrl() 
     */
    public int getCrlPartitions() {
        return crlPartitions;
    }
    
    /** 
     * Set the number of crl partitions that should be used by this ca. 
     * @see #getUsePartitionedCrl() 
     */
    public void setCrlPartitions(final int crlPartitions) {
        this.crlPartitions = crlPartitions;  
    }
    
    /** 
     * New certificates will not be assigned to suspended partitions. This can be used to balance the partitions
     * if the low numbered partitions have too many certificates (for example after increasing the number of partitions).  
     * @return the number of suspended CRL partitions for this CA.
     * @see #getUsePartitionedCrl() 
     */
    public int getSuspendedCrlPartitions() {
        return suspendedCrlPartitions;
    }
    
    /** 
     * Set the number of suspended CRL partitions for this CA.
     * @see #getUsePartitionedCrl() 
     */
    public void setSuspendedCrlPartitions(final int suspendedCrlPartitions) {
        this.suspendedCrlPartitions = suspendedCrlPartitions;  
    }
    
    public String getRequestPreProcessor() {
        return requestPreProcessor;
    }

    public void setRequestPreProcessor(String requestPreProcessor) {
        this.requestPreProcessor = requestPreProcessor;
    }

    public static class X509CAInfoBuilder {
        private int caId;
        private String subjectDn;
        private String name;
        private int status;
        private int certificateProfileId;
        private String encodedValidity;
        private int signedBy;
        private Collection<Certificate> certificateChain;
        private CAToken caToken;
        private Date updateTime = new Date();
        private String subjectAltName = "";
        private int defaultCertProfileId = 0;
        private boolean useNoConflictCertificateData = false;
        private Date expireTime = null;
        private int caType = CAInfo.CATYPE_X509;
        private String description = "";
        private int caSerialNumberOctetSize = -1;
        private int revocationReason = -1;
        private Date revocationDate = null;
        private List<CertificatePolicy> policies = null;
        private long crlPeriod = 1 * SimpleTime.MILLISECONDS_PER_DAY;
        private long crlIssueInterval = 0L;
        private long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_MINUTE;
        private long deltaCrlPeriod = 0L;
        private Collection<Integer> crlPublishers = new ArrayList<>();
        private Collection<Integer> validators = new ArrayList<>();
        private boolean useAuthorityKeyIdentifier = true;
        private boolean authorityKeyIdentifierCritical = false;
        private boolean useCrlNumber = true;
        private boolean crlNumberCritical = false;
        private String defaultCrlDistPoint = null;
        private String defaultCrlIssuer = null;
        private String defaultOcspCerviceLocator = null;
        private List<String> authorityInformationAccess = null;
        private List<String> certificateAiaDefaultCaIssuerUri = null;
        private List<String> nameConstraintsPermitted = null;
        private List<String> nameConstraintsExcluded = null;
        private String caDefinedFreshestCrl = null;
        private boolean finishUser = true;
        private Collection<ExtendedCAServiceInfo> extendedCaServiceInfos = new ArrayList<>();
        private boolean useUtf8PolicyText = false;
        private Map<ApprovalRequestType, Integer> approvals = new HashMap<>();
        private boolean usePrintableStringSubjectDN = false;
        private boolean useLdapDnOrder = true;
        private boolean useCrlDistributionPointOnCrl = false;
        private boolean crlDistributionPointOnCrlCritical = false;
        private boolean includeInHealthCheck = true;
        private boolean doEnforceUniquePublicKeys = true;
        private boolean doEnforceKeyRenewal = true;
        private boolean doEnforceUniqueDistinguishedName = true;
        private boolean doEnforceUniqueSubjectDNSerialnumber = false;
        private boolean useCertReqHistory = false;
        private boolean useUserStorage = true;
        private boolean useCertificateStorage = true;
        private boolean doPreProduceOcspResponses = false;
        private boolean doStoreOcspResponsesOnDemand = false;
        private boolean acceptRevocationNonExistingEntry = false;
        private String cmpRaAuthSecret = null;
        private boolean keepExpiredCertsOnCRL = false;
        private boolean usePartitionedCrl = false;
        private int crlPartitions;
        private int suspendedCrlPartitions;
        private String requestPreProcessor;

        public X509CAInfoBuilder  setCaId(int caId) {
            this.caId = caId;
            return this;
        }

        /**
         * @param subjectDn the Subject DN of the CA as found in the certificate
         */
        public X509CAInfoBuilder setSubjectDn(String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }

        /**
         * @param name the name of the CA shown in EJBCA, can be changed by the user
         */
        public X509CAInfoBuilder setName(String name) {
            this.name = name;
            return this;
        }

        /**
         * @param status the operational status of the CA, one of the constants in {@link CAConstants}
         */
        public X509CAInfoBuilder setStatus(int status) {
            this.status = status;
            return this;
        }

        /**
         * @param certificateProfileId the ID of the certificate profile for this CA
         */
        public X509CAInfoBuilder setCertificateProfileId(int certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
            return this;
        }

        /**
         * @param encodedValidity the validity of this CA as a human-readable string, e.g. 25y
         */
        public X509CAInfoBuilder setEncodedValidity(String encodedValidity) {
            this.encodedValidity = encodedValidity;
            return this;
        }

        /**
         * @param signedBy the id of the CA which signed this CA
         */
        public X509CAInfoBuilder setSignedBy(int signedBy) {
            this.signedBy = signedBy;
            return this;
        }

        /**
         * @param certificateChain the certificate chain containing the CA certificate of this CA
         */
        public X509CAInfoBuilder setCertificateChain(Collection<Certificate> certificateChain) {
            this.certificateChain = certificateChain;
            return this;
        }

        /**
         * @param caToken the CA token for this CA, containing e.g. a reference to the crypto token
         */
        public X509CAInfoBuilder setCaToken(CAToken caToken) {
            this.caToken = caToken;
            return this;
        }

        /**
         * @param updateTime the last time this CA was updated, normally the current date and time
         */
        public X509CAInfoBuilder setUpdateTime(Date updateTime) {
            this.updateTime = updateTime;
            return this;
        }

        /**
         * @param subjectAltName the Subject Alternative Name (SAN) of the CA, as found in the certificate
         */
        public X509CAInfoBuilder setSubjectAltName(String subjectAltName) {
            this.subjectAltName = subjectAltName;
            return this;
        }

        /**
         * @param defaultCertProfileId the id of default cetificate profile for certificates this CA issues
         */
        public X509CAInfoBuilder setDefaultCertProfileId(int defaultCertProfileId) {
            this.defaultCertProfileId = defaultCertProfileId;
            return this;
        }

        /**
         * @param useNoConflictCertificateData should use NoConflictCertificate data table to write to
         */
        public X509CAInfoBuilder setUseNoConflictCertificateData(boolean useNoConflictCertificateData) {
            this.useNoConflictCertificateData = useNoConflictCertificateData;
            return this;
        }

        /**
         * @param expireTime the date when this CA expires
         */
        public X509CAInfoBuilder setExpireTime(Date expireTime) {
            this.expireTime = expireTime;
            return this;
        }

        /**
         * @param caType the type of CA, in this case CAInfo.CATYPE_X509
         */
        public X509CAInfoBuilder setCaType(int caType) {
            this.caType = caType;
            return this;
        }

        /**
         * @param description a text describing this CA
         */
        public X509CAInfoBuilder setDescription(String description) {
            this.description = description;
            return this;
        }

        /**
         * @param revocationReason the reason why this CA was revoked, or -1 if not revoked
         */
        public X509CAInfoBuilder setRevocationReason(int revocationReason) {
            this.revocationReason = revocationReason;
            return this;
        }

        /**
         * @param revocationDate the date of revocation, or null if not revoked
         */
        public X509CAInfoBuilder setRevocationDate(Date revocationDate) {
            this.revocationDate = revocationDate;
            return this;
        }

        /**
         * @param policies a policy OID
         */
        public X509CAInfoBuilder setPolicies(List<CertificatePolicy> policies) {
            this.policies = policies;
            return this;
        }

        /**
         * @param crlPeriod the CRL validity period in ms
         */
        public X509CAInfoBuilder setCrlPeriod(long crlPeriod) {
            this.crlPeriod = crlPeriod;
            return this;
        }

        /**
         * @param crlIssueInterval how often in ms the CRLs should be distributed, e.g. 3600000 will generate a new CRL every hour
         */
        public X509CAInfoBuilder setCrlIssueInterval(long crlIssueInterval) {
            this.crlIssueInterval = crlIssueInterval;
            return this;
        }

        /**
         * @param crlOverlapTime the validity overlap in ms for a subsequent CRL, e.g. 5000 will generate a CRL 5m before the previous CRL expires
         */
        public X509CAInfoBuilder setCrlOverlapTime(long crlOverlapTime) {
            this.crlOverlapTime = crlOverlapTime;
            return this;
        }

        /**
         * @param deltaCrlPeriod how often Delta CRLs should be distributed
         */
        public X509CAInfoBuilder setDeltaCrlPeriod(long deltaCrlPeriod) {
            this.deltaCrlPeriod = deltaCrlPeriod;
            return this;
        }

        /**
         * @param crlPublishers a collection of publisher IDs for this CA
         */
        public X509CAInfoBuilder setCrlPublishers(Collection<Integer> crlPublishers) {
            this.crlPublishers = crlPublishers;
            return this;
        }

        /**
         * @param validators a collection of key validator IDs for this CA
         */
        public X509CAInfoBuilder setValidators(Collection<Integer> validators) {
            this.validators = validators;
            return this;
        }

        public X509CAInfoBuilder setUseAuthorityKeyIdentifier(boolean useAuthorityKeyIdentifier) {
            this.useAuthorityKeyIdentifier = useAuthorityKeyIdentifier;
            return this;
        }

        public X509CAInfoBuilder setAuthorityKeyIdentifierCritical(boolean authorityKeyIdentifierCritical) {
            this.authorityKeyIdentifierCritical = authorityKeyIdentifierCritical;
            return this;
        }

        public X509CAInfoBuilder setUseCrlNumber(boolean useCrlNumber) {
            this.useCrlNumber = useCrlNumber;
            return this;
        }

        public X509CAInfoBuilder setCrlNumberCritical(boolean crlNumberCritical) {
            this.crlNumberCritical = crlNumberCritical;
            return this;
        }

        /**
         * @param defaultCrlDistPoint the URI of the default CRL distribution point
         */
        public X509CAInfoBuilder setDefaultCrlDistPoint(String defaultCrlDistPoint) {
            this.defaultCrlDistPoint = defaultCrlDistPoint;
            return this;
        }

        public X509CAInfoBuilder setDefaultCrlIssuer(String defaultCrlIssuer) {
            this.defaultCrlIssuer = defaultCrlIssuer;
            return this;
        }

        public X509CAInfoBuilder setDefaultOcspCerviceLocator(String defaultOcspCerviceLocator) {
            this.defaultOcspCerviceLocator = defaultOcspCerviceLocator;
            return this;
        }

        public X509CAInfoBuilder setAuthorityInformationAccess(List<String> authorityInformationAccess) {
            this.authorityInformationAccess = authorityInformationAccess;
            return this;
        }

        public X509CAInfoBuilder setCertificateAiaDefaultCaIssuerUri(List<String> certificateAiaDefaultCaIssuerUri) {
            this.certificateAiaDefaultCaIssuerUri = certificateAiaDefaultCaIssuerUri;
            return this;
        }

        /**
         * @param nameConstraintsPermitted a list of name constraints which should be permitted
         */
        public X509CAInfoBuilder setNameConstraintsPermitted(List<String> nameConstraintsPermitted) {
            this.nameConstraintsPermitted = nameConstraintsPermitted;
            return this;
        }

        /**
         * @param nameConstraintsExcluded a list of name constraints which should be excluded
         */
        public X509CAInfoBuilder setNameConstraintsExcluded(List<String> nameConstraintsExcluded) {
            this.nameConstraintsExcluded = nameConstraintsExcluded;
            return this;
        }

        public X509CAInfoBuilder setCaDefinedFreshestCrl(String caDefinedFreshestCrl) {
            this.caDefinedFreshestCrl = caDefinedFreshestCrl;
            return this;
        }

        public X509CAInfoBuilder setFinishUser(boolean finishUser) {
            this.finishUser = finishUser;
            return this;
        }

        public X509CAInfoBuilder setExtendedCaServiceInfos(Collection<ExtendedCAServiceInfo> extendedCaServiceInfos) {
            this.extendedCaServiceInfos = extendedCaServiceInfos;
            return this;
        }

        public X509CAInfoBuilder setUseUtf8PolicyText(boolean useUtf8PolicyText) {
            this.useUtf8PolicyText = useUtf8PolicyText;
            return this;
        }

        /**
         * @param approvals a map of approval profiles which should be used for different operations
         */
        public X509CAInfoBuilder setApprovals(Map<ApprovalRequestType, Integer> approvals) {
            this.approvals = approvals;
            return this;
        }

        public X509CAInfoBuilder setUsePrintableStringSubjectDN(boolean usePrintableStringSubjectDN) {
            this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
            return this;
        }

        public X509CAInfoBuilder setUseLdapDnOrder(boolean useLdapDnOrder) {
            this.useLdapDnOrder = useLdapDnOrder;
            return this;
        }

        public X509CAInfoBuilder setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl) {
            this.useCrlDistributionPointOnCrl = useCrlDistributionPointOnCrl;
            return this;
        }

        public X509CAInfoBuilder setCrlDistributionPointOnCrlCritical(boolean crlDistributionPointOnCrlCritical) {
            this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
            return this;
        }
        /**
         * @param includeInHealthCheck enable healthcheck for this CA
         */
        public X509CAInfoBuilder setIncludeInHealthCheck(boolean includeInHealthCheck) {
            this.includeInHealthCheck = includeInHealthCheck;
            return this;
        }

        public X509CAInfoBuilder setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
            this.doEnforceUniquePublicKeys = doEnforceUniquePublicKeys;
            return this;
        }
        public X509CAInfoBuilder setDoEnforceKeyRenewal(boolean doEnforceKeyRenewal) {
            this.doEnforceKeyRenewal = doEnforceKeyRenewal;
            return this;
        }

        public X509CAInfoBuilder setDoEnforceUniqueDistinguishedName(boolean doEnforceUniqueDistinguishedName) {
            this.doEnforceUniqueDistinguishedName = doEnforceUniqueDistinguishedName;
            return this;
        }

        public X509CAInfoBuilder setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSerialnumber) {
            this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSerialnumber;
            return this;
        }

        public X509CAInfoBuilder setUseCertReqHistory(boolean useCertReqHistory) {
            this.useCertReqHistory = useCertReqHistory;
            return this;
        }

        public X509CAInfoBuilder setUseUserStorage(boolean useUserStorage) {
            this.useUserStorage = useUserStorage;
            return this;
        }

        public X509CAInfoBuilder setUseCertificateStorage(boolean useCertificateStorage) {
            this.useCertificateStorage = useCertificateStorage;
            return this;
        }
        
        public X509CAInfoBuilder setDoPreProduceOcspResponses(boolean doPreProduceOcspResponses) {
            this.doPreProduceOcspResponses = doPreProduceOcspResponses;
            return this;
        }
        
        public X509CAInfoBuilder setDoStoreOcspResponsesOnDemand(boolean doStoreOcspResponsesOnDemand) {
            this.doStoreOcspResponsesOnDemand = doStoreOcspResponsesOnDemand;
            return this;
        }

        public X509CAInfoBuilder setAcceptRevocationNonExistingEntry(boolean acceptRevocationNonExistingEntry) {
            this.acceptRevocationNonExistingEntry = acceptRevocationNonExistingEntry;
            return this;
        }

        public X509CAInfoBuilder setCmpRaAuthSecret(String cmpRaAuthSecret) {
            this.cmpRaAuthSecret = cmpRaAuthSecret;
            return this;
        }

        public X509CAInfoBuilder setKeepExpiredCertsOnCRL(boolean keepExpiredCertsOnCRL) {
            this.keepExpiredCertsOnCRL = keepExpiredCertsOnCRL;
            return this;
        }

        /**
         * @param caSerialNumberOctetSize serial number octet size for this CA
         */
        public X509CAInfoBuilder setCaSerialNumberOctetSize(int caSerialNumberOctetSize) {
            this.caSerialNumberOctetSize = caSerialNumberOctetSize;
            return this;
        }

        /**
         * @param usePartitionedCrl boolean specifying partitioned crl usage
         */
        public X509CAInfoBuilder setUsePartitionedCrl(boolean usePartitionedCrl) {
            this.usePartitionedCrl = usePartitionedCrl;
            return this;
        }

        /**
         * @param crlPartitions the number of crl partitions (if any) used currently by this ca
         */
        public X509CAInfoBuilder setCrlPartitions(int crlPartitions) {
            this.crlPartitions = crlPartitions;
            return this;
        }

        /**
         * @param suspendedCrlPartitions the number of suspended crl partitions (if any) currently used for this ca
         */
        public X509CAInfoBuilder setSuspendedCrlPartitions(int suspendedCrlPartitions) {
            this.suspendedCrlPartitions = suspendedCrlPartitions;
            return this;
        }

        public String getRequestPreProcessor() {
            return requestPreProcessor;
        }

        public X509CAInfoBuilder setRequestPreProcessor(final String requestPreProcessor) {
            this.requestPreProcessor = requestPreProcessor;
            return this;
        }

        public X509CAInfo build() {
            X509CAInfo caInfo = new X509CAInfo(encodedValidity, caToken, description, caSerialNumberOctetSize, crlPeriod, crlIssueInterval, crlOverlapTime, deltaCrlPeriod, crlPublishers, validators,
                    useAuthorityKeyIdentifier, authorityKeyIdentifierCritical, useCrlNumber, crlNumberCritical, defaultCrlDistPoint, defaultCrlIssuer, defaultOcspCerviceLocator, authorityInformationAccess,
                    certificateAiaDefaultCaIssuerUri, nameConstraintsPermitted, nameConstraintsExcluded, caDefinedFreshestCrl, finishUser, extendedCaServiceInfos, useUtf8PolicyText, approvals,
                    usePrintableStringSubjectDN, useLdapDnOrder, useCrlDistributionPointOnCrl, crlDistributionPointOnCrlCritical, includeInHealthCheck, doEnforceUniquePublicKeys, doEnforceKeyRenewal,
                    doEnforceUniqueDistinguishedName, doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage, doPreProduceOcspResponses, doStoreOcspResponsesOnDemand,
                    acceptRevocationNonExistingEntry, cmpRaAuthSecret, keepExpiredCertsOnCRL, defaultCertProfileId, useNoConflictCertificateData, usePartitionedCrl, crlPartitions, suspendedCrlPartitions, requestPreProcessor);
            caInfo.setSubjectDN(subjectDn);
            caInfo.setCAId(CertTools.stringToBCDNString(caInfo.getSubjectDN()).hashCode());
            caInfo.setName(name);
            caInfo.setStatus(status);
            caInfo.setUpdateTime(updateTime);
            caInfo.setExpireTime(expireTime);
            caInfo.setCAType(caType);
            caInfo.setSignedBy(signedBy);
            // Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure all certificates in this
            // Array were of Oracle's own provider, using CertTools.SYSTEM_SECURITY_PROVIDER.
            // As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1 anymore.
            try {
                if (certificateChain != null) {
                    X509Certificate[] certs = certificateChain.toArray(new X509Certificate[certificateChain.size()]);
                    List<Certificate> list = CertTools.getCertCollectionFromArray(certs, null);
                    caInfo.setCertificateChain(list);
                } else {
                    caInfo.setCertificateChain(null);
                }
            } catch (CertificateException | NoSuchProviderException e) {
                throw new IllegalArgumentException(e);
            }
            caInfo.setRevocationReason(revocationReason);
            caInfo.setRevocationDate(revocationDate);
            caInfo.setPolicies(policies);
            caInfo.setSubjectAltName(subjectAltName);
            caInfo.setCertificateProfileId(certificateProfileId);
            caInfo.setRequestPreProcessor(requestPreProcessor);
            return caInfo;
        }

        public X509CAInfo buildForUpdate() {
            X509CAInfo caInfo = new X509CAInfo(encodedValidity, caToken, description, caSerialNumberOctetSize, crlPeriod, crlIssueInterval, crlOverlapTime, deltaCrlPeriod, crlPublishers, validators,
                    useAuthorityKeyIdentifier, authorityKeyIdentifierCritical, useCrlNumber, crlNumberCritical, defaultCrlDistPoint, defaultCrlIssuer, defaultOcspCerviceLocator, authorityInformationAccess,
                    certificateAiaDefaultCaIssuerUri, nameConstraintsPermitted, nameConstraintsExcluded, caDefinedFreshestCrl, finishUser, extendedCaServiceInfos, useUtf8PolicyText, approvals,
                    usePrintableStringSubjectDN, useLdapDnOrder, useCrlDistributionPointOnCrl, crlDistributionPointOnCrlCritical, includeInHealthCheck, doEnforceUniquePublicKeys, doEnforceKeyRenewal,
                    doEnforceUniqueDistinguishedName, doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage, doPreProduceOcspResponses, doStoreOcspResponsesOnDemand, 
                    acceptRevocationNonExistingEntry, cmpRaAuthSecret, keepExpiredCertsOnCRL, defaultCertProfileId, useNoConflictCertificateData, usePartitionedCrl, crlPartitions, suspendedCrlPartitions, requestPreProcessor);
            caInfo.setCAId(caId);
            return caInfo;
        }

        public X509CAInfo buildDefault () { return null;}
    }
}
