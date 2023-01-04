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
package org.ejbca.ra;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Backing bean for Certificate and CRLs download page.
 *
 */
@Named
@ViewScoped
public class RaCasPageBean implements Serializable {

    /** Representation of a CA in a chain with links to CRL download locations. */
    public class CaAndCrl {
        private final String name;
        private final String subjectDn;
        private final int caId;
        private List<CrlLinkInfo> crlLinks;
        private String deltaCrlLink;
        private final int position;
        private final List<String> chainNames;
        private boolean x509 = false;

        CaAndCrl(final String name, final String subjectDn, final int caId, final int position, final List<String> chainNames) {
            this.name = name;
            this.subjectDn = subjectDn;
            this.caId = caId;
            this.position = position;
            this.chainNames = chainNames;
            crlLinks = new ArrayList<>();
        }

        public String getName() { return name; }
        public String getSubjectDn() { return subjectDn; }
        public int getCaId() { return caId; }
        public List<CrlLinkInfo> getCrlLinks() { return crlLinks; }
        public String getDeltaCrlLink() { return deltaCrlLink; }
        public int getPosition() { return position; }
        public boolean isX509() { return x509; }
        public boolean isPartitionedCrl() { 
            return crlLinks.size() > 1;
        }

        @Override
        public int hashCode() { return subjectDn.hashCode(); }
        @Override
        public boolean equals(final Object obj) { return obj instanceof CaAndCrl && subjectDn.equals(((CaAndCrl)obj).subjectDn); }

        /** @return the Subject DN string of the current certificate in unescaped RDN format */
        public final String getSubjectDnUnescapedRndValue() {
            if (StringUtils.isNotEmpty(subjectDn)) {
                return org.ietf.ldap.LDAPDN.unescapeRDN(subjectDn);
            } else {
                return subjectDn;
            }
        }
    }

    public class CrlLinkInfo {
        private final String link;
        private final int partitionIndex;

        public CrlLinkInfo(String link, int partitionIndex) {
            this.link = link;
            this.partitionIndex = partitionIndex;
        }

        public String getLink() {
            return link;
        }

        public int getPartitionIndex() {
            return partitionIndex;
        }
    }

    private static final long serialVersionUID = 1L;
    private static final String RFC4387_DEFAULT_EJBCA_URL = WebConfiguration.DEFAULT_CRLSTORE_CONTEXTROOT + "/search.cgi";
    private static final int NO_CAID_AVAILABLE = 0;

    @EJB
    private CrlStoreSessionLocal crlSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    private List<CaAndCrl> casAndCrlItems = null;
    private boolean atLeastOneCrlLinkPresent = false;

    /** @return true if at least one of the CAs available via #getCasAndCrlItems() has CRLs present on this system. */
    public boolean isAtLeastOneCrlLinkPresent() {
        getCasAndCrlItems();
        return atLeastOneCrlLinkPresent;
    }

    /** @return a list of all known authorized CAs with links to CRLs (if present) */
    public List<CaAndCrl> getCasAndCrlItems() {
        if (casAndCrlItems==null) {
            final List<CAInfo> caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
            // First build a mapping of all subjects and their short names
            final Map<String,String> caSubjectToNameMap = new HashMap<>();
            for (final CAInfo caInfo : caInfos) {
                caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
            }
            // Convert all CA's chains into CA objects (use a Set to avoid duplicates)
            final Set<CaAndCrl> cas = new HashSet<>();
            for (final CAInfo caInfo : caInfos) {
                final List<Certificate> chain = new ArrayList<>(caInfo.getCertificateChain());
                Collections.reverse(chain);
                final List<String> chainNames = new ArrayList<>();
                final int caId = caInfo.getCAId();
                for (final Certificate caCertificate : chain) {
                    final String subjectDn = CertTools.getSubjectDN(caCertificate);
                    String name = caSubjectToNameMap.get(subjectDn);
                    if (name==null) {
                        name = subjectDn;
                    }
                    chainNames.add(name);
                    final CaAndCrl caAndCrl = new CaAndCrl(name, subjectDn, chainNames.size()==chain.size()?caId:NO_CAID_AVAILABLE, chainNames.size()-1, new ArrayList<>(chainNames));
                    // Construct links to RFC4387 CRL Download Servlet
                    if (caCertificate instanceof X509Certificate) {
                        caAndCrl.x509 = true;
                        final int numberOfPartitions = caInfo.getAllCrlPartitionIndexes() == null ? 1 : caInfo.getAllCrlPartitionIndexes().getMaximumInteger();
                        for (int currentPartitionIndex = 0; currentPartitionIndex <= numberOfPartitions; currentPartitionIndex++) {
                            final CRLInfo currentCrlInfo = crlSession.getLastCRLInfoLightWeight(subjectDn, currentPartitionIndex, false);
                            if (currentCrlInfo != null) {
                                atLeastOneCrlLinkPresent = true;
                                String crlLink = RFC4387_DEFAULT_EJBCA_URL + "?iHash=" + getSubjectPrincipalHashAsUnpaddedBase64(((X509Certificate)caCertificate)); 
                                if ( numberOfPartitions > 1) {
                                    crlLink += "&partition=" + currentPartitionIndex;
                                }
                                caAndCrl.crlLinks.add(new CrlLinkInfo(crlLink, currentPartitionIndex));
                            }
                        }

                        final CRLInfo crlInfoDelta = crlSession.getLastCRLInfoLightWeight(subjectDn, CertificateConstants.NO_CRL_PARTITION, true);
                        if (crlInfoDelta!=null) {
                            caAndCrl.deltaCrlLink = RFC4387_DEFAULT_EJBCA_URL + "?iHash=" + getSubjectPrincipalHashAsUnpaddedBase64((X509Certificate)caCertificate) + "&delta=";
                        }
                    }
                    // Add missing items and replace items when we know the CAId
                    if (caAndCrl.getCaId()!=NO_CAID_AVAILABLE) {
                        cas.remove(caAndCrl);
                    }
                    if (!cas.contains(caAndCrl)) {
                        cas.add(caAndCrl);
                    }
                }
            }
            casAndCrlItems = new ArrayList<>(cas);
            // Sort by higher level CAs
            Collections.sort(casAndCrlItems, new Comparator<CaAndCrl>() {
                @Override
                public int compare(final CaAndCrl caAndCrl1, final CaAndCrl caAndCrl) {
                    final int size1 = caAndCrl1.chainNames.size();
                    final int size2 = caAndCrl.chainNames.size();
                    // Avoid checking if chain length is the same
                    for (int i=0; i<Math.min(size1, size2); i++) {
                        final String name1 = caAndCrl1.chainNames.get(i);
                        final String name2 = caAndCrl.chainNames.get(i);
                        final int compareTo = name1.compareToIgnoreCase(name2);
                        if (compareTo!=0) {
                            return compareTo;
                        }
                    }
                    return size1-size2;
                }
            });
        }
        return casAndCrlItems;
    }

    /** @return the issuer hash in base64 encoding without padding which is the way RFC4387 search function expects the iHash parameter. */
    private String getSubjectPrincipalHashAsUnpaddedBase64(final X509Certificate x509Certificate) {
        final byte[] hashSubjectX500Principal = CertTools.generateSHA1Fingerprint(x509Certificate.getSubjectX500Principal().getEncoded());
        return new String(Base64.encode(hashSubjectX500Principal)).substring(0, 27).replaceAll("\\+", "%2B");
    }
}
