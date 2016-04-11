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
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;

/**
 * Backing bean for Certificate and CRLs download page. 
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaCasPageBean implements Serializable {

    /** Representation of a CA in a chain with links to CRL download locations. */
    public class CaAndCrl {
        private final String name;
        private final String subjectDn;
        private String crlLink;
        private String deltaCrlLink;
        private final int position;
        private int relativePosition;
        
        CaAndCrl(final String name, final String subjectDn, final int position) {
            this.name = name;
            this.subjectDn = subjectDn;
            this.position = position;
        }
        
        public String getName() { return name; }
        public String getSubjectDn() { return subjectDn; }
        public String getCrlLink() { return crlLink; }
        public String getDeltaCrlLink() { return deltaCrlLink; }
        public int getPosition() { return position; }
        public int getRelativePosition() { return relativePosition; }
        private void setRelativePosition(final int relativePosition) { this.relativePosition = relativePosition; }
    }

    /** Representation of a CA's chain. */
    public class CaChainAndCrls {
        private final List<CaAndCrl> casAndCrls = new ArrayList<>();
        private final String name;
        private final String subjectDn;
        private final int caId;
        
        public CaChainAndCrls(final String name, final String subjectDn, final int caId) {
            this.name = name;
            this.subjectDn = subjectDn;
            this.caId = caId;
        }
        public String getName() { return name; }
        public String getSubjectDn() { return subjectDn; }
        public List<CaAndCrl> getCasAndCrls() { return casAndCrls; }
        public int getCaId() { return caId; }
    }
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaCasPageBean.class);
    private static final String RFC4387_DEFAULT_EJBCA_URL = "/ejbca/publicweb/crls/search.cgi";

    @ManagedProperty(value="#{raMasterApiBean}")
    private RaMasterApiBean raMasterApiBean;
    public void setRaMasterApiBean(final RaMasterApiBean raMasterApiBean) { this.raMasterApiBean = raMasterApiBean; }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    @EJB
    private CrlStoreSessionLocal crlSession;

    private List<CaChainAndCrls> caChainsAndCrls = null;;
    private Map<String,String> caSubjectToNameMap = new HashMap<>();

    /** @return a list of all authorized CAs. */
    public List<CaChainAndCrls> getCaChainsAndCrls() {
        if (caChainsAndCrls==null) {
            caChainsAndCrls = new ArrayList<>();
            final List<CAInfo> caInfos = new ArrayList<>(raMasterApiBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
            // First build a mapping of all subjects and their short names
            for (final CAInfo caInfo : caInfos) {
                caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
            }
            for (final CAInfo caInfo : caInfos) {
                if (caInfo.getCertificateChain()!=null && !caInfo.getCertificateChain().isEmpty()) {
                    caChainsAndCrls.add(getCasAndCrls(caInfo));
                }
            }
            removeCaChainsCoveredByLargerChains(caChainsAndCrls);
            sortByHigherLeverCas(caChainsAndCrls);
            hideAlreadyRenderedHigherLevelCas(caChainsAndCrls);
            setRelativePositionInFinalList(caChainsAndCrls);
        }
        return caChainsAndCrls;
    }
    
    private void removeCaChainsCoveredByLargerChains(final List<CaChainAndCrls> caChainsAndCrls) {
        // If two CAs share chain, remove the shorter chain 
        for (final CaChainAndCrls caChainAndCrls1 : new ArrayList<>(caChainsAndCrls)) {
            for (final CaChainAndCrls caChainAndCrls2 : new ArrayList<>(caChainsAndCrls)) {
                // Avoid checking itself
                if (caChainAndCrls1.getCaId()!=caChainAndCrls2.getCaId()) {
                    final int size1 = caChainAndCrls1.getCasAndCrls().size();
                    final int size2 = caChainAndCrls2.getCasAndCrls().size();
                    // Avoid checking if chain length is the same
                    if (size1!=size2) {
                        boolean shareChain = true;
                        for (int i=0; i<Math.min(size1, size2); i++) {
                            if (!caChainAndCrls1.getCasAndCrls().get(i).getSubjectDn().equals(caChainAndCrls2.getCasAndCrls().get(i).getSubjectDn())) {
                                shareChain = false;
                                break;
                            }
                        }
                        // If they share the full chain of the shortest, remove the shortest from list of CAs
                        if (shareChain) {
                            if (size1<size2) {
                                caChainsAndCrls.remove(caChainAndCrls1);
                            } else {
                                caChainsAndCrls.remove(caChainAndCrls2);
                            }
                        }
                    }
                }
            }
        }
    }

    private void sortByHigherLeverCas(final List<CaChainAndCrls> caChainsAndCrls) {
        Collections.sort(caChainsAndCrls, new Comparator<CaChainAndCrls>() {
            @Override
            public int compare(final CaChainAndCrls caChainAndCrls1, final CaChainAndCrls caChainAndCrls2) {
                final int size1 = caChainAndCrls1.getCasAndCrls().size();
                final int size2 = caChainAndCrls2.getCasAndCrls().size();
                // Avoid checking if chain length is the same
                for (int i=0; i<Math.min(size1, size2); i++) {
                    final String name1 = caChainAndCrls1.getCasAndCrls().get(i).getName();
                    final String name2 = caChainAndCrls2.getCasAndCrls().get(i).getName();
                    final int compareTo = name1.compareTo(name2);
                    if (compareTo!=0) {
                        return compareTo;
                    }
                }
                return 0;   // Unreachable
            }
        });
    }

    /** Mark subsequent occurrences of higher level CAs as non-rendered. */
    private void hideAlreadyRenderedHigherLevelCas(final List<CaChainAndCrls> sortedCaChainsAndCrls) {
        List<String> lastNames = new ArrayList<>();
        for (final CaChainAndCrls caChainAndCrls : sortedCaChainsAndCrls) {
            final List<CaAndCrl> caAndCrls = caChainAndCrls.getCasAndCrls();
            for (final CaAndCrl caAndCrl : new ArrayList<>(caAndCrls)) {
                //log.debug("lastNames=" + Arrays.toString(lastNames.toArray()) + " name=" + caAndCrl.getName() + " pos=" + caAndCrl.getPosition());
                if (lastNames.size()-1>=caAndCrl.getPosition()) {
                    if (caAndCrl.getName().equals(lastNames.get(caAndCrl.getPosition()))) {
                        caAndCrls.remove(caAndCrl);
                    } else {
                        lastNames.set(caAndCrl.getPosition(), caAndCrl.getName());
                        lastNames = new ArrayList<>(lastNames.subList(0, caAndCrl.getPosition()+1));
                        break;
                    }
                } else {
                    lastNames.add(caAndCrl.getName());
                }
            }
        }
    }

    private void setRelativePositionInFinalList(List<CaChainAndCrls> sortedCaChainsAndCrls) {
        int i=0;
        for (final CaChainAndCrls caChainAndCrls : sortedCaChainsAndCrls) {
            for (final CaAndCrl caAndCrl : caChainAndCrls.getCasAndCrls()) {
                caAndCrl.setRelativePosition(i++);
            }
        }
    }

    /** @return a representation of a CA's chain. */
    private CaChainAndCrls getCasAndCrls(final CAInfo caInfo) {
        final CaChainAndCrls ret = new CaChainAndCrls(caInfo.getName(), caInfo.getSubjectDN(), caInfo.getCAId());
        int position = caInfo.getCertificateChain().size()-1;
        for (final Certificate caCertificate : caInfo.getCertificateChain()) {
            final String subjectDn = CertTools.getSubjectDN(caCertificate);
            String name = caSubjectToNameMap.get(subjectDn);
            if (name==null) {
                name = subjectDn;
            }
            final CaAndCrl caAndCrl = new CaAndCrl(name, subjectDn, position);
            // Construct links to RFC4387 CRL Download Servlet
            if (caCertificate instanceof X509Certificate) {
                final CRLInfo crlInfoFull = crlSession.getLastCRLInfo(subjectDn, false);
                if (crlInfoFull!=null) {
                    caAndCrl.crlLink = RFC4387_DEFAULT_EJBCA_URL + "?iHash=" + getSubjectPrincipalHashAsUnpaddedBase64((X509Certificate)caCertificate);
                    final CRLInfo crlInfoDelta = crlSession.getLastCRLInfo(subjectDn, true);
                    if (crlInfoDelta!=null) {
                        caAndCrl.deltaCrlLink = RFC4387_DEFAULT_EJBCA_URL + "?iHash=" + getSubjectPrincipalHashAsUnpaddedBase64((X509Certificate)caCertificate) + "&delta=";
                    }
                }
            }
            ret.casAndCrls.add(caAndCrl);
            position--;
        }
        Collections.reverse(ret.casAndCrls);
        return ret;
    }

    /** @return the issuer hash in base64 encoding without padding which is the way RFC4387 search function expects the iHash parameter. */
    private String getSubjectPrincipalHashAsUnpaddedBase64(final X509Certificate x509Certificate) {
        final byte[] hashSubjectX500Principal = CertTools.generateSHA1Fingerprint(x509Certificate.getSubjectX500Principal().getEncoded());
        return new String(Base64.encode(hashSubjectX500Principal)).substring(0, 27).replaceAll("\\+", "%2B");
    }
}
