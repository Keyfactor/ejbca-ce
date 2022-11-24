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
package org.cesecore.certificates.ca.kfenroll;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.MutablePair;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;

public class ProxyCaInfo extends CAInfo {
    private static final long serialVersionUID = -2889579653109530259L;
    
    private static final String EST_CONFIG_SUFFIX = "Est";

    public static final String ENROLL_WITH_CSR_URL = "enrollWithCsrUrl";
    public static final String HEADERS = "headers";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String UPSTREAM_CA = "upstreamCertificateAuthority";
    public static final String TEMPLATE = "template";
    public static final String SANS = "sans";
    public static final String AUTHENTICATION_CODE_PLACEHOLDER_VALUE = "placeholder";
    private String enrollWithCsrUrl;
    private List<MutablePair<String, String>> headers;
    private String username;
    private String password;
    private String upstreamCertificateAuthority; // upstream certificate authority
    private String template;
    private String sans; // SANs in JSON format

    public ProxyCaInfo() {
        this.signedby = SIGNEDBYEXTERNALCA;
        this.status = CAConstants.CA_EXTERNAL;
        setApprovals(null);
    }

    public ProxyCaInfo(final String name, final String description, final String subjectDn, final int status, Collection<Integer> validators,
                       final String enrollByCsrUrl, final List<MutablePair<String, String>> headers, final String username, final String password,
                       final String ca, final String template, final String sans) {
        this.name = name;
        this.description = description;
        this.subjectdn = subjectDn;
        this.status = status;
        this.validators = validators;
        this.enrollWithCsrUrl = enrollByCsrUrl;
        this.headers = headers;
        this.username = username;
        this.password = password;
        this.upstreamCertificateAuthority = ca; // upstream certificate authority
        this.template = template;
        this.sans = sans; // SANs in JSON format
        this.signedby = SIGNEDBYEXTERNALCA;
        this.status = CAConstants.CA_EXTERNAL;
        setApprovals(null);
    }

    public String getEnrollWithCsrUrl() {
        return enrollWithCsrUrl;
    }

    public void setEnrollWithCsrUrl(String enrollWithCsrUrl) {
        this.enrollWithCsrUrl = enrollWithCsrUrl;
    }

    public List<MutablePair<String, String>> getHeaders() {
        return headers;
    }
    
    public Map<String, String> getHeaderMap() {
        Map<String, String> header = new HashMap<>();
        for (MutablePair<String, String> pair : getHeaders()) {
            header.put(pair.getKey(), pair.getValue());
        }
        return header;
    }
    
    public String getHeadersString() {
        StringBuilder headers = new StringBuilder();
        for (MutablePair<String, String> pair : getHeaders()) {
            headers.append(pair.getKey());
            headers.append(": ");
            headers.append(pair.getValue());
            headers.append("; ");
        }
        return headers.toString();
    }

    public void setHeaders(List<MutablePair<String, String>> headers) {
        this.headers = headers;
    }
    
    public void setHeadersString(String allHeaders) {
        this.headers = splitHeaderString(allHeaders);
    }
    
    public static List<MutablePair<String, String>> splitHeaderString(String allHeaders) {
        List<MutablePair<String, String>> headerList = new ArrayList<>();
        if(StringUtils.isEmpty(allHeaders)) {
            return headerList;
        }
        String[] headers = allHeaders.split(";");
        for(String header: headers) {
            if(StringUtils.isBlank(header)) {
                continue; // last entry
            }
            String[] headerParts = header.split(":");
            if(headerParts.length!=2) {
                throw new IllegalArgumentException("KeyFactor CA headers are malformed, "
                        + "each header key value should be split with ':'"
                        + "e.g. header1: value1; header2: value2; " + header + ", " + allHeaders);
            }
            headerList.add(new MutablePair<String, String>(headerParts[0].trim(), headerParts[1].trim()));
        }
        return headerList;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }
    
    public String getHiddenPassword(){
        return AUTHENTICATION_CODE_PLACEHOLDER_VALUE;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    public void setHiddenPassword(String password) {
        this.password = password;
    }

    public String getUpstreamCertificateAuthority() {
        return upstreamCertificateAuthority;
    }

    public void setUpstreamCertificateAuthority(String upstreamCertificateAuthority) {
        this.upstreamCertificateAuthority = upstreamCertificateAuthority;
    }

    public String getTemplate() {
        return template;
    }

    public void setTemplate(String template) {
        this.template = template;
    }

    public String getSans() {
        return sans;
    }

    public void setSans(String sans) {
        this.sans = sans;
    }

    @Override
    public boolean isExpirationInclusive() {
        return false;
    }
    
    public String getEstConfigAlias() {
        return this.name + EST_CONFIG_SUFFIX;
    }

    public static class ProxyCaInfoBuilder {
        // Common Field from CAINFO.
        private int caId;
        private String name;
        private String subjectDn;
        private String description = "";
        private int status;
        private Date updateTime;
        private Date expireTime;
        private Collection<Integer> validators = new ArrayList<>();

        // Proxy Ca specific fields
        private String enrollWithCsrUrl;
        private List<MutablePair<String, String>> headers;
        private String username;
        private String password;
        private String ca; // upstream certificate authority
        private String template;
        private String sans; // SANs in JSON format

        public ProxyCaInfo.ProxyCaInfoBuilder setCaId(int caId) {
            this.caId = caId;
            return this;
        }

        /**
         * @param name the name of the CA shown in EJBCA, can be changed by the user
         */
        public ProxyCaInfo.ProxyCaInfoBuilder setName(String name) {
            this.name = name;
            return this;
        }

        /**
         * @param subjectDn proxy subject DN
         */
        public ProxyCaInfo.ProxyCaInfoBuilder setSubjectDn(String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setDescription(String description) {
            this.description = description;
            return this;
        }

        /**
         * @param status the operational status of the CA, one of the constants in {@link CAConstants}
         */
        public ProxyCaInfo.ProxyCaInfoBuilder setStatus(int status) {
            this.status = status;
            return this;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setUpdateTime(Date updateTime) {
            this.updateTime = updateTime;
            return this;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setExpireTime(Date expireTime) {
            this.expireTime = expireTime;
            return this;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setValidators(Collection<Integer> validators) {
            this.validators = validators;
            return this;
        }

        public String getEnrollWithCsrUrl() {
            return enrollWithCsrUrl;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setEnrollWithCsrUrl(String enrollWithCsrUrl) {
            this.enrollWithCsrUrl = enrollWithCsrUrl;
            return this;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setHeaders(List<MutablePair<String, String>> headers) {
            this.headers = headers;
            return this;
        }
        
        public ProxyCaInfo.ProxyCaInfoBuilder setHeaders(String allHeaders) {
            this.headers = splitHeaderString(allHeaders);
            return this;
        }
        
        public ProxyCaInfo.ProxyCaInfoBuilder setHeaders(LinkedHashMap<String, String> headers) {
            this.headers = new ArrayList<>();
            for(Entry<String, String> header: headers.entrySet()) {
                this.headers.add(new MutablePair<String, String>(header.getKey(), header.getValue()));
            }
            return this;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setUsername(String username) {
            this.username = username;
            return this;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setPassword(String password) {
            this.password = password;
            return this;
        }

        public String getCa() {
            return ca;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setCa(String ca) {
            this.ca = ca;
            return this;
        }

        public String getTemplate() {
            return template;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setTemplate(String template) {
            this.template = template;
            return this;
        }

        public String getSans() {
            return sans;
        }

        public ProxyCaInfo.ProxyCaInfoBuilder setSans(String sans) {
            this.sans = sans;
            return this;
        }

        public ProxyCaInfo build() {
            ProxyCaInfo caInfo = new ProxyCaInfo(name, description, subjectDn, status, validators, enrollWithCsrUrl, headers, username, password, ca, template, sans);

            caInfo.setCAId(caId);
            caInfo.setUpdateTime(updateTime);

            // This fields are usually not updated in UI, only needed when creating
            // a new CA. They are not included in buildForUpdate() method below.
            caInfo.setCAType(CAInfo.CATYPE_PROXY);
            // caInfo.setSignedBy(signedBy);
            caInfo.setExpireTime(expireTime);

            return caInfo;
        }

        public ProxyCaInfo buildForUpdate() {
            ProxyCaInfo caInfo = new ProxyCaInfo(name, description, subjectDn, status, validators, enrollWithCsrUrl, headers, username, password, ca, template, sans);

            caInfo.setCAId(caId);
            caInfo.setUpdateTime(new Date());
            return caInfo;
        }
        
    }    

}
