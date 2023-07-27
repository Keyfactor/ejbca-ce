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
package org.ejbca.core.protocol.acme.response;

import java.io.Serializable;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;

/**
 * ACME Problem object JSON mapping.
 *
 * https://tools.ietf.org/html/rfc8555#section-6.7
 *
 * (The problem response object in ACME does not strictly follow
 * https://tools.ietf.org/html/rfc7807 "Problem Details for HTTP APIs".)
 *
 */
public class AcmeProblemResponse implements Serializable {

    private static final long serialVersionUID = 1L;
    
    @XmlElement(name="type", required=true)
    private String type;
    @XmlElement(name="title", required=false)
    private String title = null;
    @XmlElement(name="status", required=false)
    private Integer status = null;
    @XmlElement(name="detail", required=false)
    private String detail = null;
    /** For the userActionRequired error. */
    @XmlElement(name="instance", required=false)
    private String instance = null;
    /** For the badSignatureAlgorithm error we "MUST include an "algorithms" field with an array of supported "alg" values".*/
    @XmlElement(name="algorithms", required=false)
    private List<String> algorithms;

    private String headerLink = null;
    private String headerLocation = null;

    public AcmeProblemResponse() {}

    public AcmeProblemResponse(final AcmeProblem acmeProblem) {
        setType(acmeProblem.getType());
        setDetail(acmeProblem.getDetail());
    }
    
    public AcmeProblemResponse(final AcmeProblem acmeProblem, final String detail) {
        setType(acmeProblem.getType());
        setDetail(detail);
    }

    
    public String getType() { return type; }
    
    public void setType(String type) { this.type = type; }
    
    public String getTitle() { return title; }
    
    public void setTitle(String title) { this.title = title; }
    
    public Integer getStatus() { return status; }
    
    public void setStatus(Integer status) { this.status = status; }
    
    public String getDetail() { return detail; }
    
    public void setDetail(String detail) { this.detail = detail; }
    
    public String getInstance() { return instance; }
    
    public void setInstance(String instance) { this.instance = instance; }
    
    public List<String> getAlgorithms() { return algorithms; }
    
    public void setAlgorithms(List<String> algorithms) { this.algorithms = algorithms; }

    
    public String getHeaderLink() { return headerLink; }
    
    public void setHeaderLink(String headerLink) { this.headerLink = headerLink; }
    
    public String getHeaderLocation() { return headerLocation; }
    
    public void setHeaderLocation(String headerLocation) { this.headerLocation = headerLocation; }
    
    public void setHeaderLink(final String href, final String rel) {
        setHeaderLink("href=\"" + href + "\", rel=\"" + rel + "\"");
    }
}
