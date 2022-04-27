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
package org.ejbca.ui.web.rest.api.io.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * JSON output for pagination summary.
 */
@JsonPropertyOrder({ "page_size", "current_page", "total_certs" })
public class PaginationSummary {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("total_certs")
    private Long totalCerts;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("page_size")
    private Integer pageSize;
    
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("current_page")
    private Integer currentPage;

    public PaginationSummary() {
        super();
    }

    public PaginationSummary(final Long totalCerts) {
        super();
        this.totalCerts = totalCerts;
    }
    
    public PaginationSummary(final Integer pageSize, final Integer currentPage) {
        super();
        this.pageSize = pageSize;
        this.currentPage = currentPage;
    }

    public Long getTotalCerts() {
        return totalCerts;
    }

    public void setTotalCerts(final Long totalCerts) {
        this.totalCerts = totalCerts;
    }

    public Integer getPageSize() {
        return pageSize;
    }

    public void setPageSize(final Integer pageSize) {
        this.pageSize = pageSize;
    }

    public Integer getCurrentPage() {
        return currentPage;
    }

    public void setCurrentPage(final Integer currentPage) {
        this.currentPage = currentPage;
    }

//    /**
//     * Returns the number of pages starting at 1 or null if totalCerts is null.
//     * 
//     * @return the number of pages.
//     */
//    @JsonInclude(JsonInclude.Include.NON_NULL)
//    @JsonProperty("pages")
//    public Integer getPages() {
//        return (totalCerts != null && pageSize != null) ? (int) (totalCerts / pageSize) + 1 : null;
//    }

}
