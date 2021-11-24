/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
