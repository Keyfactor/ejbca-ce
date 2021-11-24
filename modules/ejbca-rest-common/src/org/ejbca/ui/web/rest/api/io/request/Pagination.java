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
 * A class representing pagination parameters with a page size and a current page.
 */
@JsonPropertyOrder({ "page_size", "current_page" })
public class Pagination {
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("page_size")
    private int pageSize;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("current_page")
    private int currentPage;

    public Pagination() {
        super();
    }

    public Pagination(final int pageSize, final int currentPage) {
        super();
        this.pageSize = pageSize;
        this.currentPage = currentPage;
    }

    public int getPageSize() {
        return pageSize;
    }

    public void setPageSize(final int pageSize) {
        this.pageSize = pageSize;
    }

    public int getCurrentPage() {
        return currentPage;
    }

    public void setCurrentPage(final int currentPage) {
        this.currentPage = currentPage;
    }
        
}
