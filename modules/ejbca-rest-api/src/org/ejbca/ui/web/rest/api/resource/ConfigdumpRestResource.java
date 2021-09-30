package org.ejbca.ui.web.rest.api.resource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.configdump.ConfigdumpException;
import org.ejbca.configdump.ConfigdumpExportResult;
import org.ejbca.configdump.ConfigdumpSetting;
import org.ejbca.configdump.ejb.ConfigdumpSessionLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

import io.swagger.annotations.ApiOperation;

/**
 * JAX-RS resource handling End Entity related requests.
 */
@Path("/v1/configdump")
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ConfigdumpRestResource extends BaseRestResource {

    /** POJO for returning errors from REST api */
    static public class ConfigdumpError {
        private List<String> errors = new ArrayList<>();
        private List<String> warnings = new ArrayList<>();

        public ConfigdumpError() {

        }

        public ConfigdumpError(List<String> errors, List<String> warnings) {
            this.errors = errors;
            this.warnings = warnings;
        }

        public List<String> getErrors() {
            return errors;
        }

        public void setErrors(List<String> errors) {
            this.errors = errors;
        }

        public List<String> getWarnings() {
            return warnings;
        }

        public void setWarnings(List<String> warnings) {
            this.warnings = warnings;
        }
    }

    @EJB
    public ConfigdumpSessionLocal configDump;

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource", notes = "Returns status, API version and EJBCA version.", response = RestResourceStatusRestResponse.class)
    @Override
    public Response status() {
        return super.status();
    }
    
    @GET
    @Path("/")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the configuration in JSON.", notes = "Returns the configdump data in JSON.", response = byte[].class)
    public Response getJsonConfigdump(@Context HttpServletRequest requestContext) throws AuthorizationDeniedException, RestException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIncluded(new HashMap<>());
        settings.setExcluded(new HashMap<>());
        settings.setIncludedAnyType(new ArrayList<>());
        settings.setExcludedAnyType(new ArrayList<>());
        settings.setIgnoreErrors(false);
        settings.setIgnoreWarnings(false);
        settings.setExportDefaults(true);
        settings.setExportExternalCas(true);
        settings.setExportType(ConfigdumpSetting.ExportType.JSON);
        try {
            ConfigdumpExportResult results = configDump.performExport(admin, settings);
            if (results.isSuccessful()) {
                return Response.ok(results.getOutput().get(), MediaType.APPLICATION_JSON)
                        .build();
            } else {
                return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                        .entity(new ConfigdumpError(results.getReportedErrors(), results.getReportedWarnings())).build();
            }
        } catch (ConfigdumpException | IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                    .entity(new ConfigdumpError(Collections.singletonList(e.getLocalizedMessage()), new ArrayList<>())).build();
        }
    }

    @GET
    @Path("/configdump.zip")
    @Produces("application/zip")
    @ApiOperation(value = "Get the configuration as a ZIP file.", notes = "Returns a zip archive of YAML files.", response = byte[].class)
    public Response getZipExport(@Context HttpServletRequest requestContext) throws AuthorizationDeniedException, RestException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIncluded(new HashMap<>());
        settings.setExcluded(new HashMap<>());
        settings.setIncludedAnyType(new ArrayList<>());
        settings.setExcludedAnyType(new ArrayList<>());
        settings.setIgnoreErrors(false);
        settings.setIgnoreWarnings(false);
        settings.setExportDefaults(true);
        settings.setExportExternalCas(true);
        settings.setExportType(ConfigdumpSetting.ExportType.ZIPFILE);
        try {
            ConfigdumpExportResult results = configDump.performExport(admin, settings);
            if (results.isSuccessful()) {
                return Response.ok(results.getOutput().get(), "application/zip").header("Content-Disposition", "attachment; filename=configdump.zip")
                        .build();
            } else {
                return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                        .entity(new ConfigdumpError(results.getReportedErrors(), results.getReportedWarnings())).build();
            }
        } catch (ConfigdumpException | IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                    .entity(new ConfigdumpError(Collections.singletonList(e.getLocalizedMessage()), new ArrayList<>())).build();
        }
    }

}
