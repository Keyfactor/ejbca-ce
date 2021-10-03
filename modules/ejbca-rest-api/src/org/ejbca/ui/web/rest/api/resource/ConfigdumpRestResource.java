/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.resource;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.configdump.ConfigdumpException;
import org.ejbca.configdump.ConfigdumpExportResult;
import org.ejbca.configdump.ConfigdumpImportResult;
import org.ejbca.configdump.ConfigdumpPattern;
import org.ejbca.configdump.ConfigdumpPattern.IllegalWildCardSyntaxException;
import org.ejbca.configdump.ConfigdumpSetting;
import org.ejbca.configdump.ConfigdumpSetting.ItemType;
import org.ejbca.configdump.ConfigdumpSetting.ProcessingMode;
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

    private static final Logger log = Logger.getLogger(ConfigdumpRestResource.class);

    /** POJO for returning errors from REST api */
    static public class ConfigdumpError {
        private List<String> errors = new ArrayList<>();
        private List<String> warnings = new ArrayList<>();

        public ConfigdumpError() {

        }

        public ConfigdumpError(final List<String> errors, final List<String> warnings) {
            this.errors = errors;
            this.warnings = warnings;
        }

        public List<String> getErrors() {
            return errors;
        }

        public void setErrors(final List<String> errors) {
            this.errors = errors;
        }

        public List<String> getWarnings() {
            return warnings;
        }

        public void setWarnings(final List<String> warnings) {
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
    @Path("/export")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the configuration in JSON.", notes = "Returns the configdump data in JSON.", response = byte[].class)
    public Response getJsonConfigdump(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            @DefaultValue("false") @QueryParam("ignoreerrors") final boolean ignoreErrors,
            @DefaultValue("false") @QueryParam("defaults") final boolean exportDefaults,
            @DefaultValue("false") @QueryParam("externalcas") final boolean exportExternalCas, 
            @QueryParam("include") final Set<String> includeStrings,
            @QueryParam("exclude") final Set<String> excludeStrings
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException {

        // includeStrings and excludeStrings have the same format as the CLI command.
        final List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
        final List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();
        parseIncludeExclude(includeStrings, includedAnyType, included);
        parseIncludeExclude(excludeStrings, excludedAnyType, excluded);

        // set settings
        final ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIncluded(included);
        settings.setExcluded(excluded);
        settings.setIncludedAnyType(includedAnyType);
        settings.setExcludedAnyType(excludedAnyType);
        settings.setIgnoreErrors(ignoreErrors);
        settings.setIgnoreWarnings(true);
        settings.setExportDefaults(exportDefaults);
        settings.setExportExternalCas(exportExternalCas);
        settings.setConfigdumpType(ConfigdumpSetting.ConfigdumpType.JSON);

        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            final ConfigdumpExportResult results = configDump.performExport(admin, settings);
            if (results.isSuccessful()) {
                return Response.ok(results.getOutput().get(), MediaType.APPLICATION_JSON).build();
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
    @Path("export/{type}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the configuration for type in JSON.", notes = "Returns the configdump data in JSON.", response = byte[].class)
    public Response getJsonConfigdumpForType(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            @PathParam("type") final String itemTypeString,
            @DefaultValue("false") @QueryParam("ignoreerrors") final boolean ignoreErrors,
            @DefaultValue("false") @QueryParam("defaults") final boolean exportDefaults,
            @DefaultValue("false") @QueryParam("externalcas") final boolean exportExternalCas
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException {
        // includeStrings and excludeStrings have the same format as the CLI command.
        final List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
        final List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();

        ItemType itemType;
        try {
            itemType = fromSubdirectory(itemTypeString).orElseGet(() -> ItemType.valueOf(itemTypeString));
        } catch (final IllegalArgumentException e) {
            return Response.status(Status.NOT_FOUND).build();
        }

        // exclude everything other than the type
        parseIncludeExclude(setOf("*:*"), excludedAnyType, excluded);
        parseIncludeExclude(setOf(itemType.toString() + ":*"), includedAnyType, included);

        // set settings
        final ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIncluded(included);
        settings.setExcluded(excluded);
        settings.setIncludedAnyType(includedAnyType);
        settings.setExcludedAnyType(excludedAnyType);
        settings.setIgnoreErrors(ignoreErrors);
        settings.setIgnoreWarnings(true);
        settings.setExportDefaults(exportDefaults);
        settings.setExportExternalCas(exportExternalCas);
        settings.setConfigdumpType(ConfigdumpSetting.ConfigdumpType.JSON);

        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            final ConfigdumpExportResult results = configDump.performExport(admin, settings);
            if (results.isSuccessful()) {
                return Response.ok(results.getOutput().get(), MediaType.APPLICATION_JSON).build();
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
    @Path("export/{type}/{setting}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the configuration for a type and setting in JSON.", notes = "Returns the configdump data in JSON.", response = byte[].class)
    public Response getJsonConfigdumpForTypeAndSetting(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            @PathParam("type") final String itemTypeString,
            @PathParam("setting") final String settingName,
            @DefaultValue("false") @QueryParam("ignoreerrors") final boolean ignoreErrors,
            @DefaultValue("false") @QueryParam("defaults") final boolean exportDefaults
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException {
        // includeStrings and excludeStrings have the same format as the CLI command.
        final List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
        final List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();

        ItemType itemType;
        try {
            itemType = fromSubdirectory(itemTypeString).orElseGet(() -> ItemType.valueOf(itemTypeString));
        } catch (final IllegalArgumentException e) {
            return Response.status(Status.NOT_FOUND).build();
        }

        // exclude everything other than the type
        parseIncludeExclude(setOf("*:*"), excludedAnyType, excluded);
        parseIncludeExclude(setOf(itemType.toString() + ":" + settingName), includedAnyType, included);

        // set settings
        final ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIncluded(included);
        settings.setExcluded(excluded);
        settings.setIncludedAnyType(includedAnyType);
        settings.setExcludedAnyType(excludedAnyType);
        settings.setIgnoreErrors(ignoreErrors);
        settings.setIgnoreWarnings(true);
        settings.setExportDefaults(exportDefaults);

        // always make this true - otherwise if an external CA were in settingName it wouldn't be returned unless
        // externalcas is also set to true.
        settings.setExportExternalCas(true);
        settings.setConfigdumpType(ConfigdumpSetting.ConfigdumpType.JSON);

        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            final ConfigdumpExportResult results = configDump.performExport(admin, settings);
            if (results.isNothingExported()) {
                return Response.status(Status.NOT_FOUND).build();
            } else if (results.isSuccessful()) {
                return Response.ok(results.getOutput().get(), MediaType.APPLICATION_JSON).build();
            } else {
                return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                        .entity(new ConfigdumpError(results.getReportedErrors(), results.getReportedWarnings())).build();
            }
        } catch (ConfigdumpException | IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                    .entity(new ConfigdumpError(Collections.singletonList(e.getLocalizedMessage()), new ArrayList<>())).build();
        }
    }

    private void parseIncludeExclude(final Set<String> includeStrings, final List<ConfigdumpPattern> includeAnyType,
            final Map<ItemType, List<ConfigdumpPattern>> include) {
        for (final String includeString : includeStrings) {
            try {
                ConfigdumpPattern.parseIncludeExcludeString(include, includeAnyType, includeString);
            } catch (final IllegalWildCardSyntaxException e) {
                final Response response = Response.status(Status.BAD_REQUEST).entity(includeString + "is not a valid include/exclude type").build();
                throw new WebApplicationException(response);
            }
        }
    }

    @GET
    @Path("/configdump.zip")
    @Produces("application/zip")
    @ApiOperation(value = "Get the configuration as a ZIP file.", notes = "Returns a zip archive of YAML files.", response = byte[].class)
    public Response getZipExport(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            @DefaultValue("false") @QueryParam("ignoreerrors") final boolean ignoreErrors,
            @DefaultValue("false") @QueryParam("defaults") final boolean exportDefaults,
            @DefaultValue("false") @QueryParam("externalcas") final boolean exportExternalCas, 
            @QueryParam("include") final Set<String> includeStrings,
            @QueryParam("exclude") final Set<String> excludeStrings
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException {

        // includeStrings and excludeStrings have the same format as the CLI command.
        final List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
        final List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
        final Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();
        parseIncludeExclude(includeStrings, includedAnyType, included);
        parseIncludeExclude(excludeStrings, excludedAnyType, excluded);

        // set settings
        final ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIncluded(included);
        settings.setExcluded(excluded);
        settings.setIncludedAnyType(includedAnyType);
        settings.setExcludedAnyType(excludedAnyType);
        settings.setIgnoreErrors(ignoreErrors);
        settings.setIgnoreWarnings(true);
        settings.setExportDefaults(exportDefaults);
        settings.setExportExternalCas(exportExternalCas);
        settings.setConfigdumpType(ConfigdumpSetting.ConfigdumpType.ZIPFILE);
        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            final ConfigdumpExportResult results = configDump.performExport(admin, settings);
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

    @POST
    @Path("/")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Put the configuration as a ZIP file.", response = ConfigdumpImportResults.class)
    public ConfigdumpImportResults putZipImport(@Context final HttpServletRequest requestContext, @FormParam("zipfile") final File zipfile)
            throws AuthorizationDeniedException, FileUploadException, RestException {

        // parse the input request as a multi-part json import
        final DiskFileItemFactory fileItemFactory = new DiskFileItemFactory();
        fileItemFactory.setSizeThreshold(1_000_000);
        final List<FileItem> parseRequest = new ServletFileUpload(fileItemFactory).parseRequest(requestContext);
        final FileItem zipfileItem = parseRequest.stream().findFirst().orElseThrow(() -> new BadRequestException("No file upload found."));

        byte[] zipdata;
        try {
            zipdata = IOUtils.toByteArray(zipfileItem.getInputStream());
        } catch (final IOException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "zipfile data not read:" + e.getLocalizedMessage());
        }

        log.debug("Input file = " + zipfile);

        final ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIgnoreErrors(false);
        settings.setIgnoreWarnings(true);
        settings.setProcessingMode(ProcessingMode.RUN);
        settings.setConfigdumpType(ConfigdumpSetting.ConfigdumpType.ZIPFILE);
        settings.setImportData(zipdata);

        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            final ConfigdumpImportResult results = configDump.performImport(admin, settings);
            if (results.isSuccessful()) {
                return new ConfigdumpImportResults();
            } else {
                return new ConfigdumpImportResults(results.getReportedErrors(), results.getReportedWarnings());
            }
        } catch (ConfigdumpException | IOException e) {
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Unable to import zipfile:" + e);
        }

    }

    static private Set<String> setOf(final String s) {
        final HashSet<String> strings = new HashSet<>();
        strings.add(s);
        return strings;
    }

    private static Optional<ItemType> fromSubdirectory(final String s) {
        for (final ItemType itemType : ItemType.values()) {
            if (s.equals(itemType.getSubdirectory())) {
                return Optional.of(itemType);
            }
        }
        return Optional.empty();
    }
}
