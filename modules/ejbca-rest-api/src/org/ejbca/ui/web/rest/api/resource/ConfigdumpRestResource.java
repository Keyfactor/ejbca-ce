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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
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
import org.ejbca.configdump.ConfigdumpItem;
import org.ejbca.configdump.ConfigdumpPattern;
import org.ejbca.configdump.ConfigdumpPattern.IllegalWildCardSyntaxException;
import org.ejbca.configdump.ConfigdumpSetting;
import org.ejbca.configdump.ConfigdumpSetting.ItemProblem;
import org.ejbca.configdump.ConfigdumpSetting.ItemType;
import org.ejbca.configdump.ConfigdumpSetting.NonInteractiveMode;
import org.ejbca.configdump.ConfigdumpSetting.OverwriteMode;
import org.ejbca.configdump.ConfigdumpSetting.ProcessingMode;
import org.ejbca.configdump.ConfigdumpSetting.ResolveReferenceMode;
import org.ejbca.configdump.ejb.ConfigdumpSessionLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * JAX-RS resource handling End Entity related requests.
 */
@Path("/v1/configdump")
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ConfigdumpRestResource extends BaseRestResource {

    public enum ResolveMissingReferences {
        abort, skip, useDefault
    }

    public enum Overwrite {
        yes, skip, abort
    }

    private static final Logger log = Logger.getLogger(ConfigdumpRestResource.class);

    @EJB
    public ConfigdumpSessionLocal configDump;

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource", notes = "Returns status, API version and EJBCA version.", response = RestResourceStatusRestResponse.class)
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public Response status() {
        return super.status();
    }

    @GET
    @Path("/")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the configuration in JSON.", notes = "Returns the configdump data in JSON.", response = byte[].class)
    public Response getJsonConfigdump(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            
            @ApiParam("Print a warning instead of aborting and throwing an exception on errors.")
            @DefaultValue("false") @QueryParam("ignoreerrors") 
            final boolean ignoreErrors,
            
            @ApiParam("Also include fields having the default value.")
            @DefaultValue("false") @QueryParam("defaults")
            final boolean exportDefaults,
            
            @ApiParam("Enables export of external CAs (i.e. CAs where there's only a certificate and"
                    + " nothing else)")
            @DefaultValue("false") @QueryParam("externalcas")
            final boolean exportExternalCas, 
            
            @ApiParam("Names of items/types to include in the export. The syntax is identical to that"
                    + " of exclude. For items of types that aren't listed, everything is included.")
            @QueryParam("include")
            final Set<String> includeStrings,
            
            @ApiParam("Names of items/types to exclude in the export, separated by semicolon. Type and"
                    + " name is separated by a colon, and wildcards \"\\*\" are allowed. Both are"
                    + " case-insensitive. E.g. exclude=\"\\*:Example CA;cryptotoken:Example\\*;"
                    + "systemconfiguration:\\*\".\n"
                    + "\n"
                    + "Supported types are: ACMECONFIG/acme-config, CA/certification-authorities, "
                    + " CRYPTOTOKEN/crypto-tokens, PUBLISHER/publishers, APPROVALPROFILE/approval-profiles,"
                    + " CERTPROFILE/certificate-profiles, EEPROFILE/end-entity-profiles, SERVICE/services,"
                    + " ROLE/admin-roles, KEYBINDING/internal-key-bindings, ADMINPREFS/admin-preferences,"
                    + " OCSPCONFIG/ocsp-configuration, PEERCONNECTOR/peer-connectors, SCEPCONFIG/scep-config,"
                    + " CMPCONFIG/cmp-config, ESTCONFIG/est-config, VALIDATOR/validators, CTLOG/ct-logs,"
                    + " EXTENDEDKEYUSAGE/extended-key-usage, CERTEXTENSION/custom-certificate-extensions, "
                    + " OAUTHKEY/trusted-oauth-providers")
            @QueryParam("exclude")
            final Set<String> excludeStrings
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException, IllegalWildCardSyntaxException {

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
            if (results.isSuccessful() || ignoreErrors) {
                return Response.ok(results.getOutput().get(), MediaType.APPLICATION_JSON).build();
            } else {
                return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                        .entity(new ConfigdumpResults(results.getReportedErrors(), results.getReportedWarnings())).build();
            }
        } catch (ConfigdumpException | IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                    .entity(new ConfigdumpResults(Collections.singletonList(e.getLocalizedMessage()), new ArrayList<>())).build();
        }
    }

    @GET
    @Path("{type}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the configuration for type in JSON.", notes = "Returns the configdump data in JSON.", response = byte[].class)
    public Response getJsonConfigdumpForType(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            
            @ApiParam("Configuration type to export.\n"
                    + "\n"
                    + "Supported types are: ACMECONFIG/acme-config, CA/certification-authorities, "
                    + " CRYPTOTOKEN/crypto-tokens, PUBLISHER/publishers, APPROVALPROFILE/approval-profiles,"
                    + " CERTPROFILE/certificate-profiles, EEPROFILE/end-entity-profiles, SERVICE/services,"
                    + " ROLE/admin-roles, KEYBINDING/internal-key-bindings, ADMINPREFS/admin-preferences,"
                    + " OCSPCONFIG/ocsp-configuration, PEERCONNECTOR/peer-connectors, SCEPCONFIG/scep-config,"
                    + " CMPCONFIG/cmp-config, ESTCONFIG/est-config, VALIDATOR/validators, CTLOG/ct-logs,"
                    + " EXTENDEDKEYUSAGE/extended-key-usage, CERTEXTENSION/custom-certificate-extensions, "
                    + " OAUTHKEY/trusted-oauth-providers")
            @PathParam("type") final String itemTypeString,
            
            @ApiParam("Print a warning instead of aborting and throwing an exception on errors.")
            @DefaultValue("false") @QueryParam("ignoreerrors") final boolean ignoreErrors,
            
            @ApiParam("Also include fields having the default value.")
            @DefaultValue("false") @QueryParam("defaults") final boolean exportDefaults,
            
            @ApiParam("Enables export of external CAs (i.e. CAs where there's only a certificate and"
                    + " nothing else)")
            @DefaultValue("false") @QueryParam("externalcas") final boolean exportExternalCas
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException, IllegalWildCardSyntaxException {
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
            if (results.isSuccessful() || ignoreErrors) {
                return Response.ok(results.getOutput().get(), MediaType.APPLICATION_JSON).build();
            } else {
                return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                        .entity(new ConfigdumpResults(results.getReportedErrors(), results.getReportedWarnings())).build();
            }
        } catch (ConfigdumpException | IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                    .entity(new ConfigdumpResults(Collections.singletonList(e.getLocalizedMessage()), new ArrayList<>())).build();
        }
    }

    @GET
    @Path("{type}/{setting}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the configuration for a type and setting in JSON.", notes = "Returns the configdump data in JSON.", response = byte[].class)
    public Response getJsonConfigdumpForTypeAndSetting(
    //@formatter:off
            @Context final HttpServletRequest requestContext,

            @ApiParam("Configuration type to export.\n"
                    + "\n"
                    + "Supported types are: ACMECONFIG/acme-config, CA/certification-authorities, "
                    + " CRYPTOTOKEN/crypto-tokens, PUBLISHER/publishers, APPROVALPROFILE/approval-profiles,"
                    + " CERTPROFILE/certificate-profiles, EEPROFILE/end-entity-profiles, SERVICE/services,"
                    + " ROLE/admin-roles, KEYBINDING/internal-key-bindings, ADMINPREFS/admin-preferences,"
                    + " OCSPCONFIG/ocsp-configuration, PEERCONNECTOR/peer-connectors, SCEPCONFIG/scep-config,"
                    + " CMPCONFIG/cmp-config, ESTCONFIG/est-config, VALIDATOR/validators, CTLOG/ct-logs,"
                    + " EXTENDEDKEYUSAGE/extended-key-usage, CERTEXTENSION/custom-certificate-extensions, "
                    + " OAUTHKEY/trusted-oauth-providers")
            @PathParam("type") final String itemTypeString,
            
            @ApiParam("Individual configuration name to export")
            @PathParam("setting") final String settingName,
            
            @ApiParam("Print a warning instead of aborting and throwing an exception on errors.")
            @DefaultValue("false") @QueryParam("ignoreerrors") final boolean ignoreErrors,
            
            @ApiParam("Also include fields having the default value.")
            @DefaultValue("false") @QueryParam("defaults") final boolean exportDefaults
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException, IllegalWildCardSyntaxException {
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
            } else if (results.isSuccessful() || ignoreErrors) {
                return Response.ok(results.getOutput().get(), MediaType.APPLICATION_JSON).build();
            } else {
                return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                        .entity(new ConfigdumpResults(results.getReportedErrors(), results.getReportedWarnings())).build();
            }
        } catch (ConfigdumpException | IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                    .entity(new ConfigdumpResults(Collections.singletonList(e.getLocalizedMessage()), new ArrayList<>())).build();
        }
    }

    private void parseIncludeExclude(final Set<String> patternStrings, final List<ConfigdumpPattern> noTypePatterns,
            final Map<ItemType, List<ConfigdumpPattern>> typePatterns) throws IllegalWildCardSyntaxException {
        for (final String patternString : patternStrings) {
            ConfigdumpPattern.parseIncludeExcludeString(typePatterns, noTypePatterns, patternString);
        }
    }

    @GET
    @Path("/configdump.zip")
    @Produces("application/zip")
    @ApiOperation(value = "Get the configuration as a ZIP file.", notes = "Returns a zip archive of YAML files.", response = byte[].class)
    public Response getZipExport(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            @ApiParam("Print a warning instead of aborting and throwing an exception on errors.")
            @DefaultValue("false") @QueryParam("ignoreerrors") 
            final boolean ignoreErrors,
            
            @ApiParam("Also include fields having the default value.")
            @DefaultValue("false") @QueryParam("defaults")
            final boolean exportDefaults,
            
            @ApiParam("Enables export of external CAs (i.e. CAs where there's only a certificate and"
                    + " nothing else)")
            @DefaultValue("false") @QueryParam("externalcas")
            final boolean exportExternalCas, 

            @ApiParam("Names of items/types to include in the export. The syntax is identical to that"
                    + " of exclude. For items of types that aren't listed, everything is included.")
            @QueryParam("include")
            final Set<String> includeStrings,
            
            @ApiParam("Names of items/types to exclude in the export, separated by semicolon. Type and"
                    + " name is separated by a colon, and wildcards \"\\*\" are allowed. Both are"
                    + " case-insensitive. E.g. exclude=\"\\*:Example CA;cryptotoken:Example\\*;"
                    + "systemconfiguration:\\*\".\n"
                    + "\n"
                    + "Supported types are: ACMECONFIG/acme-config, CA/certification-authorities, "
                    + " CRYPTOTOKEN/crypto-tokens, PUBLISHER/publishers, APPROVALPROFILE/approval-profiles,"
                    + " CERTPROFILE/certificate-profiles, EEPROFILE/end-entity-profiles, SERVICE/services,"
                    + " ROLE/admin-roles, KEYBINDING/internal-key-bindings, ADMINPREFS/admin-preferences,"
                    + " OCSPCONFIG/ocsp-configuration, PEERCONNECTOR/peer-connectors, SCEPCONFIG/scep-config,"
                    + " CMPCONFIG/cmp-config, ESTCONFIG/est-config, VALIDATOR/validators, CTLOG/ct-logs,"
                    + " EXTENDEDKEYUSAGE/extended-key-usage, CERTEXTENSION/custom-certificate-extensions, "
                    + " OAUTHKEY/trusted-oauth-providers")
            @QueryParam("exclude")
            final Set<String> excludeStrings
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException, IllegalWildCardSyntaxException {

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
            if (results.isSuccessful() || ignoreErrors) {
                return Response.ok(results.getOutput().get(), "application/zip").header("Content-Disposition", "attachment; filename=configdump.zip")
                        .build();
            } else {
                return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                        .entity(new ConfigdumpResults(results.getReportedErrors(), results.getReportedWarnings())).build();
            }
        } catch (ConfigdumpException | IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON)
                    .entity(new ConfigdumpResults(Collections.singletonList(e.getLocalizedMessage()), new ArrayList<>())).build();
        }
    }

    @POST
    @Path("/configdump.zip")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Put the configuration as a ZIP file.", response = ConfigdumpResults.class)
    public ConfigdumpResults postZipImport(
    //@formatter:off
            @Context final HttpServletRequest requestContext, 
            
            @ApiParam("A zipfile containing directories of YAML files.") 
            @FormParam("zipfile") final File zipfile,
            
            @ApiParam("Add to warnings instead of aborting on errors.") 
            @DefaultValue("false") @FormParam("ignoreerrors") boolean ignoreErrors,
            
            @ApiParam("Generate initial certificate for CAs on import") 
            @DefaultValue("false") @FormParam("initialize") boolean initializeCas,
            
            @ApiParam("Continue on errors. Default is to abort.")
            @DefaultValue("false") @FormParam("continue") boolean continueOnError,
            
            @ApiParam("How to handle already existing configuration. Options are abort,skip,yes") 
            @DefaultValue("abort") @FormParam("overwrite") 
            Overwrite overwrite,
            
            @ApiParam("How to resolve missing references. Options are abort,skip,default") 
            @DefaultValue("abort") @FormParam("resolve") ResolveMissingReferences resolveMissingReferences

            //@formatter:on
    ) throws AuthorizationDeniedException, FileUploadException, RestException {

        // parse the input request as a multi-part json import
        final DiskFileItemFactory fileItemFactory = new DiskFileItemFactory();
        fileItemFactory.setSizeThreshold(1_000_000);
        final List<FileItem> parseRequest = new ServletFileUpload(fileItemFactory).parseRequest(requestContext);
        FileItem zipfileItem = null;

        // all those FormParams above are just for Swagger - the default JavaEE rest library has 
        // no support for multi-part form data parameters, so we need to parse them ourselves here.
        for (final FileItem item : parseRequest) {
            if (item.isFormField()) {
                switch (item.getFieldName()) {
                case "overwrite":
                    overwrite = read(item, Overwrite.class);
                    break;
                case "resolve":
                    resolveMissingReferences = read(item, ResolveMissingReferences.class);
                    break;
                case "ignoreerrors":
                    ignoreErrors = readBoolean(item);
                    break;
                case "initialize":
                    initializeCas = readBoolean(item);
                    break;
                case "continue":
                    continueOnError = readBoolean(item);
                    break;
                }
            } else if ("zipfile".equals(item.getFieldName())) {
                zipfileItem = item;
            }
        }
        if (zipfileItem == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "No file upload found.");
        }

        byte[] zipdata;
        try {
            zipdata = IOUtils.toByteArray(zipfileItem.getInputStream());
        } catch (final IOException e) {
            log.info("Unable to read zipfile data.", e);
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "zipfile data not read:" + e.getLocalizedMessage());
        }

        log.debug("Input file = " + zipfile);

        final ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIgnoreErrors(ignoreErrors);
        settings.setIgnoreWarnings(false);
        settings.setInitializeCas(initializeCas);
        settings.setNonInteractiveMode(continueOnError ? NonInteractiveMode.CONTINUE : NonInteractiveMode.ABORT);
        settings.setConfigdumpType(ConfigdumpSetting.ConfigdumpType.ZIPFILE);
        settings.setImportData(zipdata);

        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            ConfigdumpResults results = doImport(admin, settings, overwrite, resolveMissingReferences);
            if (log.isDebugEnabled()) {
                log.debug("Zipfile import results:" + results);
            }
            return results;
        } catch (ConfigdumpException | IOException e) {
            log.info("Unable to import zipfile .", e);
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Unable to import zipfile:" + e);
        }
    }

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Put the configuration in JSON.", response = ConfigdumpResults.class)
    public ConfigdumpResults postJsonImport(
    //@formatter:off
            @Context final HttpServletRequest requestContext,
            
            @ApiParam("Add to warnings instead of aborting on errors.") 
            @DefaultValue("false") @QueryParam("ignoreerrors") 
            final boolean ignoreErrors,
            
            @ApiParam("Generate initial certificate for CAs on import") 
            @DefaultValue("false") @QueryParam("initialize") 
            final boolean initializeCas,
            
            @ApiParam("Continue on errors. Default is to abort.")
            @DefaultValue("false") @QueryParam("continue") 
            final boolean continueOnError,
            
            @ApiParam("How to handle already existing configuration. Options are abort,skip,yes") 
            @DefaultValue("abort") @QueryParam("overwrite") 
            final Overwrite overwrite,
            
            @ApiParam("How to resolve missing references. Options are abort,skip,default") 
            @DefaultValue("abort") @QueryParam("resolve") 
            final ResolveMissingReferences resolveMissingReferences,
            
            @ApiParam("JSON data in configdump format") 
            String json
            //@formatter:on
    ) throws AuthorizationDeniedException, RestException {

        final ConfigdumpSetting settings = new ConfigdumpSetting();
        settings.setIgnoreErrors(ignoreErrors);
        settings.setIgnoreWarnings(false);
        settings.setInitializeCas(initializeCas);
        settings.setNonInteractiveMode(continueOnError ? NonInteractiveMode.CONTINUE : NonInteractiveMode.ABORT);
        settings.setConfigdumpType(ConfigdumpSetting.ConfigdumpType.JSON);
        settings.setImportData(json.getBytes());

        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            ConfigdumpResults results = doImport(admin, settings, overwrite, resolveMissingReferences);
            if (log.isDebugEnabled()) {
                log.debug("JSON import results:" + results);
            }
            return results;
        } catch (ConfigdumpException | IOException e) {
            log.info("Unable to import JSON.", e);
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Unable to import json:" + e);
        }
    }

    private ConfigdumpResults doImport(final AuthenticationToken admin, final ConfigdumpSetting settings, final Overwrite overwrite,
            final ResolveMissingReferences resolveMissingReferences) throws IOException, AuthorizationDeniedException {
        // do a dry run first, to determine if we have problematic items
        settings.setProcessingMode(ProcessingMode.DRY_RUN);
        final ConfigdumpImportResult dryRunResults = configDump.performImport(admin, settings);

        // there are problematic items and overwrite mode is abort - return them as errors
        final boolean overwritesFound = dryRunResults.getProblematicItems().stream().map(ConfigdumpItem::getProblem)
                .anyMatch(p -> p == ItemProblem.EXISTING || p == ItemProblem.EXISTING_AND_MISSING_REFERENCE);
        final boolean unresolvedFound = dryRunResults.getProblematicItems().stream().map(ConfigdumpItem::getProblem)
                .anyMatch(p -> p == ItemProblem.MISSING_REFERENCE || p == ItemProblem.EXISTING_AND_MISSING_REFERENCE);
        log.debug("Problematic items found when importing configdump. overwritesFound=" + overwritesFound + ", unresolvedFound=" + unresolvedFound);
        if (overwritesFound && overwrite == Overwrite.abort || unresolvedFound && resolveMissingReferences == ResolveMissingReferences.abort) {
            ArrayList<String> errors = new ArrayList<>(dryRunResults.getReportedErrors());
            dryRunResults.getProblematicItems().forEach(i -> errors.add(createErrorMessage(i)));
            return new ConfigdumpResults(errors, dryRunResults.getReportedWarnings());
        }

        // otherwise, resolve them as specified by overwrite and resolveMissingReferences
        for (ConfigdumpItem<?> problematicItem : dryRunResults.getProblematicItems()) {
            if (problematicItem.getProblem() == ItemProblem.EXISTING || problematicItem.getProblem() == ItemProblem.EXISTING_AND_MISSING_REFERENCE) {
                settings.addOverwriteResolution(problematicItem, overwrite == Overwrite.yes ? OverwriteMode.UPDATE : OverwriteMode.SKIP);
            } else if (problematicItem.getProblem() == ItemProblem.MISSING_REFERENCE
                    || problematicItem.getProblem() == ItemProblem.EXISTING_AND_MISSING_REFERENCE) {
                settings.addResolveReferenceModeResolution(problematicItem,
                        resolveMissingReferences == ResolveMissingReferences.useDefault ? ResolveReferenceMode.USE_DEFAULT
                                : ResolveReferenceMode.SKIP);
            }
        }
        settings.setProcessingMode(ProcessingMode.RUN);
        final ConfigdumpImportResult results = configDump.performImport(admin, settings);

        if (results.isSuccessful()) {
            return new ConfigdumpResults(results.getReportedWarnings());
        } else {
            return new ConfigdumpResults(results.getReportedErrors(), results.getReportedWarnings());
        }
    }

    private String createErrorMessage(ConfigdumpItem<?> i) {
        ItemProblem problem = i.getProblem();
        if (problem == ItemProblem.EXISTING) {
            return i.getName() + " already exists.  Aborting.";
        } else if (problem == ItemProblem.EXISTING_AND_MISSING_REFERENCE) {
            return i.getName() + " already exists and has missing references.  Aborting.";
        } else {
            return i.getName() + " has missing references.  Aborting.";
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

    static private <T extends Enum<T>> T read(FileItem item, Class<T> clazz) throws RestException {
        try (InputStream valueStream = item.getInputStream()) {
            String value = IOUtils.toString(valueStream, StandardCharsets.UTF_8);
            return Arrays.stream(clazz.getEnumConstants()).filter(v -> v.name().equals(value)).findFirst().orElseThrow(
                    () -> new RestException(Response.Status.BAD_REQUEST.getStatusCode(), value + " is not a valid value for " + item.getFieldName()));
        } catch (IOException e) {
            log.info("unable to read " + item.getFieldName(), e);
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "unable to read " + item.getFieldName());
        }
    }

    private static boolean readBoolean(FileItem item) throws RestException {
        try (InputStream valueStream = item.getInputStream()) {
            String value = IOUtils.toString(valueStream, StandardCharsets.UTF_8);
            return Boolean.getBoolean(value);
        } catch (IOException e) {
            log.info("unable to read " + item.getFieldName(), e);
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "unable to read " + item.getFieldName());
        }
    }
}
