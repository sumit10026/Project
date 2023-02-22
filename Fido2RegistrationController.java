package com.uniken.authserver.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mastercard.ess.fido2.service.Fido2RPRuntimeException;
import com.uniken.authserver.database.CredentialRepositoryImpl;
import com.uniken.authserver.domains.FidoResponse;
import com.uniken.authserver.exception.AuthGenerationAttemptCounterExceededException;
import com.uniken.authserver.services.api.SecureCookieService;
import com.uniken.authserver.services.api.UserService;
import com.uniken.authserver.utility.AuthenticationUtils;
import com.uniken.authserver.utility.Constants;
import com.uniken.authserver.utility.PropertyConstants;
import com.uniken.authserver.utility.SessionConstants;
import com.uniken.authserver.utility.Utils;
import com.uniken.domains.auth.fido.FIDO2RegisteredAuthenticationModule;
import com.uniken.domains.auth.fido.PublicKeyCredentialDescriptor;
import com.uniken.domains.auth.fido.PublicKeyCredentialRequestOptions;
import com.uniken.domains.auth.fido.enums.AuthenticatorTransport;
import com.uniken.domains.enums.auth.AuthType;
import com.uniken.domains.relid.user.UserBrowser;
import com.uniken.fido2.utils.FidoUtils;
import com.uniken.logging.EventId;
import com.uniken.logging.EventLogger;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;

@RestController
public class Fido2RegistrationController {

    private static final Logger LOG = LoggerFactory.getLogger(Fido2RegistrationController.class);

    /*
     * @Autowired private AttestationService attestationService; // from master
     * card
     * @Autowired private AssertionService assertionService; // from master card
     */

    @Autowired
    private CredentialRepository crepos;

    @Autowired
    private SecureCookieService secureCookieService;

    @Autowired
    private UserService userService;

    private HttpHeaders getFixedHeaders() {
        final HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");
        headers.set("Content-Type", "application/json;charset=UTF-8");
        headers.set("X-FRAME-OPTIONS", "DENY");
        return headers;
    }

    final RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder().id("example.com").name("Example Application")
            .build();

    final RelyingParty rp = RelyingParty.builder().identity(rpIdentity)
            .credentialRepository(new CredentialRepositoryImpl()).build();

    @PostMapping(value = { "/attestation/options" }, produces = { "application/json" }, consumes = {
            "application/json" })
    public ResponseEntity<JsonNode> options(@RequestBody final JsonNode params) {
        LOG.info("attestation options() method is entered");
        final JsonNode node = null;
        try {
            // node = attestationService.options(params);

            final PublicKeyCredentialCreationOptions request = rp.startRegistration(
                    StartRegistrationOptions.builder().user(findExistingUser("alice").orElseGet(() -> {
                        byte[] userHandle = new byte[64];
                        random.nextBytes(userHandle);
                        return UserIdentity.builder().name("alice").displayName("Alice Hypothetical")
                                .id(new ByteArray(userHandle)).build();
                    })).build());

            return new ResponseEntity<>(node, getFixedHeaders(), HttpStatus.OK);
        } /*
           * catch (final Fido2RPRuntimeException e) { LOG.
           * error("Error while registering FIDO2 device (step1) due to exception"
           * , e); }
           */catch (final Exception e) {
            LOG.error("Error while registering FIDO2 device (step1) due to exception", e);
        }
        return new ResponseEntity<>(node, getFixedHeaders(), HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @PostMapping(value = { "/attestation/result" }, produces = { "application/json" }, consumes = {
            "application/json" })
    public ResponseEntity<JsonNode> result(@RequestBody final JsonNode params) {
        LOG.info("attestation verify method is entered");
        final JsonNode node = null;
        try {
            // node = attestationService.verify(params);
            return new ResponseEntity<>(node, getFixedHeaders(), HttpStatus.OK);
        } catch (final Fido2RPRuntimeException e) {
            LOG.error("Error while registering FIDO2 device (step2) due to exception", e);
        } catch (final Exception e) {
            LOG.error("Error while registering FIDO2 device (step2) due to exception", e);
        }
        return new ResponseEntity<>(node, getFixedHeaders(), HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @SuppressWarnings("unchecked")
    @PostMapping(value = { "/assertion/options" }, produces = { "application/json" }, consumes = { "application/json" })
    public ResponseEntity<FidoResponse> register(final HttpServletRequest request, final HttpServletResponse response,
            @RequestBody final JsonNode params, final Authentication authentication) {
        LOG.info("assertion register method is entered");
        final HttpSession session = request.getSession();
        final JsonNode node = null;
        Map<String, Integer> authGenerationAttemptsCounter = new HashMap<>();
        boolean isLevel1AuthenticationPending = false;

        try {
            authGenerationAttemptsCounter = (HashMap<String, Integer>) session
                    .getAttribute(SessionConstants.AUTH_GENERATION_ATTEMPT_COUNTER);
            final String fidoName = AuthType.FIDO.name();

            // Validation of FIDO Generation Attempt Counter
            if (authGenerationAttemptsCounter.get(fidoName) < 1) {
                throw new AuthGenerationAttemptCounterExceededException("FIDO Generation Attempt Counter Exhausted");
            }

            final boolean unauthenticatedUser = authentication == null || !authentication.isAuthenticated();
            isLevel1AuthenticationPending = CollectionUtils
                    .isEmpty((Set<String>) session.getAttribute(SessionConstants.VALIDATED_AUTH_TYPES));
            if (unauthenticatedUser && isLevel1AuthenticationPending) {
                ((ObjectNode) params).put("userVerification", ResidentKeyRequirement.required.name());
            }

            // node = assertionService.options(params);

            final AssertionRequest request1 = rp.startAssertion(StartAssertionOptions.builder().username("alice") // Or
                                                                                                                  // .userHandle(ByteArray)
                                                                                                                  // if
                                                                                                                  // preferred
                    .build());

            // Decrementing the RELID Verify generation attempt counter &
            // updating it into the session & DB
            if (authGenerationAttemptsCounter.get(fidoName) > 1) {
                final int decrementedCounter = authGenerationAttemptsCounter.get(fidoName) - 1;
                authGenerationAttemptsCounter.put(fidoName, decrementedCounter);

                // Updating the generation attempt counter in Session & DB
                session.setAttribute(SessionConstants.AUTH_GENERATION_ATTEMPT_COUNTER, authGenerationAttemptsCounter);
                // userAuthInfoRepo.updateWebUserAuthGenerationAttemptCounter(userName,
                // authGenerationAttemptsCounter);

                EventLogger.log(EventId.RelidAuthServer.DECREMENT_AUTH_GENERATION_ATTMEPT_COUNTER,
                        Utils.getClientIpAddress(request1), AuthenticationUtils.getRequestorId(request1),
                        AuthenticationUtils.getUsername(request1), AuthenticationUtils.getUserAgent(request1),
                        "Auth Generation Attempt Counter Decremented For " + fidoName
                                + " & current Auth Generation Attempt Counter is " + decrementedCounter);
            } else {
                authGenerationAttemptsCounter.put(fidoName, 0);

                // Updating the generation attempt counter in Session & DB
                session.setAttribute(SessionConstants.AUTH_GENERATION_ATTEMPT_COUNTER, authGenerationAttemptsCounter);
                // userAuthInfoRepo.updateWebUserAuthGenerationAttemptCounter(userName,
                // authGenerationAttemptsCounter);

                EventLogger.log(EventId.RelidAuthServer.EXHAUSTED_AUTH_GENERATION_ATTMEPT_COUNTER,
                        Utils.getClientIpAddress(request1), AuthenticationUtils.getRequestorId(request1),
                        AuthenticationUtils.getUsername(request1), AuthenticationUtils.getUserAgent(request1),
                        "Auth Generation Attempt Counter Exhausted For " + fidoName);
            }

            final PublicKeyCredentialRequestOptions options = Constants.GSON.fromJson(node.toString(),
                    PublicKeyCredentialRequestOptions.class);

            final List<PublicKeyCredentialDescriptor> allowCredentials = new ArrayList<>();
            if (unauthenticatedUser) {
                final String usernameFromSecurityContextOrRequestContext = Utils
                        .getUsernameFromSecurityContextOrRequestContext();
                final UserBrowser userBrowser = secureCookieService.getAssociatedUserBrowserBySecureCookie(request1,
                        usernameFromSecurityContextOrRequestContext);
                final List<FIDO2RegisteredAuthenticationModule> registeredAuthenticationModules = userService
                        .fetchRegisteredAuthenticationModuleFromLoginId(usernameFromSecurityContextOrRequestContext);

                for (final PublicKeyCredentialDescriptor cred : options.getAllowCredentials()) {
                    if (cred.getTransports() != null) {
                        // Use case: Use platform authenticator only when secure
                        // cookie is present during login

                        // Disable support of Platform Authenticator
                        /*
                         * if (cred.getTransports().contains(
                         * AuthenticatorTransport .internal)) { if (userBrowser
                         * != null && userBrowser.getAuthenticatorUuid() !=
                         * null) { allowCredentials.add(cred); } } else
                         */

                        // Disable support of Platform Authenticator
                        if (cred.getTransports().contains(AuthenticatorTransport.internal)) {
                            /*
                             * if (userBrowser != null &&
                             * userBrowser.getAuthenticatorUuid() != null) {
                             * allowCredentials.add(cred); }
                             */
                            continue;
                        } else if (isLevel1AuthenticationPending) {
                            // Use case: Allow only 2FA authenticators in level
                            // 1
                            if (FidoUtils.is2FaAuthenticator(registeredAuthenticationModules.stream()
                                    .filter(regAuthModule -> regAuthModule.getRegistrationKeyId().equals(cred.getId()))
                                    .findFirst().get().getAuthenticatorAttestationResponse().getAttestationObject())) {
                                allowCredentials.add(cred);
                            }
                        } else if (!PropertyConstants.AUTH_SERVER_ALLOWED_AUTH_FACTORS.isAlwaysAskForPassword()) {
                            // Use case: If always ask for password is false,
                            // allow only 1FA authenticators in level 2
                            if (!FidoUtils.is2FaAuthenticator(registeredAuthenticationModules.stream()
                                    .filter(regAuthModule -> regAuthModule.getRegistrationKeyId().equals(cred.getId()))
                                    .findFirst().get().getAuthenticatorAttestationResponse().getAttestationObject())) {
                                allowCredentials.add(cred);
                            }
                        } else {
                            allowCredentials.add(cred);
                        }
                    }
                }
            }

            // Disable support of Platform Authenticator
            /*
             * else { // Use case: Post login re-register FIDO platform
             * authenticator // on same device different browser, send only
             * platform // authenticator creds allowCredentials =
             * options.getAllowCredentials().stream() .filter(cred ->
             * cred.getTransports().contains(AuthenticatorTransport.internal))
             * .collect(Collectors.toList()); }
             */
            options.setAllowCredentials(allowCredentials);

            return new ResponseEntity<>(new FidoResponse(authGenerationAttemptsCounter,
                    Constants.JACKSON_OBJECT_MAPPER.readTree(Constants.GSON.toJson(options)),
                    isLevel1AuthenticationPending), getFixedHeaders(), HttpStatus.OK);
        } /*
           * catch (final Fido2RPRuntimeException e) { LOG.
           * error("Error while asserting FIDO2 device (step1) due to exception"
           * , e); }
           */ catch (final Exception e) {
            LOG.error("Error while asserting FIDO2 device (step1) due to exception", e);
        }
        return new ResponseEntity<>(new FidoResponse(authGenerationAttemptsCounter,
                Constants.JACKSON_OBJECT_MAPPER.createObjectNode(), isLevel1AuthenticationPending), getFixedHeaders(),
                HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @PostMapping(value = { "/assertion/result" }, produces = { "application/json" }, consumes = { "application/json" })
    public ResponseEntity<JsonNode> verify(@RequestBody final JsonNode params) {
        LOG.info("assertion result method is entered");
        final JsonNode node = null;
        try {
            // node = assertionService.options(params);

            return new ResponseEntity<>(node, getFixedHeaders(), HttpStatus.OK);
        } catch (final Fido2RPRuntimeException e) {
            LOG.error("Error while asserting FIDO2 device (step2) due to exception", e);
        } catch (final Exception e) {
            LOG.error("Error while asserting FIDO2 device (step2) due to exception", e);
        }
        return new ResponseEntity<>(node, getFixedHeaders(), HttpStatus.UNPROCESSABLE_ENTITY);
    }
}
