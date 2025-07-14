package com.example.hrportal.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 🔑 OAuth2 Callback Handler
 * KrakenD'den gelen authorization code'u access token ile exchange eder
 */
@RestController
public class OAuth2CallbackController {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2CallbackController.class);

    // ✅ application.yml'den client secret al
    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String tokenUri;

    @Value("${hr-portal.gateway.base-url:http://localhost:8000}")
    private String gatewayBaseUrl;

    /**
     * 🔑 OAuth2 Authorization Code Callback
     * KrakenD'den gelen code'u token ile exchange eder
     */
    @GetMapping("/oauth/callback")
    public ResponseEntity<?> oauthCallback(
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "session_state", required = false) String sessionState,
            @RequestParam(value = "iss", required = false) String issuer,
            HttpServletResponse response,
            HttpServletRequest request) {

        logger.info("🔑 OAuth2 callback received - Code: {}, State: {}, Session: {}, Issuer: {}",
                code != null ? "***" + code.substring(Math.max(0, code.length()-6)) : null,
                state != null ? state : "not-provided",
                sessionState != null ? sessionState : "not-provided",
                issuer != null ? issuer : "not-provided");

        try {
            // 1. Authorization Code → Access Token Exchange
            String accessToken = exchangeCodeForToken(code);

            if (accessToken != null) {
                // 2. ✅ Authorization Header ile Redirect (Cookie yerine)
                HttpHeaders headers = new HttpHeaders();
                headers.setLocation(URI.create(gatewayBaseUrl + "/dashboard"));
                headers.set("Authorization", "Bearer " + accessToken);
                headers.set("X-JWT-Token", accessToken); // Backup header

                logger.info("✅ OAuth2 token exchange successful, redirecting with Authorization header");
                logger.debug("🔍 Redirect Headers: Authorization=Bearer ***, Location={}", gatewayBaseUrl + "/dashboard");

                return new ResponseEntity<>(headers, HttpStatus.FOUND); // 302 redirect

            } else {
                logger.error("❌ Token exchange failed - no access token received");
                return redirectToError("token_exchange_failed");
            }

        } catch (Exception e) {
            logger.error("❌ OAuth callback error", e);
            return redirectToError("oauth_callback_failed");
        }
    }

    // Helper method for error redirects
    private ResponseEntity<?> redirectToError(String errorCode) {
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(gatewayBaseUrl + "/?error=" + errorCode));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }
    /**
     * 🔄 Authorization Code → Access Token Exchange
     */
    private String exchangeCodeForToken(String code) {
        try {
            logger.debug("🔄 Starting token exchange for authorization code");
            logger.debug("🔧 Client ID: {}", clientId);
            logger.debug("🔧 Client Secret: {}...", clientSecret != null ? clientSecret.substring(0, 5) : "null");
            logger.debug("🔧 Token URI: {}", tokenUri);

            RestTemplate restTemplate = new RestTemplate();

            // Token exchange request parameters
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "authorization_code");
            params.add("client_id", clientId);
            params.add("client_secret", clientSecret);
            params.add("code", code);
            params.add("redirect_uri", gatewayBaseUrl + "/oauth-callback");

            // Debug: Request parameters logla (secret hariç)
            logger.debug("🔍 Token exchange parameters:");
            logger.debug("  - grant_type: authorization_code");
            logger.debug("  - client_id: {}", clientId);
            logger.debug("  - code: {}...", code);
            logger.debug("  - redirect_uri: {}", gatewayBaseUrl + "/oauth-callback");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> request =
                    new HttpEntity<>(params, headers);

            logger.debug("🌐 Making token exchange request to: {}", tokenUri);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    tokenUri,
                    request,
                    Map.class
            );

            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> tokenResponse = response.getBody();
                String accessToken = (String) tokenResponse.get("access_token");
                String tokenType = (String) tokenResponse.get("token_type");
                Integer expiresIn = (Integer) tokenResponse.get("expires_in");

                logger.info("🎯 Access token received successfully - Type: {}, Expires in: {}s, Token: {}...",
                        tokenType, expiresIn,
                        accessToken != null ? accessToken : "null");

                return accessToken;
            } else {
                logger.error("❌ Token exchange failed with status: {}", response.getStatusCode());
            }

        } catch (HttpClientErrorException e) {
            logger.error("💥 Token exchange HTTP error - Status: {}, Response: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());

            // 401 Unauthorized için özel mesaj
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                logger.error("🚨 UNAUTHORIZED - Check client credentials:");
                logger.error("   Client ID: {}", clientId);
                logger.error("   Client Secret exists: {}", clientSecret != null && !clientSecret.isEmpty());
                logger.error("   Token URI: {}", tokenUri);
            }
        } catch (Exception e) {
            logger.error("💥 Token exchange general error", e);
        }

        return null;
    }
}