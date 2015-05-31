package controllers;

import java.net.URI;
import java.net.URISyntaxException;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

import play.Configuration;

public class ConfigManager {

	// Config key
	private static final String ROOT = "soc.";
	private static final String CLIENT_ID = ROOT + "clientId";
	private static final String CLIENT_SECRET = ROOT + "clientSecret";
	private static final String SCOPE = ROOT + "scope";
	private static final String ISSUER = ROOT + "issuer";
	private static final String AUTHZ_ENDPOINT = ROOT + "authzEndpoint";
	private static final String TOKEN_ENDPOINT = ROOT + "tokenEndpoint";
	private static final String REDIRECT_URI = ROOT + "redirectUri";
	private static final String LOGOUT_ENDPOINT = ROOT + "logoutEndpoint";
	private static final String POST_LOGOUT_REDIRECT_URI = ROOT + "postLogoutRedirectUri";

	private static String getString(String key) {
		return Configuration.root().getString(key);
	}

	private static URI getURI(String key) {
		try {
			return new URI(getString(key));
		} catch (URISyntaxException e) {
			throw new RuntimeException("config is invalid or missing. key=" + key, e);
		}
	}

	public static ClientID getClient() {
		return new ClientID(getString(CLIENT_ID));
	}

	public static Secret getSecret() {
		return new Secret(getString(CLIENT_SECRET));
	}

	public static Scope getScope() {
		return new Scope(getString(SCOPE));
	}

	public static Issuer getIssuer() {
		return new Issuer(getString(ISSUER));
	}

	public static URI getAuthzEndpoint() {
		return getURI(AUTHZ_ENDPOINT);
	}

	public static URI getTokenEndpoint() {
		return getURI(TOKEN_ENDPOINT);
	}

	public static URI getRedirectUri() {
		return getURI(REDIRECT_URI);
	}

	public static URI getLogoutEndpoint() {
		return getURI(LOGOUT_ENDPOINT);
	}

	public static URI getPostLogoutRedirectUri() {
		return getURI(POST_LOGOUT_REDIRECT_URI);
	}
}
