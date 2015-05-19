package controllers;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import play.mvc.*;
import views.html.*;

public class LoginController extends Controller {

	// Parameters for OpenID Connect
	private static final ClientID clientId = new ClientID("dummy");
	private static final Secret clientSecret = new Secret("dummy");
	private static final Scope scope = new Scope("openid");
	private static final Issuer issuer = new Issuer("dummy");
	private static final Audience audience = new Audience(clientId.toString());
	private static final URI authzEndpoint;
	private static final URI tokenEndpoint;
	private static final URI redirectUri;
	static {
		try {
			authzEndpoint = new URI("http://example.com/authz");
			tokenEndpoint = new URI("http://example.com/token");
			redirectUri = new URI("http://localhost:9000/loginCallback");
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	public static Result getPage() {
		return ok(login.render());
	}

	public static Result doLogin() {

		// Create a random string for CSRF prevention, and store in the cookie of client.
		State state = new State();
		SessionManager.setState(state);

		// Build URI of authorization request.
		URI requestUri;
		try {
			ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
			requestUri = new AuthenticationRequest.Builder(responseType, scope, clientId, redirectUri)
				.endpointURI(authzEndpoint)
				.state(state)
				.build()
				.toURI();
		} catch (SerializeException e) {
			throw new RuntimeException(e);
		}

		return redirect(requestUri.toString());
	}

	public static Result callback() {

		/*
		 *  Validate request uri and retrieve authorization code.
		 */
		AuthorizationCode authzCode;
		try {
			AuthenticationResponse authnResponse = AuthenticationResponseParser.parse(new URI(request().uri()));

			// if an error query parameter is set, show an error page.
			if (!authnResponse.indicatesSuccess()) {
				AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) authnResponse;
				//AuthorizationErrorResponse errorResponse = (AuthorizationErrorResponse) response;
				String errorCode = String.valueOf(errorResponse.getErrorObject().getCode());
				return ok(error.render("authorization failed. errorCode=" + errorCode));
			}

			// if value of state parameter is defferent form the one in the session, show an error page.
			State state = SessionManager.getState();
			if (!state.getValue().equals(authnResponse.getState().getValue())) {
				return ok(error.render("authorization failed. state parameter is invalid. cookie=" + state.getValue()));
			}

			// Retreive authorization code.
			AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authnResponse;
			authzCode = successResponse.getAuthorizationCode();

		} catch (ParseException | URISyntaxException e) {
			throw new RuntimeException(e);
		}

		/*
		 * Exchange authorization code for id token.
		 */
		AuthorizationGrant authzGrant = new AuthorizationCodeGrant(authzCode, redirectUri);
		ClientAuthentication clientAuthn = new ClientSecretBasic(clientId, clientSecret);
		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuthn, authzGrant);
		TokenResponse tokenResponse;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
		} catch (ParseException | SerializeException | IOException e) {
			throw new RuntimeException(e);
		}
		if (!tokenResponse.indicatesSuccess()) {

			TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
			String errorCode = String.valueOf(errorResponse.getErrorObject().getCode());
			return ok(error.render("token request failed. errorCode=" + errorCode));
		}
		OIDCAccessTokenResponse oidcAccessTokenResponse = (OIDCAccessTokenResponse) tokenResponse;
		JWT idToken = oidcAccessTokenResponse.getIDToken();

		/*
		 * Validate id token and retrieve user id.
		 */
		IDTokenClaimsSet idTokenClaimSet;
		try {
			idTokenClaimSet =  new IDTokenClaimsSet(idToken.getJWTClaimsSet());
		} catch (ParseException | java.text.ParseException e) {
			throw new RuntimeException(e);
		}
		// iss
		if (!idTokenClaimSet.getIssuer().equals(issuer)) {
			return ok(error.render("issuer is invalid. iss=" + String.valueOf(idTokenClaimSet.getIssuer())));
		}
		// aud
		if (!idTokenClaimSet.getAudience().contains(audience)) {
			return ok(error.render("Audience is invalid. aud=" + String.valueOf(idTokenClaimSet.getAudience())));
		}
		// exp
		if (new Date().after(idTokenClaimSet.getExpirationTime())) {
			return ok(error.render("ExpirationTime is invalid. exp=" + String.valueOf(idTokenClaimSet.getExpirationTime())));
		}

		/*
		 * Create a local login session.
		 */
		String userId = idTokenClaimSet.getSubject().getValue();
		SessionManager.login(userId);
		SessionManager.setIdToken(idToken);
		return redirect(routes.DashboardController.getPage());
	}
}