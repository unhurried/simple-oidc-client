package controllers;

import java.net.URI;
import java.net.URISyntaxException;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.LogoutRequest;

import play.mvc.*;
import views.html.*;

public class DashboardController extends Controller {

	private static final URI logoutEndpoint;
	private static final URI postLogoutRedirectUri;
	static {
		try {
			logoutEndpoint = new URI("http://localhost:9000/dummyLogoutEndpoint");
			postLogoutRedirectUri = new URI("http://localhost:9000/logoutCallback");
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	@Security.Authenticated(UserAuthenticator.class)
	public static Result getPage() {
		String userId = SessionManager.getLoginUser();
		return ok(dashboard.render(userId));
	}

	public static Result doLogout(){

		// Get id token from the cookie.
		JWT idToken = SessionManager.getIdToken();
		if (idToken == null) {
			return ok(error.render("Unexpected session state."));
		}

		SessionManager.logout();

		State state = new State();
		SessionManager.setState(state);
		LogoutRequest logoutRequest = new LogoutRequest(logoutEndpoint, idToken, postLogoutRedirectUri, state);
		try {
			return redirect(logoutRequest.toURI().toString());
		} catch (SerializeException e) {
			throw new RuntimeException(e);
		}
	}

	public static Result callback() {

		// if value of state parameter is defferent form the one in the session, show an error page.
		LogoutResponse response = LogoutResponse.parse(request());
		if (!response.isStateValid(SessionManager.getState())) {
			return ok(error.render("state parameter is invalid."));
		}

		return redirect(routes.LoginController.getPage());
	}
}