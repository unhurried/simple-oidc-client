package controllers;

import play.mvc.Result;
import play.mvc.Security;
import play.mvc.Http.Context;

public class UserAuthenticator extends Security.Authenticator {

	private static final String SESSION_KEY_USER_ID = "userId";

	@Override
    public String getUsername(Context ctx) {
        return ctx.session().get(SESSION_KEY_USER_ID);
    }

	@Override
    public Result onUnauthorized(Context ctx) {
        return redirect(routes.LoginController.getPage());
    }
}
