import NextAuth from "next-auth";
import GoogleProvider from "next-auth/providers/google";

/**
 * Refreshes a Google OAuth access token using the stored refresh token.
 * Returns the updated token object with a new access token and expiry.
 */
async function refreshAccessToken(token) {
  try {
    const url = "https://oauth2.googleapis.com/token";
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: token.refreshToken,
      }),
    });

    const refreshed = await response.json();

    if (!response.ok) throw refreshed;

    return {
      ...token,
      accessToken: refreshed.access_token,
      // New expiry: current time + expires_in seconds (converted to ms)
      accessTokenExpires: Date.now() + refreshed.expires_in * 1000,
      // Keep old refresh token if Google doesn't issue a new one
      refreshToken: refreshed.refresh_token ?? token.refreshToken,
    };
  } catch (error) {
    console.error("Error refreshing access token:", error);
    return { ...token, error: "RefreshAccessTokenError" };
  }
}

const handler = NextAuth({
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      authorization: {
        params: {
          // access_type=offline → Google issues a refresh_token
          // prompt=consent     → Forces consent screen so refresh_token is always returned
          scope: "openid email profile https://www.googleapis.com/auth/gmail.readonly",
          access_type: "offline",
          prompt: "consent",
        },
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account, profile }) {
      if (user?.email) {
        try {
          await fetch("https://phishlens-production.up.railway.app/admin/log-action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              email: user.email,
              action: `Signed In via Google`
            })
          });
        } catch (err) {
          console.error("Error logging sign-in:", err);
        }
      }
      return true;
    },
    async jwt({ token, account }) {
      // On initial sign-in, store access token, refresh token, and expiry
      if (account) {
        return {
          ...token,
          accessToken: account.access_token,
          refreshToken: account.refresh_token,
          // expires_at is in seconds from Google; convert to ms
          accessTokenExpires: account.expires_at
            ? account.expires_at * 1000
            : Date.now() + 3600 * 1000,
        };
      }

      // Return token as-is if it hasn't expired yet
      if (Date.now() < token.accessTokenExpires) {
        return token;
      }

      // Access token has expired — refresh it
      return refreshAccessToken(token);
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken;
      session.error = token.error; // expose refresh errors to the client if needed
      return session;
    },
  },
});

export { handler as GET, handler as POST };
