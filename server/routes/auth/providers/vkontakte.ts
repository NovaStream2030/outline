import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import { Profile } from "passport";
import {
  Strategy as VKStrategy,
  Profile as _VKProfile,
} from "passport-vkontakte";
import accountProvisioner, {
  AccountProvisionerResult,
} from "@server/commands/accountProvisioner";
import env from "@server/env";
import { ForbiddenError } from "@server/errors";
import passportMiddleware from "@server/middlewares/passport";
import { User } from "@server/models";
import { isVkUserAllowed } from "@server/utils/authentication";
import { StateStore } from "@server/utils/passport";

const router = new Router();
const providerName = "vkontakte";
const VK_CLIENT_ID = process.env.VK_CLIENT_ID;
const VK_CLIENT_SECRET = process.env.VK_CLIENT_SECRET;
const VK_TEAM_NAME = process.env.VK_TEAM_NAME || "default";

export const config = {
  name: "VKontakte",
  enabled: !!VK_CLIENT_ID,
};

type VKProfile = Profile & _VKProfile;

if (VK_CLIENT_ID && VK_CLIENT_SECRET) {
  passport.use(
    new VKStrategy(
      {
        clientID: VK_CLIENT_ID,
        clientSecret: VK_CLIENT_SECRET,
        callbackURL: `${env.URL}/auth/vkontakte.callback`,
        profileFields: ["photo"],
        lang: "ru",
        apiVersion: "5.131",
        // @ts-expect-error StateStore
        store: new StateStore(),
      },
      async function (
        accessToken: string,
        refreshToken: string,
        _: unknown,
        profile: VKProfile,
        done: (
          err: Error | null,
          user: User | null,
          result?: AccountProvisionerResult
        ) => void
      ) {
        try {
          if (!isVkUserAllowed("" + profile.id)) {
            throw ForbiddenError();
          }

          const result = await accountProvisioner({
            ip: "1.1.1.1",
            team: {
              // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
              name: VK_TEAM_NAME,
              subdomain: "",
            },
            user: {
              name: profile.displayName,
              // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
              email: profile.username + "@vk.com",
              username: profile.username,
              avatarUrl: profile?.photos?.[profile.photos?.length - 1].value,
            },
            authenticationProvider: {
              name: providerName,
              providerId: "vkontakte",
            },
            authentication: {
              providerId: Buffer.from("" + profile.id).toString("base64"),
              accessToken: Buffer.from("" + profile.id).toString("base64"),
              refreshToken: Buffer.from("" + profile.id).toString("base64"),
              scopes: [""],
            },
          });

          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          done(null, result.user, result);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  router.get("vkontakte", passport.authenticate(providerName));

  router.get("vkontakte.callback", passportMiddleware(providerName));
}

export default router;
