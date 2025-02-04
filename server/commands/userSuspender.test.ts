import GroupUser from "@server/models/GroupUser";
import { buildGroup, buildAdmin, buildUser } from "@server/test/factories";
import { flushdb } from "@server/test/support";
import userSuspender from "./userSuspender";

beforeEach(() => flushdb());

describe("userSuspender", () => {
  const ip = "127.0.0.1";

  it("should not suspend self", async () => {
    const user = await buildUser();
    let error;

    try {
      await userSuspender({
        actorId: user.id,
        user,
        ip,
      });
    } catch (err) {
      error = err;
    }

    expect(error.message).toEqual("Unable to suspend the current user");
  });

  it("should suspend the user", async () => {
    const admin = await buildAdmin();
    const user = await buildUser({
      teamId: admin.teamId,
    });
    await userSuspender({
      actorId: admin.id,
      user,
      ip,
    });
    expect(user.suspendedAt).toBeTruthy();
    expect(user.suspendedById).toEqual(admin.id);
  });

  it("should remove group memberships", async () => {
    const admin = await buildAdmin();
    const user = await buildUser({
      teamId: admin.teamId,
    });
    const group = await buildGroup({
      teamId: user.teamId,
    });
    await group.$add("user", user, {
      through: {
        createdById: user.id,
      },
    });
    await userSuspender({
      actorId: admin.id,
      user,
      ip,
    });
    expect(user.suspendedAt).toBeTruthy();
    expect(user.suspendedById).toEqual(admin.id);
    expect(await GroupUser.count()).toEqual(0);
  });
});
