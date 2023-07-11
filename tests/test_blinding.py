from sogs import crypto
from sogs.model.room import Room
from sogs.model.user import User
from user import User as TUser
from nacl.signing import SigningKey
from sogs.hashing import blake2b
from util import config_override
import nacl.bindings as sodium
import pytest
import time

from auth import x_sogs


# For test reproducibility use this fixed server pubkey for the blinding derivation tests (because
# each test environment typically has its own, which completely changes the derived pubkeys).
fake_server_pubkey_bytes = bytes.fromhex(
    '6a32c7b491f4199dd1260a4cc60ae51c6bd71dad939cc521e738409f53f943be'
)


@pytest.mark.parametrize(
    ["seed_hex", "blinded_id_exp"],
    [
        pytest.param(
            "880adf5164a79bce71f7387fbc2cb2693c0bf0ab4cb42bf1edafddade7527a66",
            "15cef185d46b60a548641bd8c5baa4b7cf90b7da8e883c0ac774c703d249086479",
        ),
        pytest.param(
            "67416582e0700081604860d270bc986011fc5e62c53de908a9a5af2cb497c528",
            "15f8fbeb20cdde5e0cc0ec84e0b3705ca6090c7b23e8132589970473a5592ba388",
        ),
        pytest.param(
            "a5ad71709cfa315d147921e377186270367fd06926f4dbfe33f519dec6b016f7",
            "15758e10dc51210d7a36ea6076e2aa84d9f87283bddb508364272dce0a7618f92a",
        ),
        pytest.param(
            "c929a389a0dcf375ae8177891655b3835773e3a2d6d27490de8b8a160ca472f8",
            "1515ad8f8c5e56b31078a4a5ae73938bd523b1c86ea36033d564759e4495fbb64d",
        ),
        pytest.param(
            "0576076b8a82aae0fa1d0f00e97b538b43205f63759a972f26b851a55b60b5d0",
            "15375a56d4cbf0538f4b326e54917fd1953e9e3dfe076eb8b35929a8d869a15c13",
        ),
        pytest.param(
            "0a5db01db307ffd1bbe3cdd0d47c71e8837c60b38983d1df1b187301959095c9",
            "151a821dd107ac68845f82085efb1f88d046a084a63f7fc381ec07a367e6bc5aac",
        ),
        pytest.param(
            "d9b4ff572d4ebbcf26b07329f9029462f0606087d64e8932e698aa0a98231ce3",
            "15a4acf4c814fd1bcf83ebbe42c276630a63e32365633cb57089544b3a60b5e4ac",
        ),
        pytest.param(
            "dbcf64e7e6323ace8a75327119c13ef0b41e0efb94e594a6424ba41472987844",
            "1503e60a1fbde2a930e11db0898220ceb41e5ea9161f61ff1dc7d83be3e9b96993",
        ),
        pytest.param(
            "2e90f20775370121a2db8413a68bb41c3618e63c744c865d8b03ca2cb9d52e9e",
            "150bfdf09d985453d70b07b779ac7de982c0b6190c19126df74e8ca3adbfb87fec",
        ),
        pytest.param(
            "0b19b8b2f006f73810a86244697ac3feb3500af22f97434bf1e4bac575e95d2f",
            "15c430f8cf5e3ca4a3d0fa79d75fe60b3dc21212b4467ddd01fc1173c738161628",
        ),
        pytest.param(
            "32c58327a3856acb77ca0e97993100b4a14475b2d5cd3804213ae2d6f2515709",
            "150fdb6a400ade0aa2d261999fc51aa0151201d30626b30ec94d3a06a927948523",
        ),
        pytest.param(
            "f5c57e9949bbb87b3ae9fa374bc05b8e945c33141b7eb19c5125d17023120287",
            "15cdda69401f8ca32c4760b025b8315967ce9f5c53d4b75239b26d8ff9db5852f8",
        ),
        pytest.param(
            "3aacbfb5059e1df00d11ff5742f8a5b91cdb9fe163f38906d7dfaae29ad30c0c",
            "152701bb6cf273f7c30a0b2bb3a4b027415aab3fdff5d44b7b50af269aaa46007d",
        ),
        pytest.param(
            "cce2487f4f1a01a54811204e8c774e7380c080f5f40cda0ef395752ef96dd35c",
            "15c92aa80e809a84d97323f911355d5015e916f3d5bebc297a17b4c44bad487ad6",
        ),
        pytest.param(
            "a414c2990f36a115308f74bbcb56c4238135c0578abf8de0505b08e9c7b69134",
            "150e51c490bc7c570310276b7fdaeb9e0e14ab4674ce8217df5418b621b52c5c31",
        ),
        pytest.param(
            "cbf84283c5d4a906b81e7533005fdd832d9d3712e71d5ee8247e3d32c1e2e38c",
            "157b0487fa9bc7449a167d66b56eb3e3fc628101d84a08f3f510f46de90de2e3a4",
        ),
        pytest.param(
            "e75399dac3b5b3675874ba1708d1effc6ab9bbd5b0fac4cf78a3c2b36af9cfc5",
            "15f277d3d6afbecc15c71d16c3f183e6dbb772b176f3c818265f4459aa649b9d80",
        ),
        pytest.param(
            "6cef60808348898f17123eb4f47556f22ae0e7bd1988455da6d4b685ea0f93d0",
            "152d766ba9a19fd108e8f397b7fddaad2473cf13192858b8fd28f641e6c817c7c1",
        ),
        pytest.param(
            "9396176367912b4bc9b2fca427bf7fea97293ee9db75e521e31e4618e2da061c",
            "15a2308a015da570bd749348991d4fee7b0ea5816f372a6c584581964680c9d46a",
        ),
        pytest.param(
            "b9ac6f130f0ef218e1fbd9484b38ba3a0a8ec5657744732b0a4a9e7f6c80a62e",
            "1513533ac53ea094b0c0e907046ffc2ade32122da069df503583bf89d6af01e127",
        ),
    ],
)
def test_blinded_key_derivation(seed_hex, blinded_id_exp):
    """
    Tests that we can successfully compute the blinded session id from the unblinded session id.

    seed_hex - the ed25519 master key seed
    blinded_id_exp - the expected blinded ed25519-based pubkey
    """

    s = SigningKey(bytes.fromhex(seed_hex))
    # The following name is misleading name: this is an easy way to extract the private scalar
    # (which happens to *also* be the private scalar when converting to curve, hence the name).
    a = s.to_curve25519_private_key().encode()

    k = sodium.crypto_core_ed25519_scalar_reduce(blake2b(fake_server_pubkey_bytes, digest_size=64))
    ka = sodium.crypto_core_ed25519_scalar_mul(k, a)
    kA = sodium.crypto_scalarmult_ed25519_base_noclamp(ka)

    session_id = '05' + s.to_curve25519_private_key().public_key.encode().hex()
    blinded_id = '15' + kA.hex()

    assert blinded_id == blinded_id_exp

    id_pos = crypto.compute_blinded_abs_id(session_id, k=k)
    assert len(id_pos) == 66
    id_neg = crypto.blinded_neg(id_pos)
    assert len(id_neg) == 66
    assert id_pos != id_neg
    assert id_pos[:64] == id_neg[:64]
    assert int(id_pos[64], 16) ^ int(id_neg[64], 16) == 0x8
    assert id_pos[65] == id_neg[65]

    assert blinded_id in (id_pos, id_neg)


def test_blinded_transition(
    db, client, room, room2, user, user2, mod, admin, global_mod, global_admin, banned_user
):
    r3 = Room.create('R3', name='R3', description='Another room')
    r3.default_read = False
    r3.default_write = False
    r3.default_accessible = False
    r3.default_upload = False

    r3.set_moderator(user, added_by=global_admin, admin=True, visible=False)
    r3.set_permissions(user2, mod=user, read=True, write=True, accessible=True, upload=True)
    r3.set_permissions(mod, mod=user, read=True, accessible=True)

    u3 = TUser()

    room.set_permissions(user, mod=global_admin, upload=False)
    room.ban_user(user2, mod=global_mod, timeout=86400)
    room2.set_permissions(user2, mod=global_admin, write=False, upload=False)
    db.query(
        """
        INSERT INTO user_permission_futures (room, "user", at, write, upload)
        VALUES (:r, :u, :at, :wr, :up)
        """,
        r=room.id,
        u=user2.id,
        wr=True,
        up=True,
        at=time.time() + 86400,
    )

    assert db.query("SELECT COUNT(*) FROM users").fetchone()[0] == 9
    assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 0

    assert [r[0] for r in db.query('SELECT "user" FROM user_permission_futures')] == [user2.id]
    assert [r[0] for r in db.query('SELECT "user" FROM user_ban_futures')] == [user2.id]

    with config_override(REQUIRE_BLIND_KEYS=True):
        # Forcibly reinit, which should populate the blinding transition tables
        db.database_init()

        unmigrated = {
            global_mod.id,
            global_admin.id,
            banned_user.id,
            mod.id,
            admin.id,
            user.id,
            user2.id,
            # u3 is not in here because it isn't assigned any permissions that need migration
        }
        r1mods = (
            [mod.session_id],
            [admin.session_id],
            [global_mod.session_id],
            [global_admin.session_id],
        )
        r2mods = ([], [], [global_mod.session_id], [global_admin.session_id])
        r3mods = (
            [],
            [],
            [global_mod.session_id],
            sorted((user.session_id, global_admin.session_id)),
        )
        assert unmigrated == set(r[0] for r in db.query('SELECT "user" FROM needs_blinding'))
        assert room.get_mods(global_admin) == r1mods
        assert room2.get_mods(global_admin) == r2mods
        assert r3.get_mods(global_admin) == r3mods

        from sogs.model.user import User

        # Direct User construction of a new blinded user should transition:
        b_mod = User(session_id=mod.blinded_id)
        unmigrated.remove(mod.id)
        assert unmigrated == set(r[0] for r in db.query('SELECT "user" FROM needs_blinding'))
        r1mods[0][0] = b_mod.session_id
        assert room.get_mods(global_admin) == r1mods

        # Transition should occur on the first authenticated request:
        r = client.get(
            '/capabilities',
            headers=x_sogs(user.ed_key, crypto.server_pubkey, 'GET', '/capabilities', blinded=True),
        )
        assert r.status_code == 200

        unmigrated.remove(user.id)
        assert unmigrated == set(r[0] for r in db.query('SELECT "user" FROM needs_blinding'))
        r3mods[3].clear()
        r3mods[3].extend(sorted((user.blinded_id, global_admin.session_id)))
        assert room.get_mods(global_admin) == r1mods
        assert room2.get_mods(global_admin) == r2mods
        assert r3.get_mods(global_admin) == r3mods

        for u in (user2, u3, admin, global_mod, global_admin, banned_user):
            r = client.get(
                '/capabilities',
                headers=x_sogs(
                    u.ed_key, crypto.server_pubkey, 'GET', '/capabilities', blinded=True
                ),
            )
            # Banned user should still be banned after migration:
            if u.id == banned_user.id:
                assert r.status_code == 403
            else:
                assert r.status_code == 200
            if u.id != u3.id:
                unmigrated.remove(u.id)

        assert unmigrated == set()

        for r in (room, room2, r3):
            r._refresh(perms=True)

        # NB: "global_admin" isn't actually an admin anymore (we transferred the permission to the
        # blinded equivalent), so shouldn't see the invisible mods:
        assert room.get_mods(global_admin) == ([mod.blinded_id], [admin.blinded_id], [], [])
        assert room2.get_mods(global_admin) == ([], [], [], [])
        assert r3.get_mods(global_admin) == ([], [], [], [])

        r1mods = (
            [mod.blinded_id],
            [admin.blinded_id],
            [global_mod.blinded_id],
            [global_admin.blinded_id],
        )
        r2mods = ([], [], [global_mod.blinded_id], [global_admin.blinded_id])
        r3mods = (
            [],
            [],
            [global_mod.blinded_id],
            sorted((user.blinded_id, global_admin.blinded_id)),
        )

        b_g_admin = User(session_id=global_admin.blinded_id)
        assert room.get_mods(b_g_admin) == r1mods
        assert room2.get_mods(b_g_admin) == r2mods
        assert r3.get_mods(b_g_admin) == r3mods

        b_u2 = User(session_id=user2.blinded_id)
        assert [r[0] for r in db.query('SELECT "user" FROM user_permission_futures')] == [b_u2.id]
        assert [r[0] for r in db.query('SELECT "user" FROM user_ban_futures')] == [b_u2.id]


def get_perm_flags(db, cols, exclude=[]):
    return {
        r['user']: {c: None if r[c] is None else bool(r[c]) for c in cols}
        for r in db.query(
            f"""
                SELECT "user", {", ".join(cols)} FROM user_permission_overrides
                WHERE "user" NOT IN :u
                ORDER BY "user"
                """,
            bind_expanding=['u'],
            u=[u.id for u in exclude],
        )
    }


def test_auto_blinding(db, client, room, user, user2, mod, global_admin):
    with config_override(REQUIRE_BLIND_KEYS=True):
        assert db.query("SELECT COUNT(*) FROM users").fetchone()[0] == 5
        assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 0

        # Banning a user by unblinded ID should set up the ban for the unblinded id *and* put them
        # in the needs_blinding table

        room.ban_user(user2, mod=mod)
        # Set these in two separate calls so that we are making sure multiple changes on the same
        # user works as expected:
        room.set_permissions(user, mod=mod, write=True)
        room.set_permissions(user, mod=mod, write=False)
        room.set_permissions(user, mod=mod, upload=False)

        upo = get_perm_flags(db, ['write', 'banned', 'upload'], [mod])
        assert upo == {
            user.id: {'banned': False, 'write': False, 'upload': False},
            user2.id: {'banned': True, 'write': None, 'upload': None},
        }
        assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 2

        # Initializing the blinded user should resolve the needs_blinding:
        b_user2 = User(session_id=user2.blinded_id)
        assert b_user2.id != user2.id

        upo = get_perm_flags(db, ['write', 'banned'], [mod])
        assert upo == {
            user.id: {'banned': False, 'write': False},
            b_user2.id: {'banned': True, 'write': None},
        }
        assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 1

        room.unban_user(b_user2, mod=mod)
        upo = get_perm_flags(db, ['write', 'banned'], [mod])
        assert upo == {user.id: {'banned': False, 'write': False}}
        # Now, since user2's blinded account already exists, attempting to ban user2 should ban
        # b_user2 directly:
        user2._refresh()
        room.ban_user(user2, mod=mod)
        upo = get_perm_flags(db, ['write', 'banned'], [mod])
        assert upo == {
            user.id: {'banned': False, 'write': False},
            b_user2.id: {'banned': True, 'write': None},
        }
        assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 1

        u3 = TUser()
        # Try the same for a global ban:
        u3.ban(banned_by=global_admin)
        u3.unban(unbanned_by=global_admin)
        u3.ban(banned_by=global_admin)
        assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 2
        u3._refresh()
        assert u3.banned

        b_u3 = User(session_id=u3.blinded_id)
        assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 1
        assert b_u3.banned
        u3._refresh()
        assert not u3.banned

        b_u3.unban(unbanned_by=global_admin)
        u3._refresh()
        b_u3._refresh()
        assert not u3.banned
        assert not b_u3.banned
        u3.ban(banned_by=global_admin)  # should ban b_u3 instead
        b_u3._refresh()
        u3._refresh()
        assert not u3.banned
        assert b_u3.banned

        # Moderator setting migration:
        b_user = User(session_id=user.blinded_id)
        user._refresh()
        assert db.query("SELECT COUNT(*) FROM needs_blinding").fetchone()[0] == 0
        room.set_moderator(user, added_by=global_admin)
        user._refresh()
        b_user._refresh()
        assert not room.check_moderator(user)
        assert room.check_moderator(b_user)
        assert not room.check_admin(b_user)
