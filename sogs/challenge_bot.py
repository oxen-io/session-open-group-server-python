from sogs.captcha import CaptchaManager
import os
from sogs.web import app
import configparser
import sqlalchemy.exc
from sogs.bot import *
import sogs.config as config


def delete(dic, outer_key, inner_key):
    del dic[outer_key][inner_key]
    if len(dic[outer_key]) == 0:
        del dic[outer_key]


class ChallengeBot(Bot):

    def __init__(
            self,
            sogs_address,
            sogs_pubkey,
            privkey,
            pubkey,
            display_name,
            retry_limit=3,
            refresh_timeout=60,
            retry_timeout=120,
            write_timeout=120,
    ):
        self.refresh_reaction = "\U0001F504"
        self.pending_requests = {}  # map {session_id : {room_token : msg_id}}
        self.pending_delete = {}  # map {session_id : {room_token : [msg_id]}}
        self.retry_jail = {}  # map {session_id: {room_token : Timestamp}}
        self.retry_limit = retry_limit
        self.retry_timeout = retry_timeout
        self.refresh_timeout = refresh_timeout
        self.write_timeout = write_timeout
        self.challenges = {}  # map {session_id : {room_token : (Captcha, Timestamp)}}
        self.retry_record = {}  # map {session_id: {room_token : Int}}
        self.captcha_manager = CaptchaManager(initial_count=200)

        Bot.__init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name)
        self.register_request_read_handler(self.handle_request_read)

    @staticmethod
    def create_and_run(db=None, ini: str = "bot.ini"):
        conf_ini = ini
        if not os.path.exists(conf_ini):
            app.logger.warning("bot.ini does not exist")
            conf_ini = None

        if not conf_ini:
            return

        app.logger.info(f"Loading bot config from {conf_ini}")
        cp = configparser.ConfigParser()
        cp.read(conf_ini)

        # Mandatory configs
        bot_privkey_hex_str = None
        if cp.has_option('bot', 'privkey_hex'):
            bot_privkey_hex_str = cp.get('bot', 'privkey_hex')
        if not bot_privkey_hex_str:
            app.logger.warning("bot private key hex missing")
            return

        sogs_key_hex_str = None
        if cp.has_option('sogs', 'sogs_pubkey_hex'):
            sogs_key_hex_str = cp.get('sogs', 'sogs_pubkey_hex')
        if not sogs_key_hex_str:
            app.logger.warning("sogs public key hex missing")
            return

        # Optional configs
        bot_name = "Challenge Bot"
        if cp.has_option('bot', 'name'):
            bot_name = cp.get('bot', 'name')

        bot_retry_limit = 3
        if cp.has_option('bot', 'retry_limit'):
            bot_retry_limit = cp.getint('bot', 'retry_limit')

        bot_write_timeout = 0
        if cp.has_option('bot', 'write_timeout'):
            bot_write_timeout = cp.getint('bot', 'write_timeout')

        bot_refresh_timeout = 60
        if cp.has_option('bot', 'refresh_timeout'):
            bot_refresh_timeout = cp.getint('bot', 'refresh_timeout')

        bot_retry_timeout = 120
        if cp.has_option('bot', 'retry_timeout'):
            bot_retry_timeout = cp.getint('bot', 'retry_timeout')

        sogs_address = config.OMQ_LISTEN
        if cp.has_option('sogs', 'sogs_address'):
            sogs_address = cp.get('sogs', 'sogs_address')

        from nacl.public import PublicKey

        sogs_key = PublicKey(HexEncoder.decode(str.encode(sogs_key_hex_str)))
        sogs_key_bytes = sogs_key.encode()

        privkey = SigningKey(HexEncoder.decode(str.encode(bot_privkey_hex_str)))
        print(f"privkey: {privkey.encode(HexEncoder)}")
        privkey_bytes = privkey.encode()
        pubkey_bytes = privkey.verify_key.encode()
        print(f"pubkey: {privkey.verify_key.encode(HexEncoder)}")
        bot = ChallengeBot(
            sogs_address,
            sogs_key_bytes,
            privkey_bytes,
            pubkey_bytes,
            bot_name,
            write_timeout=bot_write_timeout,
            retry_limit=bot_retry_limit,
            retry_timeout=bot_retry_timeout,
            refresh_timeout=bot_refresh_timeout
        )

        bot_key = SigningKey(bot.x_pub)

        from .db import query

        if db is not None:
            try:
                with db.transaction():
                    query(
                        "INSERT INTO bots (auth_key, global, approver, subscribe) VALUES (:key, 1, 1, 1)",
                        key=bot_key.encode(),
                    )

                print(f"Bot({bot.x_pub.hex()}) has been added.")
            except sqlalchemy.exc.IntegrityError:
                print(f"Bot({bot.x_pub.hex()}) is already added.")

        bot.run()

    def handle_request_read(self, req):
        room_token = req[b'room_token']
        session_id = req[b'session_id']
        if session_id in self.retry_record:
            if self.retry_record[session_id] >= self.retry_limit:
                return bt_serialize("JAIL FOREVER")

        if session_id in self.retry_jail and room_token in self.retry_jail[session_id]:
            if time() > self.retry_jail[session_id][room_token]:
                delete(self.retry_jail, session_id, room_token)
            else:
                return bt_serialize("JAIL")

        if session_id in self.pending_requests and room_token in self.pending_requests[session_id]:
            return bt_serialize("OK")
        print(f"request_read from {session_id}, id={req[b'user_id']}, room={room_token}")
        return self.post_challenge(room_token, session_id)

    def post_challenge(self, room_token, session_id):
        try:
            if session_id in self.pending_delete and room_token in self.pending_delete[session_id]:
                self.delete_messages(self.pending_delete[session_id][room_token])
                delete(self.pending_delete, session_id, room_token)

            self.refresh_capcha_handler(session_id, room_token)
            captcha = self.challenges[session_id][room_token][0]
            file_path = captcha.file_name
            file_meta = self.upload_file(file_path, room_token)

            body = f"{captcha.question} "

            refresh_times_left = self.retry_limit
            if session_id in self.retry_record and room_token in self.retry_record:
                refresh_times_left -= self.retry_record[session_id][room_token]
            remaining = f"{refresh_times_left} " + "time" + ("s" if refresh_times_left > 1 else "")
            body += (f"You have hit the limit of refreshing the challenge. "
                     f"Please try to solve the current challenge by reacting the emoji in the image.") \
                if refresh_times_left == 0 \
                else (f"You can refresh the picture by reacting with \U0001F504. "
                      f"You have {remaining} remaining to refresh.")

            msg_id = self.post_message(
                room_token,
                body,
                whisper_target=session_id,
                no_bots=True,
                files=[file_meta,]
            )
            print(f'Challenge message id: {msg_id}')
            if msg_id:
                if refresh_times_left > 0:
                    react_resp = self.post_reactions(
                        room_token, msg_id, self.refresh_reaction
                    )
                    print(f'React response: {react_resp}')
                    if b'error' in react_resp:
                        print(f"Error adding reactions to whisper: {react_resp[b'error']}")
                        return bt_serialize("ERROR")
                if session_id not in self.pending_requests:
                    self.pending_requests[session_id] = dict()
                self.pending_requests[session_id][room_token] = msg_id
        except:
            import traceback
            print(traceback.format_exc())
        return bt_serialize("OK")

    def refresh_capcha_handler(self, session_id, room_token):
        if session_id not in self.challenges:
            self.challenges[session_id] = dict()
        self.challenges[session_id][room_token] = (self.captcha_manager.refresh(), time())

    def handle_refresh(self, msg_id, session_id, room_token):
        if session_id not in self.retry_record or room_token not in self.retry_record[session_id]:
            self.retry_record[session_id][room_token] = 0
        if self.retry_record[session_id][room_token] >= self.retry_limit:
            return

        timeout = self.refresh_timeout - (time() - self.challenges[session_id][room_token][1])
        if timeout > 0:
            msg_id = self.post_message(
                room_token,
                f"You can refresh in {timeout} second {'s' if timeout > 1 else ''}.",
                whisper_target=session_id,
                no_bots=True
            )
            print(f'Refresh timeout message id: {msg_id}')
            if session_id not in self.pending_delete or room_token not in self.pending_delete[session_id]:
                self.pending_delete[session_id][room_token] = []
            self.pending_delete[session_id][room_token].append(msg_id)
        else:
            self.retry_record[session_id][room_token] += 1
            self.delete_message(msg_id)
            self.post_challenge(room_token, session_id)

    def handle_success(self, msg_id, session_id, room_token):
        if self.write_timeout == 0:
            self.post_message(
                room_token,
                "Congrats! You can read and write now.",
                whisper_target=session_id,
                no_bots=True,
            )
            # Grant read and write permission immediately after receiving the correct reaction
            self.set_user_room_permissions(
                room_token=room_token, user_session_id=session_id, sec_from_now=None, read=True, write=True
            )
        else:
            self.post_message(
                room_token,
                f"Congrats! You can read now. You will be able to write in {self.write_timeout} seconds.",
                whisper_target=session_id,
                no_bots=True,
            )
            # Grant read permission immediately after receiving the correct reaction
            self.set_user_room_permissions(
                room_token=room_token, user_session_id=session_id, sec_from_now=None, read=True
            )
            # Grant write permission after {self.write_timeout} time
            self.set_user_room_permissions(
                room_token=room_token, user_session_id=session_id, sec_from_now=self.write_timeout, write=True
            )

        self.delete_message(msg_id)
        delete(self.pending_requests, session_id, room_token)

    def handle_failure(self, msg_id, session_id, room_token):
        if session_id not in self.retry_record or room_token not in self.retry_record:
            self.retry_record[session_id][room_token] = 0

        self.retry_record[session_id][room_token] += 1
        retry_times_left = self.retry_limit - self.retry_record[session_id][room_token]
        remaining = f"{retry_times_left} " + "attempt" + ("s" if retry_times_left > 1 else "")
        body = (f"Incorrect choice. I will send you another image in {self.retry_timeout} seconds. "
                f"You have {remaining} remaining.") if retry_times_left > 0 else \
            (f"You have failed to identify the emoji in the image {self.retry_limit} times. "
             f"Please contact the community administrator for assistance.")

        response_msg_id = self.post_message(
            room_token,
            body,
            whisper_target=session_id,
            no_bots=True,
        )
        self.retry_jail[session_id][room_token] = time() + self.retry_timeout
        self.pending_delete[session_id][room_token].append(response_msg_id)

        self.delete_message(msg_id)
        delete(self.pending_requests, session_id, room_token)

    def reaction_posted(self, m: oxenmq.Message):
        req = bt_deserialize(m.dataview()[0])
        print(f"reaction_posted, req = {req}")
        msg_id = req[b'msg_id']
        session_id = req[b'session_id']
        room_token = req[b'room_token']
        if (
                session_id in self.pending_requests
                and room_token in self.pending_requests[session_id]
                and msg_id == self.pending_requests[session_id][room_token]
                and session_id in self.challenges
                and room_token in self.challenges[session_id]
                and self.challenges[session_id][room_token] is not None
        ):
            print(f"reaction_posted, correct session_id, room, and msg_id")
            reaction = req[b'reaction'].decode('utf-8')

            if reaction == self.refresh_reaction:
                print(f"{session_id} request refreshing challenge.")
                self.handle_refresh(msg_id, session_id, room_token)
            elif reaction == self.challenges[session_id][room_token][0].answer:
                print(f"Granting permissions to {session_id} for room with token {room_token}")
                self.handle_success(msg_id, session_id, room_token)
            else:
                print(f"Wrong answer! Can't grant permission to {session_id}")
                self.handle_failure(msg_id, session_id, room_token)


