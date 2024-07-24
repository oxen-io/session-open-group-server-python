from bot import *
from captcha import CaptchaManager, Captcha


class ChallengeBot(Bot):

    def __init__(
            self,
            sogs_address,
            sogs_pubkey,
            privkey,
            pubkey,
            display_name,
            refresh_limit=5,
            retry_timeout=120,
            write_timeout=120,
    ):
        self.refresh_reaction = "\U0001F504"
        self.pending_requests = {}  # map {session_id : {room_token : msg_id}}
        self.retry_jail = {}
        self.refresh_limit = refresh_limit
        self.retry_timeout = retry_timeout
        self.write_timeout = write_timeout
        self.challenges = {}  # map {session_id : Captcha}
        self.refresh_record = {}  # map {session_id: [refresh_timestamps]}
        self.captcha_manager = CaptchaManager(initial_count=2000)

        Bot.__init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name)
        self.register_request_read_handler(self.handle_request_read)

    def handle_request_read(self, req):
        room_token = req[b'room_token']
        session_id = req[b'session_id']
        if session_id in self.retry_jail:
            if time() > self.retry_jail[session_id]:
                del self.retry_jail[session_id]
            else:
                return bt_serialize("JAIL")

        if session_id in self.pending_requests and room_token in self.pending_requests[session_id]:
            return bt_serialize("OK")
        print(f"request_read from {session_id}, id={req[b'user_id']}, room={room_token}")
        return self.post_challenge(room_token, session_id)

    def post_challenge(self, room_token, session_id):
        self.refresh_capcha_handler(session_id)
        file_name = self.challenges[session_id].captcha_image
        with open(file_name, 'rb') as file:
            file_contents = file.read()
        file_id = self.upload_file(
            filename=file_name,
            file_contents=file_contents,
            room_token=room_token
        )
        msg_id = self.post_message(
            room_token,
            f"{self.challenges[session_id].question} You can refresh the picture by reacting \U0001F504.",
            whisper_target=session_id,
            no_bots=True,
            files=[
                {
                    'id': file_id,
                    'content_type': 'png',
                    'width': Captcha.WIDTH,
                    'height': Captcha.HEIGHT
                }
            ]
        )
        if msg_id:
            react_resp = self.post_reactions(
                room_token, msg_id, self.refresh_reaction
            )
            if b'error' in react_resp:
                print(f"Error adding reactions to whisper: {react_resp[b'error']}")
                return bt_serialize("ERROR")
            if session_id not in self.pending_requests:
                self.pending_requests[session_id] = dict()
            self.pending_requests[session_id][room_token] = msg_id
        return bt_serialize("OK")

    def refresh_capcha_handler(self, session_id):
        self.challenges[session_id] = self.captcha_manager.refresh()

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
                and self.challenges[session_id] is not None
        ):
            print(f"reaction_posted, correct session_id, room, and msg_id")
            reaction = req[b'reaction'].decode('utf-8')

            if reaction == self.refresh_reaction:
                print(f"{session_id} request refreshing challenge.")
                if self.refresh_record[session_id] is None:
                    self.refresh_record[session_id] = []
                if len(self.refresh_record[session_id]) > self.refresh_limit:
                    self.post_message(
                        room_token,
                        f"Whoa, slow down! You may try again in {self.retry_timeout} seconds with a new prompt.",
                        whisper_target=session_id,
                        no_bots=True
                    )
                    self.retry_jail[session_id] = time() + self.retry_timeout
                else:
                    self.refresh_record[session_id].append(time())
                    self.post_challenge(room_token, session_id)
            elif reaction == self.challenges[session_id].answer:
                print(f"Granting permissions to {session_id} for room with token {room_token}")
                # Grant read permission immediately after receiving the correct reaction
                self.set_user_room_permissions(
                    room_token=room_token, user_session_id=session_id, sec_from_now=None, read=True
                )
                # Grant write permission after {self.write_timeout} time
                self.set_user_room_permissions(
                    room_token=room_token, user_session_id=session_id, sec_from_now=self.write_timeout, write=True
                )
                self.post_message(
                    room_token,
                    f"Congrats! You can read now. You will be able to write in {self.write_timeout} seconds.",
                    whisper_target=session_id,
                    no_bots=True,
                )
            else:
                print(f"Wrong answer! Can't grant permission to {session_id}")
                self.post_message(
                    room_token,
                    f"You chose...poorly. You may try again in {self.retry_timeout} seconds with a new prompt.",
                    whisper_target=session_id,
                    no_bots=True,
                )
                self.retry_jail[session_id] = time() + self.retry_timeout

            self.delete_message(msg_id)
            del self.pending_requests[session_id][room_token]
            if len(self.pending_requests[session_id]) == 0:
                del self.pending_requests[session_id]


if __name__ == '__main__':
    server_key_hex = b'0bac1f7b4ec1fbe61f89d6ef95504859622eba175ffe3c50050a94b14f755359'
    bot_privkey_hex = b'489327e8db1e9f6e05c4ad4d75b8bef6aeb8ad78ae6b3d4a74b96455b7438e79'

    from nacl.public import PublicKey

    server_key = PublicKey(HexEncoder.decode(server_key_hex))
    server_key_bytes = server_key.encode()

    privkey = SigningKey(HexEncoder.decode(bot_privkey_hex))
    print(f"privkey: {privkey.encode(HexEncoder)}")
    privkey_bytes = privkey.encode()
    pubkey_bytes = privkey.verify_key.encode()
    print(f"pubkey: {privkey.verify_key.encode(HexEncoder)}")
    bot = ChallengeBot(
        "tcp://127.0.0.1:43210", server_key_bytes, privkey_bytes, pubkey_bytes, "Challenge Bot"
    )
    bot.run()
