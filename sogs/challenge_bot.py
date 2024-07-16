from bot import *
from captcha import Captcha


class ChallengeBot(Bot):

    def __init__(
            self,
            sogs_address,
            sogs_pubkey,
            privkey,
            pubkey,
            display_name,
            retry_timeout=120,
            write_timeout=120,
    ):
        self.refresh_reaction = "\U0001F504"
        self.pending_requests = {}  # map {session_id : {room_token : msg_id } }
        self.retry_jail = {}
        self.retry_timeout = retry_timeout
        self.write_timeout = write_timeout
        self.challenges = {}  # map {session_id : Captcha }
        self.refresh_record = {}  # map {session_id: [refresh_timestamp]}

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
        self.refresh_capcha_handler(session_id)
        # TODO: Upload the image
        msg_id = self.post_message(
                    room_token,
                    f"{self.challenges[session_id].question} You can refresh the picture by reacting \U0001F504.",
                    whisper_target=session_id,
                    no_bots=True
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
        if self.challenges[session_id] is not None:
            self.challenges[session_id].refresh()
        else:
            self.challenges[session_id] = Captcha()

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
                self.refresh_capcha_handler(session_id)
                self.post_message(
                    room_token,
                    self.challenges[session_id].question,
                    whisper_target=session_id,
                    no_bots=True
                )
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