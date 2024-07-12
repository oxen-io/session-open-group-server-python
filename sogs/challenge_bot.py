from bot import Bot
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

        Bot.__init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name)

    def handle_refresh_capcha(self):
        pass