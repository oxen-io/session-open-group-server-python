# SOGS CAPTCHA Plugin

Once installed (via [install-uwsgi.md](manually)) and a room is set up already (following [administration.md]()), 
you can add a CAPTCHA plugin by following the instruction below.

Note: When running from a session-pysogs project source code directory then you must run `python3
-msogs` from the `session-pysogs` directory instead of the `sogs` command.

## Step 1: Disable the Read and Write permission of your room

```bash
sogs --remove-perms "rw"
```

## Step 2: Adjust configuration

### captcha.ini

Copy the `captcha.ini.sample` to `captcha.ini`:

```bash
cp captcha.ini.sample captcha.ini
```

and edit it to change relevant config settings including privkey_hex, sogs_pubkey_hex, and sogs_address.
Other settings such as plugin name can also be altered if required.

```ini
privkey_hex = 32_BYTES_PRIVATE_KEY_HEX
sogs_pubkey_hex = SOGS_PUBLIC_KEY_HEX
sogs_address = OXENMQ_ADDRESS
name = DISPLAY_NAME_OF_PLUGIN
```

### uwsgi.ini

Uncomment (remove the `;`) this line in `uwsgi.ini`, so the CAPTCHA plugin will be running as part of the sogs:
```ini
;mule = sogs.mule:run_captcha
```

## Step 3: Restart SOGS

Restart the SOGS service by:

```bash
uwsgi uwsgi-sogs.ini
```

## Additional Note:

`python-magic` and `exif` need to be installed:

```bash
pip install python-magic exif
```

`session-util` needs to be installed:

```bash
apt install python3-session-util
```

if a `chdir` is set in `uwsgi.ini`, the `NotoColorEmoji.ttf` needs be copied to the `chdir`:

```bash
cp sogs/plugins/NotoColorEmoji.ttf [chdir]/NotoColorEmoji.ttf
```

