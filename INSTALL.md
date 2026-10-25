# Installing Bouncer

There are three parts. Part A happens **once**. Part B happens **once per release** (it builds the SD card image). Part C happens **for every household**.

You need: a free GitHub account with two-factor authentication, a Windows/Mac computer with Python 3 (python.org), a USB stick for your signing key, and per household a Raspberry Pi 3 B or newer (Pi 4 recommended), its official power supply (Pi 3: micro-USB 5 V 2.5 A; Pi 4: USB-C), a 16–32 GB "high endurance" microSD card, a case and a network cable.

---

## Part A · One-time setup (about 30 minutes)

1. **Create the repository.** On github.com: *New repository* → name `bouncer` → **Public** → *Create*. Upload all files from this folder (drag and drop on the repository page, or use GitHub Desktop).
2. **Install the Python helper** on your computer, in a terminal (Windows: "Command Prompt"):
   ```
   pip install cryptography
   ```
3. **Create your signing key**, in the Bouncer folder:
   ```
   python tools/keygen.py
   ```
   Choose a long passphrase. This creates `bouncer-signing-key.pem` (private) and updates `keys/release.pub` (public).
4. **Store the private key safely:** copy `bouncer-signing-key.pem` to the USB stick and to a second backup (e.g. another USB stick in a drawer). Delete it from the computer. **Never upload it to GitHub.** If it is lost, existing Bouncers can't receive updates until they are re-flashed.
5. **Upload `keys/release.pub`** to GitHub (replace the placeholder file).

## Part B · Build the SD card image (about 45 minutes, automatic)

1. On GitHub open **Actions** → **Build SD card image** → **Run workflow**.
2. When it is green (30–60 minutes), open the run and download **bouncer-image** at the bottom. Unzip it: you get `bouncer-….img.xz`.

When you publish a release (Part D), the image is also built automatically and attached to the release.

## Part C · Prepare a Bouncer for a household (10 minutes)

1. Install **Raspberry Pi Imager** (raspberrypi.com/software).
2. Imager → *Choose OS* → **Use custom** → select `bouncer-….img.xz` → choose the SD card → *Next*. When Imager asks about OS customisation, choose **No** (Bouncer needs none). Write the card.
3. Take the card out and put it back in. A drive named **bootfs** appears. Open **`bouncer-pin.txt`** and write the household's first PIN after `PIN=`, for example `PIN=4719`. Save. Eject the card.
4. Put the card into the Pi. Connect the **network cable to the router**, then the **power**.
5. Wait about **3 minutes**. Open **http://bouncer.local** (FRITZ!Box: also **http://bouncer.fritz.box**, or the Pi's address shown in the router's device list).
6. Enter the PIN. The household chooses its own PIN and emails itself the recovery code.
7. **Router setting:** follow the router guide (dashboard → *Help* → *Router guide (PDF)*). For a FRITZ!Box: *Home Network › Network › Network Settings › IPv4 Settings › Local DNS server* = Bouncer's address, plus the IPv6 setting.
8. Turn Wi-Fi off and on on a phone. The dashboard should show **"Your router sends all devices through Bouncer"** and **"This device is protected"**.

**Without a network cable:** plug in only the power. After about 2 minutes a Wi-Fi network called **Bouncer-Setup** appears. Connect a phone to it; a page opens where you choose the home Wi-Fi and type its password. Then continue with step 5. (A cable is more reliable for a DNS server.)

## Part D · Releasing an update to all Bouncers

1. Change the code and raise the number in `VERSION` (e.g. `1.0.0` → `1.0.1`).
2. With the USB stick plugged in:
   ```
   python tools/make_release.py --key E:\bouncer-signing-key.pem
   ```
   (Mac: `--key /Volumes/USB/bouncer-signing-key.pem`.) This creates two files in `dist/`.
3. Upload the changed code to GitHub. Then **Releases** → *Draft a new release* → tag **`v1.0.1`** → attach both files from `dist/` → **Publish release**.
4. Every Bouncer installs it during the following night (between 02:00 and 05:00). If the new version fails its self-test, the Bouncer goes back to the previous version by itself and the dashboard says so.

All Bouncers update the same night, so test changes first on your computer (`python3 -m pytest` and `python3 tools/devserver.py`) and, if you can, on your own Bouncer with `install.sh`.

## What updates by itself

| What | How often | Who does it |
|---|---|---|
| Block lists | weekly | each Bouncer |
| Bouncer software and dashboard | nightly check | each Bouncer, from your signed GitHub releases |
| Raspberry Pi OS security updates | daily check, reboot at 04:30 if needed | each Bouncer |
| Router setting, hardware, major OS upgrades | – | by hand |

## Good to know

- **Forgotten PIN:** the household uses its recovery code ("Forgot your PIN?"). If that is lost too: SD card into a computer, create `bouncer-reset-pin.txt` on the bootfs drive containing `PIN=1234` (new PIN), card back in, power on.
- **Diagnostics:** households can send you the file from *Help › Download diagnostics*. It contains no website names, no device names and no PIN.
- **SSH** is switched off in the image. For your own test Pi you can use `install.sh` on a normal Raspberry Pi OS Lite installation instead (with SSH enabled in Raspberry Pi Imager): `sudo ./install.sh <your-github-name>/bouncer`.
- **Development on a computer:** `python3 tools/devserver.py` shows the dashboard with sample data at http://localhost:8080 (PIN 2580). Tests: `python3 -m pytest`.
