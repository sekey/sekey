# SeKey

[![Build Status][build-image]][build-link]
[![MIT Licensed][license-image]][license-link]

<p align="center">
  <img src="https://raw.githubusercontent.com/ntrippar/sekey/master/assets/screenshot.png" alt="SeKey" width="80%" height="80%" />
</p>

## About
SeKey is a SSH Agent that allow users to authenticate to UNIX/Linux SSH servers using the Secure Enclave

## How it Works?
The Secure Enclave is a hardware-based key manager that’s isolated from the main processor to provide an extra layer of security. When you store a private key in the Secure Enclave, you never actually handle the key, making it difficult for the key to become compromised. Instead, you instruct the Secure Enclave to create the key, securely store it, and perform operations with it. You receive only the output of these operations, such as encrypted data or a cryptographic signature verification outcome.


### Limitations
* Only support MacBook Pro with the Touch Bar and Touch ID
* Can’t import preexisting key
* Stores only 256-bit elliptic curve private key

## Install

**Homebrew**

Unfortunately, I can't make a Homebrew formula because KeyChain API requires entitlements, so the binary has to be signed to work, still you can use [Homebrew Cask](https://caskroom.github.io/)

**Homebrew Cask**
1. Install Sekey
```sh
brew install --cask sekey
```
2. Append the following line to your `~/.bash_profile` or `~/.zshrc`
```sh
export SSH_AUTH_SOCK=$HOME/.sekey/ssh-agent.ssh
```
_or_

2. Add the following line you your `~/.ssh/config` or `/etc/ssh/ssh_config`
```
IdentityAgent ~/.sekey/ssh-agent.ssh
```


**Pkg Installer**
1. Go to [Releases](https://github.com/ntrippar/sekey/releases/) and download the pkg release
2. Install the application using the pkg.
3. Set enviroment variables and fix the path of sekey folder.
```
export PATH=$PATH:/Applications/SeKey.app/Contents/MacOS
export SSH_AUTH_SOCK=$HOME/.sekey/ssh-agent.ssh
```

**Manual Installation**
1. Go to [Releases](https://github.com/ntrippar/sekey/releases/) and download the zip release
2. Place the App in the Applications folder.
3. Go to ~/Library/LaunchAgents
4. Create the file com.ntrippar.sekey.plist
5. Paste the following into the file and fix the path of the sekey binary:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ntrippar.sekey</string>
    <key>ProgramArguments</key>
    <array>
        <string>/absolute/path/to/SeKey.app/Contents/MacOS/sekey</string>
        <string>--daemon</string>
    </array>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>

```
4. Fix permissions
```sh
chown youruser:staff /absolute/path/to/SeKey.app/Contents/MacOS/sekey
```
5. Load the agent to the user account:
```sh
launchctl load -F ~/Library/LaunchAgents/com.ntrippar.sekey.plist
```
6. Set enviroment variables and fix the path of sekey folder.
```
export PATH=$PATH:/path/to/SeKey.app/Contents/MacOS
export SSH_AUTH_SOCK=$HOME/.sekey/ssh-agent.ssh
```

## Usage

For the help menu:

```sh
ntrippar@macbookpro:~% sekey -h
SeKey 1.0
Nicolas Trippar <ntrippar@gmail.com>
Use Secure Enclave for SSH Authentication

USAGE:
    sekey [FLAGS] [OPTIONS]

FLAGS:
        --daemon       Run the daemon
    -h, --help         Prints help information
        --list-keys    List all keys
    -V, --version      Prints version information

OPTIONS:
        --delete-keypair <ID>         Deltes the keypair
        --export-key <ID>             export key to OpenSSH Format
        --generate-keypair <LABEL>    Generate a key inside the Secure Enclave
```


**Examples**

Create KeyPair inside the Secure Enclave:

```sh
ntrippar@macbookpro:~% sekey --generate-keypair "Github Key"
Keypair Github Key sucessfully generated

```

List keys in the secure enclave:

```sh
ntrippar@macbookpro:~% sekey --list-keys

┌────────────────────┬──────────────────────────────────────────────────┐
│       Label        │                        ID                        │
├────────────────────┼──────────────────────────────────────────────────┤
│     Github Key     │     d179eb4c2d6a242de64e82240b8b6e611cf0d729     │
└────────────────────┴──────────────────────────────────────────────────┘
```

Export public key to OpenSSH format:

```sh
ntrippar@macbookpro:~% sekey --export-key d179eb4c2d6a242de64e82240b8b6e611cf0d729
ecdsa-sha2-nistp25 AAAAEmVjZHNhLXNoYTItbmlzdHAyNQAAAAhuaXN0cDI1NgAAAEEE8HM7SBdu3yOYkmF0Wnj/q8t2NJC6JYJWZ4IyvkOVIeUs6mi4B424bAjhZ4Awgk5ax9r25RB3Q8tL2/7J/3xchQ==
```

Delete Keypair:

```sh
ntrippar@macbookpro:~% sekey --delete-keypair d179eb4c2d6a242de64e82240b8b6e611cf0d729
Key d179eb4c2d6a242de64e82240b8b6e611cf0d729 sucessfully deleted
```

Use key for a specific host:

1. export the public key from sekey and save it to a file
```sh
ntrippar@macbookpro:~% sekey --export-key d179eb4c2d6a242de64e82240b8b6e611cf0d729 > ~/.ssh/example.com.pub
```
2. on the ssh config file located in `~/.ssh/config` we should add a entry so the ssh only query that key for the given host

```
Host example.com
    IdentityFile ~/.ssh/example.com.pub
    IdentitiesOnly yes
```

## How to Build

**Build**

Sekey is built with [Cargo](https://crates.io/), the Rust package manager.

```sh
git clone https://github.com/ntrippar/sekey
cd sekey
cargo build --release
```


**Sign**

SeKey utilizes the KeyChain API on MacOS, for using it the app needs to be signed and have the correct entitlements.

You need to change the sign parameter to match your own signing key

Listing keys

```sh
security find-identity -v -p codesigning
```

Sign

```sh
codesign --force --identifier "com.ntrippar.sekey" --sign "Developer ID Application: Nicolas Trippar (5E8NNEEMLP)" --entitlements ./assets/sekey.entitlements --timestamp=none ./bundle/SeKey.app
```

**Package**

```sh
cp ./target/release/sekey ./bundle/Applications/SeKey.app/Contents/MacOS/sekey
```

if needed to create a pkg installer
```sh
pkgbuild --analyze --root ./bundle/ SeKey.plist

pkgbuild --sign "Developer ID Installer: Nicolas Trippar (5E8NNEEMLP)" --identifier com.ntrippar.sekey --root ./bundle/ --scripts ./install-scripts --component-plist ./Sekey.plist ./sekey.pkg
```

## Contribute
Members of the open-source community are encouraged to submit pull requests directly through GitHub.

[build-image]: https://travis-ci.org/sekey/sekey.svg?branch=master
[build-link]: https://travis-ci.org/sekey/sekey
[license-image]: https://img.shields.io/github/license/sekey/sekey.svg
[license-link]: https://github.com/sekey/sekey/blob/master/LICENSE

