# Ajuna.NetWallet (NETStandard2.0)
![ajuna-Header-1080p_with_logo](https://user-images.githubusercontent.com/17710198/136852531-d9eb47cd-efcd-4c88-bdbf-78dfcbffe287.png)

## What is Ajuna.NetWallet ?
![Build](https://github.com/ajuna-network/Ajuna.NetWallet/actions/workflows/build.yml/badge.svg)
[![Nuget](https://img.shields.io/nuget/v/Ajuna.NetWallet)](https://www.nuget.org/packages/Ajuna.NetWallet/)
[![GitHub issues](https://img.shields.io/github/issues/ajuna-network/Ajuna.NetWallet.svg)](https://github.com/ajuna-network/Ajuna.NetWallet/issues)
[![license](https://img.shields.io/github/license/ajuna-network/Ajuna.NetWallet)](https://github.com/ajuna-network/Ajuna.NetWallet/blob/origin/LICENSE)
[![contributors](https://img.shields.io/github/contributors/ajuna-network/Ajuna.NetWallet)](https://github.com/ajuna-network/Ajuna.NetWallet/graphs/contributors)  

`Ajuna.NetWallet` implements the basic functionality to create an account, and encrypt it on a device based filesystem.

It also:
- Supports mnemonic, AES, SR25519 and ED25519 encryption.
- Encodes and decodes substrate-based address formats in ss58.


`Ajuna.NetWallet` ideally extends [Ajuna.NetApi](https://github.com/ajuna-network/Ajuna.NetApi) which is the basic framework for accessing and handling JSON-RPC connections and handling all standard RPC calls exposed by the `rpc.methods()` of every substrate node.



## Usage Examples


### Check wallet Name and Password validity

```c#

// Check name validity
var wallet = new Wallet();
wallet.IsValidWalletName("1234");     // false
wallet.IsValidWalletName("wal_let"); // true

// Check password validity
wallet.IsValidPassword("1BCDefg");   // false
wallet.IsValidPassword("ABCDefg1"); // true

```


### Create wallet with name, password and mnemonic

```c#
var walletName = "mnemonic_wallet";
var walletPassword = "aA1234dd"
var walletMnemonic = "tornado glad segment lift squirrel top ball soldier joy sudden edit advice";

var wallet = new Wallet();

// KeyType.Sr25519 and KeyType.Ed25519 can be both used. 
wallet.Create(walletPassword, , KeyType.Sr25519, Mnemonic.BIP39Wordlist.English , walletName);

// Confirm that wallet was successfully created
var isCreated = wallet.IsCreated;
```


### Load wallet from device based filesystem and unlock it

```c#
// We will load the wallet that we created in the example above

var walletToUnlock = new Wallet();

walletToUnlock.Load("mnemonic_wallet");

// unlock wallet with password
walletToUnlock.Unlock("aA1234dd");

// Confirm that wallet is unlocked
var isUnlocked = walletToUnlock.IsUnlocked;
```

