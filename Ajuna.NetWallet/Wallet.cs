using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ajuna.NetApi;
using Ajuna.NetApi.Model.FrameSystem;
using Ajuna.NetApi.Model.Rpc;
using Ajuna.NetApi.Model.Types;
using Chaos.NaCl;
using NLog;
using Schnorrkel;
using Schnorrkel.Keys;

namespace Ajuna.NetWallet
{
    /// <summary>
    /// Basic Wallet implementation
    /// TODO: Make sure that a live runtime change is handled correctly.
    /// </summary>
    public class Wallet
    {
        private const string Websocketurl = "ws://127.0.0.1:9944";

        private const string FileType = "dat";

        private const string DefaultWalletName = "wallet";

        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly CancellationTokenSource _connectTokenSource;

        private readonly Random _random = new Random();

        private readonly IWalletSubscriptionHandler _subscriptionHandler;

        private FileStore _walletFile;

        /// <summary>
        /// Constructor
        /// </summary>
        public Wallet(IWalletSubscriptionHandler subscriptionHandler)
        {
            _subscriptionHandler = subscriptionHandler;
            _connectTokenSource = new CancellationTokenSource();
        }

        /// <summary>
        /// Gets a value indicating whether this instance is unlocked.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is unlocked; otherwise, <c>false</c>.
        /// </value>
        public bool IsUnlocked => Account != null;

        /// <summary>
        /// Gets a value indicating whether this instance is created.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is created; otherwise, <c>false</c>.
        /// </value>
        public bool IsCreated => _walletFile != null;

        public Account Account { get; private set; }

        public AccountInfo AccountInfo { get; private set; }

        public ChainInfo ChainInfo { get; private set; }

        public SubstrateClient Client { get; private set; }

        /// <summary>
        /// Gets a value indicating whether this instance is connected.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is connected; otherwise, <c>false</c>.
        /// </value>
        public bool IsConnected => Client != null && Client.IsConnected;

        /// <summary>
        /// Gets a value indicating whether this instance is online.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is online; otherwise, <c>false</c>.
        /// </value>
        public bool IsOnline => IsConnected && _subscriptionHandler.IsSubscribedToNewHeadChanges &&
                              _subscriptionHandler.IsSubscribedToFinalizedHeadsChanges ;

        /// <summary>
        /// Determines whether [is valid wallet name] [the specified wallet name].
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns>
        ///   <c>true</c> if [is valid wallet name] [the specified wallet name]; otherwise, <c>false</c>.
        /// </returns>
        public bool IsValidWalletName(string walletName)
        {
            return walletName.Length > 4 && walletName.Length < 21 &&
                   walletName.All(c => char.IsLetterOrDigit(c) || c.Equals('_'));
        }

        /// <summary>
        /// Determines whether [is valid password] [the specified password].
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>
        ///   <c>true</c> if [is valid password] [the specified password]; otherwise, <c>false</c>.
        /// </returns>
        public bool IsValidPassword(string password)
        {
            return password.Length > 7 && password.Length < 21 && password.Any(char.IsUpper) &&
                   password.Any(char.IsLower) && password.Any(char.IsDigit);
        }

        /// <summary>
        /// Adds the type of the wallet file.
        /// </summary>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public string AddWalletFileType(string walletName)
        {
            return $"{walletName}.{FileType}";
        }

        /// <summary>
        /// Occurs when [chain information updated].
        /// </summary>
        public event EventHandler<ChainInfo> ChainInfoUpdated;

        /// <summary>
        /// Occurs when [account information updated].
        /// </summary>
        public event EventHandler<AccountInfo> AccountInfoUpdated;

        /// <summary>
        /// Load an existing wallet
        /// </summary>
        /// <param name="walletName"></param>
        /// <returns></returns>
        public bool Load(string walletName = DefaultWalletName)
        {
            if (!IsValidWalletName(walletName))
            {
                Logger.Warn("Wallet name is invalid, please provide a proper wallet name. [A-Za-Z_]{20}.");
                return false;
            }

            var walletFileName = AddWalletFileType(walletName);
            if (!Caching.TryReadFile(walletFileName, out _walletFile))
            {
                Logger.Warn($"Failed to load wallet file '{walletFileName}'!");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Creates the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="mnemonic">The mnemonic.</param>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public async Task<bool> CreateAsync(string password, string mnemonic, string walletName = DefaultWalletName)
        {
            if (IsCreated)
            {
                Logger.Warn("Wallet already created.");
                return true;
            }

            if (!IsValidPassword(password))
            {
                Logger.Warn(
                    "Password is invalid, please provide a valid password. Minmimum eight characters long and should include digits as well as upper and  lower case letters.");
                return false;
            }

            Logger.Info("Creating new wallet from mnemonic.");

            var seed = Mnemonic.GetSecretKeyFromMnemonic(mnemonic, "Substrate", Mnemonic.BIP39Wordlist.English);

            var randomBytes = new byte[48];

            _random.NextBytes(randomBytes);

            var memoryBytes = randomBytes.AsMemory();

            var pswBytes = Encoding.UTF8.GetBytes(password);

            var salt = memoryBytes.Slice(0, 16).ToArray();

            pswBytes = SHA256.Create().ComputeHash(pswBytes);

            var encryptedSeed =
                ManagedAes.EncryptStringToBytes_Aes(Utils.Bytes2HexString(seed, Utils.HexStringFormat.Pure), pswBytes, salt);

            var miniSecret = new MiniSecret(seed, ExpandMode.Ed25519);
            var getPair = miniSecret.GetPair();

            var keyType = KeyType.Sr25519;
            _walletFile = new FileStore(keyType, getPair.Public.Key, encryptedSeed, salt);

            Caching.Persist(AddWalletFileType(walletName), _walletFile);

            Account = Account.Build(keyType, getPair.Secret.ToBytes(), getPair.Public.Key);

            if (IsOnline)
                await _subscriptionHandler.SubscribeAccountInfoAsync(Client, Account,
                    CallBackAccountChange);

            return true;
        }

        /// <summary>
        /// Creates the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="walletName">Name of the wallet.</param>
        /// <returns></returns>
        public async Task<bool> CreateAsync(string password, string walletName = DefaultWalletName)
        {
            if (IsCreated)
            {
                Logger.Warn("Wallet already created.");
                return true;
            }

            if (!IsValidPassword(password))
            {
                Logger.Warn(
                    "Password isn't is invalid, please provide a proper password. Minmimu eight size and must have upper, lower and digits.");
                return false;
            }

            Logger.Info("Creating new wallet.");

            var randomBytes = new byte[48];

            _random.NextBytes(randomBytes);

            var memoryBytes = randomBytes.AsMemory();

            var pswBytes = Encoding.UTF8.GetBytes(password);

            var salt = memoryBytes.Slice(0, 16).ToArray();

            var seed = memoryBytes.Slice(16, 32).ToArray();

            pswBytes = SHA256.Create().ComputeHash(pswBytes);

            var encryptedSeed =
                ManagedAes.EncryptStringToBytes_Aes(Utils.Bytes2HexString(seed, Utils.HexStringFormat.Pure), pswBytes,
                    salt);

            Ed25519.KeyPairFromSeed(out var publicKey, out var privateKey, seed);

            var keyType = KeyType.Ed25519;
            _walletFile = new FileStore(keyType, publicKey, encryptedSeed, salt);

            Caching.Persist(AddWalletFileType(walletName), _walletFile);

            Account = Account.Build(keyType, privateKey, publicKey);

            if (IsOnline)
                await _subscriptionHandler.SubscribeAccountInfoAsync(Client, Account,
                    CallBackAccountChange);
            return true;
        }

        /// <summary>
        /// Unlocks the asynchronous.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="noCheck">if set to <c>true</c> [no check].</param>
        /// <returns></returns>
        /// <exception cref="Exception">Public key check failed!</exception>
        public async Task<bool> UnlockAsync(string password, bool noCheck = false)
        {
            if (IsUnlocked || !IsCreated)
            {
                Logger.Warn("Wallet is already unlocked or doesn't exist.");
                return IsUnlocked && IsCreated;
            }

            Logger.Info("Unlock new wallet.");

            try
            {
                var pswBytes = Encoding.UTF8.GetBytes(password);

                pswBytes = SHA256.Create().ComputeHash(pswBytes);

                var seed = ManagedAes.DecryptStringFromBytes_Aes(_walletFile.EncryptedSeed, pswBytes, _walletFile.Salt);

                byte[] publicKey = null;
                byte[] privateKey = null;
                switch (_walletFile.KeyType)
                {
                    case KeyType.Ed25519:
                        Ed25519.KeyPairFromSeed(out publicKey, out privateKey, Utils.HexToByteArray(seed));
                        break;
                    case KeyType.Sr25519:
                        var miniSecret = new MiniSecret(Utils.HexToByteArray(seed), ExpandMode.Ed25519);
                        var getPair = miniSecret.GetPair();
                        privateKey = getPair.Secret.ToBytes();
                        publicKey = getPair.Public.Key;
                        break;
                }

                if (noCheck || !publicKey.SequenceEqual(_walletFile.PublicKey))
                    throw new Exception("Public key check failed!");

                Account = Account.Build(_walletFile.KeyType, privateKey, publicKey);
            }
            catch (Exception exception)
            {
                Logger.Warn($"Couldn't unlock the wallet with this password. {exception}");
                return false;
            }


            if (IsOnline)
                await _subscriptionHandler.SubscribeAccountInfoAsync(Client, Account,
                    CallBackAccountChange);
            return true;
        }

        /// <summary>
        /// Tries the sign message.
        /// </summary>
        /// <param name="signer">The signer.</param>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException">KeyType {signer.KeyType} is currently not implemented for signing.</exception>
        public bool TrySignMessage(Account signer, byte[] data, out byte[] signature)
        {
            signature = null;

            if (signer?.PrivateKey == null)
            {
                Logger.Warn("Account or private key doesn't exists.");
                return false;
            }

            switch (signer.KeyType)
            {
                case KeyType.Ed25519:
                    signature = Ed25519.Sign(data, signer.PrivateKey);
                    break;
                case KeyType.Sr25519:
                    signature = Sr25519v091.SignSimple(signer.Bytes, signer.PrivateKey, data);
                    break;
                default:
                    throw new NotImplementedException(
                        $"KeyType {signer.KeyType} is currently not implemented for signing.");
            }

            return true;
        }

        /// <summary>
        /// Verifies the signature.
        /// </summary>
        /// <param name="signer">The signer.</param>
        /// <param name="data">The data.</param>
        /// <param name="signature">The signature.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException">KeyType {signer.KeyType} is currently not implemented for verifying signatures.</exception>
        public bool VerifySignature(Account signer, byte[] data, byte[] signature)
        {
            switch (signer.KeyType)
            {
                case KeyType.Ed25519:
                    return Ed25519.Verify(signature, data, signer.Bytes);
                case KeyType.Sr25519:
                    return Sr25519v091.Verify(signature, signer.Bytes, data);
                default:
                    throw new NotImplementedException(
                        $"KeyType {signer.KeyType} is currently not implemented for verifying signatures.");
            }
        }

        /// <summary>
        /// Subscribe to AccountInfo asynchronous
        /// </summary>
        /// <returns></returns>
        public async Task SubscribeAccountInfoAsync()
        {
            await _subscriptionHandler.SubscribeAccountInfoAsync(Client, Account,
                newAccountInfo => { AccountInfo = newAccountInfo; });
        }

        /// <summary>
        /// Connects the asynchronous.
        /// </summary>
        /// <param name="webSocketUrl">The web socket URL.</param>
        private async Task ConnectAsync(string webSocketUrl)
        {
            Logger.Info($"Connecting to {webSocketUrl}");

            Client = new SubstrateClient(new Uri(webSocketUrl));

            await Client.ConnectAsync(_connectTokenSource.Token);

            if (!IsConnected)
            {
                Logger.Error("Connection couldn't be established!");
                return;
            }

            var systemName = await Client.System.NameAsync(_connectTokenSource.Token);

            var systemVersion = await Client.System.VersionAsync(_connectTokenSource.Token);

            var systemChain = await Client.System.ChainAsync(_connectTokenSource.Token);

            ChainInfo = new ChainInfo(systemName, systemVersion, systemChain, Client.RuntimeVersion);

            Logger.Info($"Connection established to {ChainInfo}");
        }

        /// <summary>
        /// Starts the asynchronous.
        /// </summary>
        /// <param name="webSocketUrl">The web socket URL.</param>
        public async Task StartAsync(string webSocketUrl = Websocketurl)
        {
            // disconnect from node if we are already connected to one.
            if (IsConnected)
            {
                Logger.Warn($"Wallet already connected, disconnecting from {ChainInfo} now");
                await StopAsync();
            }

            // connect wallet
            await ConnectAsync(webSocketUrl);

            if (IsConnected)
            {
                Logger.Warn("Starting subscriptions now.");
                await StartOrRefreshSubscriptionsAsync();
            }
        }

        
        /// <summary>
        /// Refreshes the subscriptions asynchronous.
        /// </summary>
        public async Task StartOrRefreshSubscriptionsAsync()
        {
            Logger.Info("Refreshing all subscriptions");

            // unsubscribe all subscriptions
            await _subscriptionHandler.UnsubscribeAllAsync(Client);
            
            await _subscriptionHandler.StartOrRefreshSubscriptionsAsync(Client,Account,CallBackFinalizedHeads,
                newAccountInfo => { AccountInfo = newAccountInfo;});
        }

 
        /// <summary>
        /// Unsubscribes all asynchronous.
        /// </summary>
        public async Task UnsubscribeAllAsync()
        {
            await _subscriptionHandler.UnsubscribeAllAsync(Client);
        }

        /// <summary>
        /// Stops the asynchronous.
        /// </summary>
        public async Task StopAsync()
        {
            // unsubscribe all subscriptions
            await UnsubscribeAllAsync();

            //ChainInfoUpdated -= Wallet_ChainInfoUpdated;

            // disconnect wallet
            await Client.CloseAsync(_connectTokenSource.Token);
        }

        protected virtual void CallBackFinalizedHeads(Header header)
        {
            ChainInfo.UpdateFinalizedHeader(header);

            ChainInfoUpdated?.Invoke(this, ChainInfo);
        }

        /// <summary>
        /// Calls the back account change.
        /// </summary>
        /// <param name="newAccountInfo"></param>
        protected virtual void CallBackAccountChange(AccountInfo newAccountInfo)
        {
            AccountInfo = newAccountInfo;
            AccountInfoUpdated?.Invoke(this, AccountInfo);
        }
    }
}