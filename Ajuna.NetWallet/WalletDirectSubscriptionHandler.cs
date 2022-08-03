using System;
using System.Threading;
using System.Threading.Tasks;
using Ajuna.NetApi;
using Ajuna.NetApi.Model.FrameSystem;
using Ajuna.NetApi.Model.Rpc;
using Ajuna.NetApi.Model.SpCore;
using Ajuna.NetApi.Model.Types;
using NLog;

namespace Ajuna.NetWallet
{
    public interface IWalletSubscriptionHandler
    {
        bool IsSubscribedToNewHeadChanges { get; }
        bool IsSubscribedToFinalizedHeadsChanges { get; }
        bool IsSubscribedToAccountInfoChanges { get; }

        /// <summary>
        /// Subscribe to AccountInfo asynchronous
        /// </summary>
        /// <returns></returns>
        Task SubscribeAccountInfoAsync(SubstrateClient client, Account walletAccount, 
            Action<AccountInfo> accountChangeCallBack);

        /// <summary>
        /// Unsubscribes all asynchronous.
        /// </summary>
        Task UnsubscribeAllAsync(SubstrateClient client);

        /// <summary>
        /// Refreshes the subscriptions asynchronous.
        /// </summary>
        Task StartOrRefreshSubscriptionsAsync(
            SubstrateClient client, 
            Account walletAccount,
            Action<Header>  chainInfoChangeCallback,
            Action<AccountInfo> accountChangeCallBack);
    }

    public class WalletSubscriptionHandler : IWalletSubscriptionHandler
    {
        private readonly CancellationTokenSource _connectTokenSource;
        
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public bool IsSubscribedToNewHeadChanges => !String.IsNullOrEmpty(_subscriptionIdNewHead);
        public bool IsSubscribedToFinalizedHeadsChanges => !String.IsNullOrEmpty(_subscriptionIdFinalizedHeads);
        public bool IsSubscribedToAccountInfoChanges => !String.IsNullOrEmpty(_subscriptionAccountInfo);
        
        private string _subscriptionIdNewHead, _subscriptionIdFinalizedHeads, _subscriptionAccountInfo;

        public WalletSubscriptionHandler()
        {
            _connectTokenSource = new CancellationTokenSource();
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
        /// Subscribe to AccountInfo asynchronous
        /// </summary>
        /// <returns></returns>
        public async Task SubscribeAccountInfoAsync(SubstrateClient client, Account walletAccount, 
            Action<AccountInfo> accountChangeCallBack)
        {
            AccountId32 account = new AccountId32();
            account.Create(Utils.GetPublicKeyFrom(walletAccount.Value));
            _subscriptionAccountInfo = await client.SubscribeStorageKeyAsync(Ajuna.NetApi.Model.FrameSystem.SystemStorage.AccountParams(account),
                (subscriptionId, storageChangeSet) => 
                    CallBackAccountChange(storageChangeSet,accountChangeCallBack), _connectTokenSource.Token);
        }
        
        /// <summary>
        /// Unsubscribes all asynchronous.
        /// </summary>
        public async Task UnsubscribeAllAsync(SubstrateClient client)
        {
            if (!string.IsNullOrEmpty(_subscriptionIdNewHead))
            {
                // unsubscribe from new heads
                if (!await client.Chain.UnsubscribeNewHeadsAsync(_subscriptionIdNewHead, _connectTokenSource.Token))
                    Logger.Warn($"Couldn't unsubscribe new heads {_subscriptionIdNewHead} id.");
                _subscriptionIdNewHead = string.Empty;
            }

            if (!string.IsNullOrEmpty(_subscriptionIdNewHead))
            {
                // unsubscribe from finalized heads
                if (!await client.Chain.UnsubscribeFinalizedHeadsAsync(_subscriptionIdFinalizedHeads,
                        _connectTokenSource.Token))
                    Logger.Warn($"Couldn't unsubscribe finalized heads {_subscriptionIdFinalizedHeads} id.");
                _subscriptionIdFinalizedHeads = string.Empty;
            }

            if (!string.IsNullOrEmpty(_subscriptionAccountInfo))
            {
                // unsubscribe from finalized heads
                if (!await client.State.UnsubscribeStorageAsync(_subscriptionAccountInfo, _connectTokenSource.Token))
                    Logger.Warn($"Couldn't unsubscribe storage subscription {_subscriptionAccountInfo} id.");
                _subscriptionAccountInfo = string.Empty;
            }
        }
        
        /// <summary>
        /// Refreshes the subscriptions asynchronous.
        /// </summary>
        public async Task StartOrRefreshSubscriptionsAsync(
            SubstrateClient client, 
            Account walletAccount,
            Action<Header>  chainInfoChangeCallback,
            Action<AccountInfo> accountChangeCallBack)
        {
            Logger.Info("Refreshing all subscriptions");

            // unsubscribe all subscriptions
            await UnsubscribeAllAsync(client);

            // subscribe to new heads
            _subscriptionIdNewHead =
                await client.Chain.SubscribeNewHeadsAsync(CallBackNewHeads, _connectTokenSource.Token);

            // subscribe to finalized heads
            _subscriptionIdFinalizedHeads =
                await client.Chain.SubscribeFinalizedHeadsAsync( ((s, header) => { chainInfoChangeCallback(header); }) , _connectTokenSource.Token);

            if (walletAccount!=null)
                // subscribe to account info
                await SubscribeAccountInfoAsync(client,walletAccount,accountChangeCallBack);
        }
        

        /// <summary>
        /// Calls the back new heads.
        /// </summary>
        /// <param name="subscriptionId">The subscription identifier.</param>
        /// <param name="header">The header.</param>
        protected virtual void CallBackNewHeads(string subscriptionId, Header header)
        {
        }

        /// <summary>
        /// Calls the back finalized heads.
        /// </summary>
        /// <param name="subscriptionId">The subscription identifier.</param>
        /// <param name="header">The header.</param>
        protected virtual void CallBackFinalizedHeads(Header header, ChainInfo chainInfo)
        {
            chainInfo.UpdateFinalizedHeader(header);

            ChainInfoUpdated?.Invoke(this, chainInfo);
        }

        /// <summary>
        /// Calls the back account change.
        /// </summary>
        /// <param name="storageChangeSet">The storage change set.</param>
        /// <param name="callBackAccountChange"></param>
        protected virtual void CallBackAccountChange( StorageChangeSet storageChangeSet, Action<AccountInfo> accountChangeCallBack)
        {
            if (storageChangeSet.Changes == null 
                || storageChangeSet.Changes.Length == 0 
                || storageChangeSet.Changes[0].Length < 2)
            {
                Logger.Warn("Couldn't update account informations. Please check 'CallBackAccountChange'");
                return;
            }

            var accountInfoStr = storageChangeSet.Changes[0][1];

            if (string.IsNullOrEmpty(accountInfoStr))
            {
                Logger.Warn("Couldn't update account informations. Account doesn't exists, please check 'CallBackAccountChange'");
                return;
            }

            var updatedAccountInfo = new AccountInfo();
            updatedAccountInfo.Create(accountInfoStr);
            
            if (accountChangeCallBack != null)
                accountChangeCallBack(updatedAccountInfo);
        }
    }
}