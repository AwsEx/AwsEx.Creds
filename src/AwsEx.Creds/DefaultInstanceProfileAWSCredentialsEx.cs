using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Runtime;
using Amazon.Util;

namespace AwsEx.Creds
{
    /// <summary>
    ///     AWS SDK version of this class has really a terrible race condition that allows all the callers to
    ///     attempt to load their own creds, this is an attempt to fix it.
    /// </summary>
    internal class DefaultInstanceProfileAWSCredentialsEx : AWSCredentials, IDisposable
    {
        private static readonly Lazy<DefaultInstanceProfileAWSCredentialsEx> InstanceLazy = new Lazy<DefaultInstanceProfileAWSCredentialsEx>(() => new DefaultInstanceProfileAWSCredentialsEx());

        private readonly Task _credentialsRetrieverTimer;
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1);
        private bool _disposed;
        private ImmutableCredentials _lastRetrievedCredentials;

        private DefaultInstanceProfileAWSCredentialsEx()
        {
            _credentialsRetrieverTimer = Task.Run(async () =>
            {
                while (!_disposed)
                    try
                    {
                        _lastRetrievedCredentials = FetchCredentials();
                        await Task.Delay(RefreshRate);
                    }
                    catch (Exception ex)
                    {
                        Error?.Invoke("Error in RenewCredentials", ex);
                        await Task.Delay(ErrorRefreshRate);
                    }
            });
        }

        /// <summary>
        ///     Action that is called if there is an error, wire this up to a log
        /// </summary>
        public Action<string, Exception> Error { get; set; }

        /// <summary>
        ///     Action that is called before fetching new creds
        /// </summary>
        public Action BeforeFetch { get; set; }

        /// <summary>
        ///     If an error is encountered we wait this long before retrying
        /// </summary>
        public static TimeSpan ErrorRefreshRate { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        ///     If creds were received successfully we wait this long before refreshing them
        /// </summary>
        private static TimeSpan RefreshRate { get; } = TimeSpan.FromMinutes(15);

        public static DefaultInstanceProfileAWSCredentialsEx Instance => InstanceLazy.Value;

        public void Dispose()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(DefaultInstanceProfileAWSCredentialsEx));
            _disposed = true;
            _credentialsRetrieverTimer.GetAwaiter().GetResult();
        }

        /// <summary>
        ///     Returns a copy of the most recent instance profile credentials sync
        /// </summary>
        public override ImmutableCredentials GetCredentials()
        {
            return GetCredentialsAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        ///     Returns a copy of the most recent instance profile credentials async
        /// </summary>
        public override async Task<ImmutableCredentials> GetCredentialsAsync()
        {
            if (!EC2InstanceMetadata.IsIMDSEnabled) throw new AmazonServiceException("Unable to retrieve credentials.");

            var immutableCredentials = _lastRetrievedCredentials?.Copy();
            if (immutableCredentials != null) return immutableCredentials;

            await _semaphore.WaitAsync().ConfigureAwait(false);
            try
            {
                immutableCredentials = _lastRetrievedCredentials?.Copy();
                if (immutableCredentials != null) return immutableCredentials;

                return _lastRetrievedCredentials = FetchCredentials();
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private ImmutableCredentials FetchCredentials()
        {
            BeforeFetch?.Invoke();

            var securityCredentials = EC2InstanceMetadata.IAMSecurityCredentials;
            if (securityCredentials == null)
                throw new AmazonServiceException("Unable to get IAM security credentials from EC2 Instance Metadata Service.");

            var index = securityCredentials.Keys.FirstOrDefault();
            if (string.IsNullOrEmpty(index))
                throw new AmazonServiceException("Unable to get EC2 instance role from EC2 Instance Metadata Service.");

            var credentialMetadata = securityCredentials[index];
            if (credentialMetadata == null) throw new AmazonServiceException("Unable to get credentials for role \"" + index + "\" from EC2 Instance Metadata Service.");

            return new ImmutableCredentials(credentialMetadata.AccessKeyId, credentialMetadata.SecretAccessKey, credentialMetadata.Token);
        }
    }
}