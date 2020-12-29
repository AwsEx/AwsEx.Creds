using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.Runtime.Internal.Util;

namespace AwsEx.Creds
{
    /// <summary>
    /// This work exactly like FallbackCredentialsFactory except it uses DefaultInstanceProfileAWSCredentialsEx instead of AWS SDKs implementation
    /// </summary>
    public static class FallbackCredentialsFactoryEx
    {
        public delegate AWSCredentials CredentialsGenerator();

        private const string AWS_PROFILE_ENVIRONMENT_VARIABLE = "AWS_PROFILE";
        private const string DefaultProfileName = "default";

        private static readonly CredentialProfileStoreChain credentialProfileChain = new CredentialProfileStoreChain();

        private static AWSCredentials cachedCredentials;

        static FallbackCredentialsFactoryEx()
        {
            Reset();
        }

        public static List<CredentialsGenerator> CredentialsGenerators { get; set; }

        public static void Reset(IWebProxy proxy = null)
        {
            cachedCredentials = null;
            CredentialsGenerators = new List<CredentialsGenerator>
            {
#if BCL
                () => new AppConfigAWSCredentials(),            // Test explicit keys/profile name first.
#endif
                AssumeRoleWithWebIdentityCredentials.FromEnvironmentVariables,
                // Attempt to load the default profile.  It could be Basic, Session, AssumeRole, or SAML.
                () => GetAWSCredentials(credentialProfileChain),
                () => new EnvironmentVariablesAWSCredentials(), // Look for credentials set in environment vars.
                () => ECSEC2CredentialsWrapper(proxy) // either get ECS credentials or instance profile credentials
            };
        }

        private static AWSCredentials GetAWSCredentials(ICredentialProfileSource source)
        {
            var profileName = Environment.GetEnvironmentVariable(AWS_PROFILE_ENVIRONMENT_VARIABLE) ?? DefaultProfileName;

            if (source.TryGetProfile(profileName, out var profile))
                return AWSCredentialsFactory.GetAWSCredentials(profile, source, true);
            throw new AmazonClientException("Unable to find the '" + profileName + "' profile in CredentialProfileStoreChain.");
        }

        /// If either AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI environment variables are set, we want to attempt to retrieve credentials
        /// using ECS endpoint instead of referring to instance profile credentials.
        private static AWSCredentials ECSEC2CredentialsWrapper(IWebProxy proxy = null)
        {
            try
            {
                var relativeUri = Environment.GetEnvironmentVariable(ECSTaskCredentials.ContainerCredentialsURIEnvVariable);
                if (!string.IsNullOrEmpty(relativeUri)) return new ECSTaskCredentials(proxy);

                var fullUri = Environment.GetEnvironmentVariable(ECSTaskCredentials.ContainerCredentialsFullURIEnvVariable);
                if (!string.IsNullOrEmpty(fullUri)) return new ECSTaskCredentials(proxy);
            }
            catch (SecurityException e)
            {
                Logger.GetLogger(typeof(ECSTaskCredentials)).Error(e, $"Failed to access environment variables {ECSTaskCredentials.ContainerCredentialsURIEnvVariable} and {ECSTaskCredentials.ContainerCredentialsFullURIEnvVariable}." +
                                                                      $" Either {ECSTaskCredentials.ContainerCredentialsURIEnvVariable} or {ECSTaskCredentials.ContainerCredentialsFullURIEnvVariable} environment variables must be set.");
            }

            return DefaultInstanceProfileAWSCredentialsEx.Instance;
        }

        public static AWSCredentials GetCredentials(bool fallbackToAnonymous = false)
        {
            if (cachedCredentials != null)
                return cachedCredentials;

            var errors = new List<Exception>();

            foreach (var generator in CredentialsGenerators)
            {
                try
                {
                    cachedCredentials = generator();
                }
                // Breaking the FallbackCredentialFactory chain in case a ProcessAWSCredentialException exception 
                // is encountered. ProcessAWSCredentialException is thrown by the ProcessAWSCredential provider
                // when an exception is encountered when running a user provided process to obtain Basic/Session 
                // credentials. The motivation behind this is that, if the user has provided a process to be run
                // he expects to use the credentials obtained by running the process. Therefore the exception is
                // surfaced to the user.
                catch (ProcessAWSCredentialException)
                {
                    throw;
                }
                catch (Exception e)
                {
                    cachedCredentials = null;
                    errors.Add(e);
                }

                if (cachedCredentials != null)
                    break;
            }

            if (cachedCredentials == null)
            {
                if (fallbackToAnonymous) return new AnonymousAWSCredentials();

                using (var writer = new StringWriter(CultureInfo.InvariantCulture))
                {
                    writer.WriteLine("Unable to find credentials");
                    writer.WriteLine();
                    for (var i = 0; i < errors.Count; i++)
                    {
                        var e = errors[i];
                        writer.WriteLine("Exception {0} of {1}:", i + 1, errors.Count);
                        writer.WriteLine(e.ToString());
                        writer.WriteLine();
                    }

                    throw new AmazonServiceException(writer.ToString());
                }
            }

            return cachedCredentials;
        }
    }
}