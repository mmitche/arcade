// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.DotNet.RecursiveSigning.Abstractions;
using Microsoft.DotNet.RecursiveSigning.Implementation;
using Microsoft.DotNet.RecursiveSigning.Models;

namespace Microsoft.DotNet.RecursiveSigning.Configuration
{
    /// <summary>
    /// Extension methods for configuring RecursiveSigning services.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add all default RecursiveSigning services including core orchestration,
        /// file analyzers, and container handlers.
        /// Consumers must still register:
        /// - ICertificateCalculator (or call <see cref="AddDefaultCertificateCalculator"/>)
        /// - ISigningProvider (or call <see cref="AddDryRunSigningProvider"/>)
        /// </summary>
        public static IServiceCollection AddDefaultRecursiveSigning(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddRecursiveSigning();
            services.AddDefaultFileAnalyzers();
            services.AddDefaultContainerHandlers();

            return services;
        }

        /// <summary>
        /// Add RecursiveSigning core orchestration services only.
        /// Use <see cref="AddDefaultRecursiveSigning"/> for a batteries-included setup,
        /// or call this with <see cref="AddDefaultFileAnalyzers"/> and
        /// <see cref="AddDefaultContainerHandlers"/> individually for more control.
        /// </summary>
        public static IServiceCollection AddRecursiveSigning(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddSingleton<IFileSystem, FileSystem>();
            services.AddSingleton<IProcessRunner, DefaultProcessRunner>();
            services.AddTransient<IFileDeduplicator, DefaultFileDeduplicator>();
            services.AddTransient<IRecursiveSigning, Implementation.RecursiveSigning>();

            return services;
        }

        /// <summary>
        /// Register the default file analyzers (e.g. <see cref="PEFileAnalyzer"/>).
        /// Analyzers are registered as <c>IEnumerable&lt;IFileAnalyzer&gt;</c> and
        /// dispatched by the orchestrator, matching the container handler pattern.
        /// </summary>
        public static IServiceCollection AddDefaultFileAnalyzers(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddSingleton<IFileAnalyzer, PEFileAnalyzer>();

            return services;
        }

        /// <summary>
        /// Register the default container handlers (e.g. <see cref="ZipContainerHandler"/>
        /// for .nupkg, .zip, .vsix).
        /// </summary>
        public static IServiceCollection AddDefaultContainerHandlers(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddContainerHandler<ZipContainerHandler>();

            return services;
        }

        /// <summary>
        /// Register a container handler. The orchestrator receives all registered
        /// <see cref="IContainerHandler"/> instances via <c>IEnumerable&lt;IContainerHandler&gt;</c>.
        /// </summary>
        public static IServiceCollection AddContainerHandler<THandler>(this IServiceCollection services)
            where THandler : class, IContainerHandler
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddSingleton<IContainerHandler, THandler>();

            return services;
        }

        /// <summary>
        /// Register <see cref="DefaultCertificateCalculator"/> with the supplied certificate rules.
        /// </summary>
        public static IServiceCollection AddDefaultCertificateCalculator(
            this IServiceCollection services,
            DefaultCertificateRules rules)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (rules == null)
            {
                throw new ArgumentNullException(nameof(rules));
            }

            services.AddSingleton<ICertificateCalculator>(_ => new DefaultCertificateCalculator(rules));

            return services;
        }

        /// <summary>
        /// Register <see cref="DryRunSigningProvider"/> as the signing provider.
        /// Files are not actually signed; the provider logs what would have been signed.
        /// </summary>
        public static IServiceCollection AddDryRunSigningProvider(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddSingleton<ISigningProvider, DryRunSigningProvider>();

            return services;
        }
    }
}
