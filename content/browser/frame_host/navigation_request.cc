// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/frame_host/navigation_request.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/debug/alias.h"
#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/optional.h"
#include "base/rand_util.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/system/sys_info.h"
#include "base/task/post_task.h"
#include "build/build_config.h"
#include "content/browser/appcache/appcache_navigation_handle.h"
#include "content/browser/appcache/chrome_appcache_service.h"
#include "content/browser/blob_storage/chrome_blob_storage_context.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/client_hints/client_hints.h"
#include "content/browser/devtools/devtools_instrumentation.h"
#include "content/browser/download/download_manager_impl.h"
#include "content/browser/frame_host/debug_urls.h"
#include "content/browser/frame_host/frame_tree.h"
#include "content/browser/frame_host/frame_tree_node.h"
#include "content/browser/frame_host/navigation_controller_impl.h"
#include "content/browser/frame_host/navigation_request.h"
#include "content/browser/frame_host/navigation_request_info.h"
#include "content/browser/frame_host/navigator.h"
#include "content/browser/frame_host/navigator_impl.h"
#include "content/browser/frame_host/origin_policy_throttle.h"
#include "content/browser/frame_host/render_frame_host_impl.h"
#include "content/browser/loader/browser_initiated_resource_request.h"
#include "content/browser/loader/cached_navigation_url_loader.h"
#include "content/browser/loader/navigation_url_loader.h"
#include "content/browser/net/cross_origin_embedder_policy_reporter.h"
#include "content/browser/network_service_instance_impl.h"
#include "content/browser/renderer_host/render_process_host_impl.h"
#include "content/browser/renderer_host/render_view_host_delegate.h"
#include "content/browser/renderer_host/render_view_host_impl.h"
#include "content/browser/service_worker/service_worker_context_wrapper.h"
#include "content/browser/service_worker/service_worker_main_resource_handle.h"
#include "content/browser/site_instance_impl.h"
#include "content/browser/web_package/prefetched_signed_exchange_cache.h"
#include "content/browser/web_package/web_bundle_handle_tracker.h"
#include "content/browser/web_package/web_bundle_navigation_info.h"
#include "content/browser/web_package/web_bundle_source.h"
#include "content/browser/web_package/web_bundle_utils.h"
#include "content/common/appcache_interfaces.h"
#include "content/common/content_constants_internal.h"
#include "content/common/frame_messages.h"
#include "content/common/navigation_params.h"
#include "content/common/navigation_params_mojom_traits.h"
#include "content/common/navigation_params_utils.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/client_hints_controller_delegate.h"
#include "content/public/browser/content_browser_client.h"
#include "content/public/browser/global_request_id.h"
#include "content/public/browser/navigation_controller.h"
#include "content/public/browser/navigation_ui_data.h"
#include "content/public/browser/network_service_instance.h"
#include "content/public/browser/render_view_host.h"
#include "content/public/browser/site_isolation_policy.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/common/child_process_host.h"
#include "content/public/common/content_client.h"
#include "content/public/common/content_features.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/navigation_policy.h"
#include "content/public/common/network_service_util.h"
#include "content/public/common/origin_util.h"
#include "content/public/common/url_constants.h"
#include "content/public/common/url_utils.h"
#include "content/public/common/web_preferences.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "net/base/filename_util.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/url_util.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_status_code.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/content_security_policy/content_security_policy.h"
#include "services/network/public/cpp/cross_origin_resource_policy.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/fetch_api.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/blob/blob_utils.h"
#include "third_party/blink/public/common/frame/sandbox_flags.h"
#include "third_party/blink/public/mojom/appcache/appcache.mojom.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom.h"
#include "third_party/blink/public/mojom/renderer_preferences.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_provider.mojom.h"
#include "third_party/blink/public/mojom/web_feature/web_feature.mojom.h"
#include "third_party/blink/public/platform/resource_request_blocked_reason.h"
#include "third_party/blink/public/platform/web_mixed_content_context_type.h"
#include "url/url_constants.h"

#include "uos/database/database_thread_manager.h"
#include "uos/database/risky_urls_database.h"
#include "ui/base/l10n/l10n_util.h"
#include "chrome/grit/generated_resources.h"

namespace content {

namespace {

// Default timeout for the READY_TO_COMMIT -> COMMIT transition. Chosen
// initially based on the Navigation.ReadyToCommitUntilCommit UMA, and then
// refined based on feedback based on CrashExitCodes.Renderer/RESULT_CODE_HUNG.
constexpr base::TimeDelta kDefaultCommitTimeout =
    base::TimeDelta::FromSeconds(30);

// Timeout for the READY_TO_COMMIT -> COMMIT transition.
// Overrideable via SetCommitTimeoutForTesting.
base::TimeDelta g_commit_timeout = kDefaultCommitTimeout;

// crbug.com/954271: This feature is a part of an ablation study which makes
// history navigations slower.
// TODO(altimin): Clean this up after the study finishes.
constexpr base::Feature kHistoryNavigationDoNotUseCacheAblationStudy{
    "HistoryNavigationDoNotUseCacheAblationStudy",
    base::FEATURE_DISABLED_BY_DEFAULT};
constexpr base::FeatureParam<double> kDoNotUseCacheProbability{
    &kHistoryNavigationDoNotUseCacheAblationStudy, "probability", 0.0};

// Corresponds to the "NavigationURLScheme" histogram enumeration type in
// src/tools/metrics/histograms/enums.xml.
//
// DO NOT REORDER OR CHANGE THE MEANING OF THESE VALUES.
enum class NavigationURLScheme {
  UNKNOWN = 0,
  ABOUT = 1,
  BLOB = 2,
  CONTENT = 3,
  CONTENT_ID = 4,
  DATA = 5,
  FILE = 6,
  FILE_SYSTEM = 7,
  FTP = 8,
  HTTP = 9,
  HTTPS = 10,
  kMaxValue = HTTPS
};

NavigationURLScheme GetScheme(const GURL& url) {
  static const base::NoDestructor<std::map<std::string, NavigationURLScheme>>
      kSchemeMap({
          {url::kAboutScheme, NavigationURLScheme::ABOUT},
          {url::kBlobScheme, NavigationURLScheme::BLOB},
          {url::kContentScheme, NavigationURLScheme::CONTENT},
          {url::kContentIDScheme, NavigationURLScheme::CONTENT_ID},
          {url::kDataScheme, NavigationURLScheme::DATA},
          {url::kFileScheme, NavigationURLScheme::FILE},
          {url::kFileSystemScheme, NavigationURLScheme::FILE_SYSTEM},
          {url::kFtpScheme, NavigationURLScheme::FTP},
          {url::kHttpScheme, NavigationURLScheme::HTTP},
          {url::kHttpsScheme, NavigationURLScheme::HTTPS},
      });
  auto it = kSchemeMap->find(url.scheme());
  if (it != kSchemeMap->end())
    return it->second;
  return NavigationURLScheme::UNKNOWN;
}

// Returns the net load flags to use based on the navigation type.
// TODO(clamy): Remove the blink code that sets the caching flags.
void UpdateLoadFlagsWithCacheFlags(int* load_flags,
                                   mojom::NavigationType navigation_type,
                                   bool is_post) {
  switch (navigation_type) {
    case mojom::NavigationType::RELOAD:
    case mojom::NavigationType::RELOAD_ORIGINAL_REQUEST_URL:
      *load_flags |= net::LOAD_VALIDATE_CACHE;
      break;
    case mojom::NavigationType::RELOAD_BYPASSING_CACHE:
      *load_flags |= net::LOAD_BYPASS_CACHE;
      break;
    case mojom::NavigationType::RESTORE:
      *load_flags |= net::LOAD_SKIP_CACHE_VALIDATION;
      break;
    case mojom::NavigationType::RESTORE_WITH_POST:
      *load_flags |=
          net::LOAD_ONLY_FROM_CACHE | net::LOAD_SKIP_CACHE_VALIDATION;
      break;
    case mojom::NavigationType::SAME_DOCUMENT:
    case mojom::NavigationType::DIFFERENT_DOCUMENT:
      if (is_post)
        *load_flags |= net::LOAD_VALIDATE_CACHE;
      break;
    case mojom::NavigationType::HISTORY_SAME_DOCUMENT:
    case mojom::NavigationType::HISTORY_DIFFERENT_DOCUMENT:
      if (is_post) {
        *load_flags |=
            net::LOAD_ONLY_FROM_CACHE | net::LOAD_SKIP_CACHE_VALIDATION;
      } else if (base::FeatureList::IsEnabled(
                     kHistoryNavigationDoNotUseCacheAblationStudy) &&
                 base::RandDouble() < kDoNotUseCacheProbability.Get()) {
        *load_flags |= net::LOAD_BYPASS_CACHE;
      } else {
        *load_flags |= net::LOAD_SKIP_CACHE_VALIDATION;
      }
      break;
  }
}

// TODO(clamy): This should be function in FrameTreeNode.
bool IsSecureFrame(FrameTreeNode* frame) {
  while (frame) {
    if (!IsPotentiallyTrustworthyOrigin(frame->current_origin()))
      return false;
    frame = frame->parent();
  }
  return true;
}

// This should match blink::ResourceRequest::needsHTTPOrigin.
bool NeedsHTTPOrigin(net::HttpRequestHeaders* headers,
                     const std::string& method) {
  // Blink version of this function checks if the Origin header might have
  // already been added to |headers|.  This check is not replicated below
  // because:
  // 1. We want to overwrite the old (renderer-provided) header value
  //    with a new, trustworthy (browser-provided) value.
  // 2. The rest of the function matches the Blink version, so there should
  //    be no discrepancies in the Origin value used.

  // Don't send an Origin header for GET or HEAD to avoid privacy issues.
  // For example, if an intranet page has a hyperlink to an external web
  // site, we don't want to include the Origin of the request because it
  // will leak the internal host name. Similar privacy concerns have lead
  // to the widespread suppression of the Referer header at the network
  // layer.
  if (method == "GET" || method == "HEAD")
    return false;

  // For non-GET and non-HEAD methods, always send an Origin header so the
  // server knows we support this feature.
  return true;
}

// TODO(clamy): This should match what's happening in
// blink::FrameFetchContext::addAdditionalRequestHeaders.
void AddAdditionalRequestHeaders(net::HttpRequestHeaders* headers,
                                 const GURL& url,
                                 mojom::NavigationType navigation_type,
                                 ui::PageTransition transition,
                                 BrowserContext* browser_context,
                                 const std::string& method,
                                 const std::string user_agent_override,
                                 bool has_user_gesture,
                                 base::Optional<url::Origin> initiator_origin,
                                 blink::mojom::Referrer* referrer,
                                 FrameTreeNode* frame_tree_node) {
  if (!url.SchemeIsHTTPOrHTTPS())
    return;

  bool is_reload =
      navigation_type == mojom::NavigationType::RELOAD ||
      navigation_type == mojom::NavigationType::RELOAD_BYPASSING_CACHE ||
      navigation_type == mojom::NavigationType::RELOAD_ORIGINAL_REQUEST_URL;
  blink::mojom::RendererPreferences render_prefs =
      frame_tree_node->render_manager()
          ->current_host()
          ->GetDelegate()
          ->GetRendererPrefs(browser_context);
  UpdateAdditionalHeadersForBrowserInitiatedRequest(headers, browser_context,
                                                    is_reload, render_prefs);

  // Tack an 'Upgrade-Insecure-Requests' header to outgoing navigational
  // requests, as described in
  // https://w3c.github.io/webappsec/specs/upgrade/#feature-detect
  headers->SetHeaderIfMissing("Upgrade-Insecure-Requests", "1");

  headers->SetHeaderIfMissing(
      net::HttpRequestHeaders::kUserAgent,
      user_agent_override.empty()
          ? GetContentClient()->browser()->GetUserAgent()
          : user_agent_override);

  if (!render_prefs.enable_referrers) {
    *referrer =
        blink::mojom::Referrer(GURL(), network::mojom::ReferrerPolicy::kNever);
  }

  // Next, set the HTTP Origin if needed.
  if (NeedsHTTPOrigin(headers, method)) {
    url::Origin origin_header_value = initiator_origin.value_or(url::Origin());
    origin_header_value = Referrer::SanitizeOriginForRequest(
        url, origin_header_value, referrer->policy);
    headers->SetHeader(net::HttpRequestHeaders::kOrigin,
                       origin_header_value.Serialize());
  }

  if (base::FeatureList::IsEnabled(features::kDocumentPolicy)) {
    const blink::DocumentPolicy::FeatureState& required_policy =
        frame_tree_node->effective_frame_policy().required_document_policy;
    if (!required_policy.empty()) {
      base::Optional<std::string> policy_header =
          blink::DocumentPolicy::Serialize(required_policy);
      DCHECK(policy_header);
      headers->SetHeader("Sec-Required-Document-Policy", policy_header.value());
    }
  }
}

// Should match the definition of
// blink::SchemeRegistry::ShouldTreatURLSchemeAsLegacy.
bool ShouldTreatURLSchemeAsLegacy(const GURL& url) {
  return url.SchemeIs(url::kFtpScheme);
}

bool ShouldPropagateUserActivation(const url::Origin& previous_origin,
                                   const url::Origin& new_origin) {
  if ((previous_origin.scheme() != "http" &&
       previous_origin.scheme() != "https") ||
      (new_origin.scheme() != "http" && new_origin.scheme() != "https")) {
    return false;
  }

  if (previous_origin.host() == new_origin.host())
    return true;

  std::string previous_domain =
      net::registry_controlled_domains::GetDomainAndRegistry(
          previous_origin.host(),
          net::registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES);
  std::string new_domain =
      net::registry_controlled_domains::GetDomainAndRegistry(
          new_origin.host(),
          net::registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES);
  return !previous_domain.empty() && previous_domain == new_domain;
}

// LOG_NAVIGATION_TIMING_HISTOGRAM logs |value| for "Navigation.<histogram>" UMA
// as well as supplementary UMAs (depending on |transition| and |is_background|)
// for BackForward/Reload/NewNavigation variants.
//
// kMaxTime and kBuckets constants are consistent with
// UMA_HISTOGRAM_MEDIUM_TIMES, but a custom kMinTime is used for high fidelity
// near the low end of measured values.
//
// TODO(csharrison,nasko): This macro is incorrect for subframe navigations,
// which will only have subframe-specific transition types. This means that all
// subframes currently are tagged as NewNavigations.
#define LOG_NAVIGATION_TIMING_HISTOGRAM(histogram, transition, is_background, \
                                        duration)                             \
  do {                                                                        \
    const base::TimeDelta kMinTime = base::TimeDelta::FromMilliseconds(1);    \
    const base::TimeDelta kMaxTime = base::TimeDelta::FromMinutes(3);         \
    const int kBuckets = 50;                                                  \
    UMA_HISTOGRAM_CUSTOM_TIMES("Navigation." histogram, duration, kMinTime,   \
                               kMaxTime, kBuckets);                           \
    if (transition & ui::PAGE_TRANSITION_FORWARD_BACK) {                      \
      UMA_HISTOGRAM_CUSTOM_TIMES("Navigation." histogram ".BackForward",      \
                                 duration, kMinTime, kMaxTime, kBuckets);     \
    } else if (ui::PageTransitionCoreTypeIs(transition,                       \
                                            ui::PAGE_TRANSITION_RELOAD)) {    \
      UMA_HISTOGRAM_CUSTOM_TIMES("Navigation." histogram ".Reload", duration, \
                                 kMinTime, kMaxTime, kBuckets);               \
    } else if (ui::PageTransitionIsNewNavigation(transition)) {               \
      UMA_HISTOGRAM_CUSTOM_TIMES("Navigation." histogram ".NewNavigation",    \
                                 duration, kMinTime, kMaxTime, kBuckets);     \
    } else {                                                                  \
      NOTREACHED() << "Invalid page transition: " << transition;              \
    }                                                                         \
    if (is_background.has_value()) {                                          \
      if (is_background.value()) {                                            \
        UMA_HISTOGRAM_CUSTOM_TIMES("Navigation." histogram                    \
                                   ".BackgroundProcessPriority",              \
                                   duration, kMinTime, kMaxTime, kBuckets);   \
      } else {                                                                \
        UMA_HISTOGRAM_CUSTOM_TIMES("Navigation." histogram                    \
                                   ".ForegroundProcessPriority",              \
                                   duration, kMinTime, kMaxTime, kBuckets);   \
      }                                                                       \
    }                                                                         \
  } while (0)

void RecordStartToCommitMetrics(base::TimeTicks navigation_start_time,
                                ui::PageTransition transition,
                                const base::TimeTicks& ready_to_commit_time,
                                base::Optional<bool> is_background,
                                bool is_same_process,
                                bool is_main_frame) {
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeDelta delta = now - navigation_start_time;
  LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit", transition, is_background,
                                  delta);
  if (is_main_frame) {
    LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.MainFrame", transition,
                                    is_background, delta);
  } else {
    LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.Subframe", transition,
                                    is_background, delta);
  }
  if (is_same_process) {
    LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.SameProcess", transition,
                                    is_background, delta);
    if (is_main_frame) {
      LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.SameProcess.MainFrame",
                                      transition, is_background, delta);
    } else {
      LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.SameProcess.Subframe",
                                      transition, is_background, delta);
    }
  } else {
    LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.CrossProcess", transition,
                                    is_background, delta);
    if (is_main_frame) {
      LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.CrossProcess.MainFrame",
                                      transition, is_background, delta);
    } else {
      LOG_NAVIGATION_TIMING_HISTOGRAM("StartToCommit.CrossProcess.Subframe",
                                      transition, is_background, delta);
    }
  }
  if (!ready_to_commit_time.is_null()) {
    LOG_NAVIGATION_TIMING_HISTOGRAM("ReadyToCommitUntilCommit2", transition,
                                    is_background, now - ready_to_commit_time);
  }
}

void RecordReadyToCommitMetrics(
    RenderFrameHostImpl* old_rfh,
    RenderFrameHostImpl* new_rfh,
    const mojom::CommonNavigationParams& common_params,
    base::TimeTicks ready_to_commit_time) {
  bool is_main_frame = !new_rfh->GetParent();
  bool is_same_process =
      old_rfh->GetProcess()->GetID() == new_rfh->GetProcess()->GetID();

  // Navigation.IsSameBrowsingInstance
  if (is_main_frame) {
    bool is_same_browsing_instance =
        old_rfh->GetSiteInstance()->IsRelatedSiteInstance(
            new_rfh->GetSiteInstance());

    UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameBrowsingInstance",
                          is_same_browsing_instance);
  }

  // Navigation.IsSameSiteInstance
  {
    bool is_same_site_instance =
        old_rfh->GetSiteInstance() == new_rfh->GetSiteInstance();
    UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameSiteInstance",
                          is_same_site_instance);
    if (is_main_frame) {
      UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameSiteInstance.MainFrame",
                            is_same_site_instance);
    } else {
      UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameSiteInstance.Subframe",
                            is_same_site_instance);
    }
  }

  // Navigation.IsLockedProcess
  {
    ChildProcessSecurityPolicyImpl* policy =
        ChildProcessSecurityPolicyImpl::GetInstance();
    GURL process_lock = policy->GetOriginLock(new_rfh->GetProcess()->GetID());
    UMA_HISTOGRAM_BOOLEAN("Navigation.IsLockedProcess",
                          !process_lock.is_empty());
    if (common_params.url.SchemeIsHTTPOrHTTPS()) {
      UMA_HISTOGRAM_BOOLEAN("Navigation.IsLockedProcess.HTTPOrHTTPS",
                            !process_lock.is_empty());
    }
  }

  // Navigation.RequiresDedicatedProcess
  {
    UMA_HISTOGRAM_BOOLEAN(
        "Navigation.RequiresDedicatedProcess",
        new_rfh->GetSiteInstance()->RequiresDedicatedProcess());
    if (common_params.url.SchemeIsHTTPOrHTTPS()) {
      UMA_HISTOGRAM_BOOLEAN(
          "Navigation.RequiresDedicatedProcess.HTTPOrHTTPS",
          new_rfh->GetSiteInstance()->RequiresDedicatedProcess());
    }
  }

  // Navigation.IsSameProcess
  {
    UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameProcess", is_same_process);
    if (common_params.transition & ui::PAGE_TRANSITION_FORWARD_BACK) {
      UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameProcess.BackForward",
                            is_same_process);
    } else if (ui::PageTransitionCoreTypeIs(common_params.transition,
                                            ui::PAGE_TRANSITION_RELOAD)) {
      UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameProcess.Reload", is_same_process);
    } else if (ui::PageTransitionIsNewNavigation(common_params.transition)) {
      UMA_HISTOGRAM_BOOLEAN("Navigation.IsSameProcess.NewNavigation",
                            is_same_process);
    } else {
      NOTREACHED() << "Invalid page transition: " << common_params.transition;
    }
  }

  // TimeToReadyToCommit2
  {
    constexpr base::Optional<bool> kIsBackground = base::nullopt;
    base::TimeDelta delta =
        ready_to_commit_time - common_params.navigation_start;

    LOG_NAVIGATION_TIMING_HISTOGRAM(
        "TimeToReadyToCommit2", common_params.transition, kIsBackground, delta);
    if (is_main_frame) {
      LOG_NAVIGATION_TIMING_HISTOGRAM("TimeToReadyToCommit2.MainFrame",
                                      common_params.transition, kIsBackground,
                                      delta);
    } else {
      LOG_NAVIGATION_TIMING_HISTOGRAM("TimeToReadyToCommit2.Subframe",
                                      common_params.transition, kIsBackground,
                                      delta);
    }
    if (is_same_process) {
      LOG_NAVIGATION_TIMING_HISTOGRAM("TimeToReadyToCommit2.SameProcess",
                                      common_params.transition, kIsBackground,
                                      delta);
    } else {
      LOG_NAVIGATION_TIMING_HISTOGRAM("TimeToReadyToCommit2.CrossProcess",
                                      common_params.transition, kIsBackground,
                                      delta);
    }
  }
}

// Use this to get a new unique ID for a NavigationHandle during construction.
// The returned ID is guaranteed to be nonzero (zero is the "no ID" indicator).
int64_t CreateUniqueHandleID() {
  static int64_t unique_id_counter = 0;
  return ++unique_id_counter;
}

// Given an net::IPAddress and a set of headers, this function calculates the
// IPAddressSpace which should be associated with the document this navigation
// eventually commits into.
//
// https://wicg.github.io/cors-rfc1918/#address-space
//
// TODO(mkwst): This implementation treats requests that don't use a URL loader
// (`about:blank`), as well as requests whose IP address is invalid
// (`about:srcdoc`, `blob:`, etc.) as `kUnknown`. This is incorrect (as we'll
// eventually want to make sure we inherit from the navigation's initiator in
// some cases), but safe, as `kUnknown` is treated the same as `kPublic`.
network::mojom::IPAddressSpace CalculateIPAddressSpace(
    const net::IPAddress& ip,
    net::HttpResponseHeaders* headers) {
  // First, check whether the response forces itself into a public address space
  // as per https://wicg.github.io/cors-rfc1918/#csp.
  bool must_treat_as_public_address = false;
  std::string csp_value;
  if (headers &&
      headers->GetNormalizedHeader("content-security-policy", &csp_value)) {
    // A content-security-policy is a semicolon-separated list of directives.
    for (const auto& directive :
         base::SplitStringPiece(csp_value, ";", base::TRIM_WHITESPACE,
                                base::SPLIT_WANT_NONEMPTY)) {
      if (base::EqualsCaseInsensitiveASCII("treat-as-public-address",
                                           directive)) {
        must_treat_as_public_address = true;
      }
    }
  }

  if (must_treat_as_public_address)
    return network::mojom::IPAddressSpace::kPublic;

  // Otherwise, calculate the address space via the provided IP address.
  if (!ip.IsValid()) {
    return network::mojom::IPAddressSpace::kUnknown;
  } else if (ip.IsLoopback()) {
    return network::mojom::IPAddressSpace::kLocal;
  } else if (!ip.IsPubliclyRoutable()) {
    return network::mojom::IPAddressSpace::kPrivate;
  }
  return network::mojom::IPAddressSpace::kPublic;
}

// Convert the navigation type to the appropriate cross-document one.
//
// This is currently used when:
// 1) Restarting a same-document navigation as cross-document.
// 2) Committing an error page after blocking a same-document navigations.
mojom::NavigationType ConvertToCrossDocumentType(mojom::NavigationType type) {
  switch (type) {
    case mojom::NavigationType::SAME_DOCUMENT:
      return mojom::NavigationType::DIFFERENT_DOCUMENT;
    case mojom::NavigationType::HISTORY_SAME_DOCUMENT:
      return mojom::NavigationType::HISTORY_DIFFERENT_DOCUMENT;
    case mojom::NavigationType::RELOAD:
    case mojom::NavigationType::RELOAD_BYPASSING_CACHE:
    case mojom::NavigationType::RELOAD_ORIGINAL_REQUEST_URL:
    case mojom::NavigationType::RESTORE:
    case mojom::NavigationType::RESTORE_WITH_POST:
    case mojom::NavigationType::HISTORY_DIFFERENT_DOCUMENT:
    case mojom::NavigationType::DIFFERENT_DOCUMENT:
      return type;
  }
}

base::debug::CrashKeyString* GetNavigationRequestUrlCrashKey() {
  static auto* crash_key = base::debug::AllocateCrashKeyString(
      "navigation_request_url", base::debug::CrashKeySize::Size256);
  return crash_key;
}

base::debug::CrashKeyString* GetNavigationRequestInitiatorCrashKey() {
  static auto* crash_key = base::debug::AllocateCrashKeyString(
      "navigation_request_initiator", base::debug::CrashKeySize::Size64);
  return crash_key;
}

class ScopedNavigationRequestCrashKeys {
 public:
  explicit ScopedNavigationRequestCrashKeys(
      NavigationRequest* navigation_request)
      : initiator_origin_(
            GetNavigationRequestInitiatorCrashKey(),
            base::OptionalOrNullptr(navigation_request->GetInitiatorOrigin())),
        url_(GetNavigationRequestUrlCrashKey(),
             navigation_request->GetURL().possibly_invalid_spec()) {}
  ~ScopedNavigationRequestCrashKeys() = default;

  // No copy constructor and no copy assignment operator.
  ScopedNavigationRequestCrashKeys(const ScopedNavigationRequestCrashKeys&) =
      delete;
  ScopedNavigationRequestCrashKeys& operator=(
      const ScopedNavigationRequestCrashKeys&) = delete;

 private:
  url::debug::ScopedOriginCrashKey initiator_origin_;
  base::debug::ScopedCrashKeyString url_;
};

// Start a new nested async event with the given name.
void EnterChildTraceEvent(const char* name, NavigationRequest* request) {
  // Tracing no longer outputs the end event name, so we can simply pass an
  // empty string here.
  TRACE_EVENT_NESTABLE_ASYNC_END0("navigation", "", request);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("navigation", name, request);
}

// Start a new nested async event with the given name and args.
template <typename ArgType>
void EnterChildTraceEvent(const char* name,
                          NavigationRequest* request,
                          const char* arg_name,
                          ArgType arg_value) {
  // Tracing no longer outputs the end event name, so we can simply pass an
  // empty string here.
  TRACE_EVENT_NESTABLE_ASYNC_END0("navigation", "", request);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("navigation", name, request, arg_name,
                                    arg_value);
}

}  // namespace

// static
std::unique_ptr<NavigationRequest> NavigationRequest::CreateBrowserInitiated(
    FrameTreeNode* frame_tree_node,
    mojom::CommonNavigationParamsPtr common_params,
    mojom::CommitNavigationParamsPtr commit_params,
    bool browser_initiated,
    const std::string& extra_headers,
    FrameNavigationEntry* frame_entry,
    NavigationEntryImpl* entry,
    const scoped_refptr<network::ResourceRequestBody>& post_body,
    std::unique_ptr<NavigationUIData> navigation_ui_data) {
  // TODO(arthursonzogni): Form submission with the "GET" method is possible.
  // This is not currently handled here.
  bool is_form_submission = !!post_body;

  auto navigation_params = mojom::BeginNavigationParams::New(
      extra_headers, net::LOAD_NORMAL, false /* skip_service_worker */,
      blink::mojom::RequestContextType::LOCATION,
      network::mojom::RequestDestination::kDocument,
      blink::WebMixedContentContextType::kBlockable, is_form_submission,
      false /* was_initiated_by_link_click */, GURL() /* searchable_form_url */,
      std::string() /* searchable_form_encoding */,
      GURL() /* client_side_redirect_url */,
      base::nullopt /* devtools_initiator_info */,
      false /* attach_same_site_cookies */, nullptr /* trust_token_params */);

  // Shift-Reload forces bypassing caches and service workers.
  if (common_params->navigation_type ==
      mojom::NavigationType::RELOAD_BYPASSING_CACHE) {
    navigation_params->load_flags |= net::LOAD_BYPASS_CACHE;
    navigation_params->skip_service_worker = true;
  }

  RenderFrameHostImpl* rfh_restored_from_back_forward_cache = nullptr;
  if (entry) {
    NavigationControllerImpl* controller =
        static_cast<NavigationControllerImpl*>(
            frame_tree_node->navigator()->GetController());
    BackForwardCacheImpl::Entry* restored_entry =
        controller->GetBackForwardCache().GetEntry(entry->GetUniqueID());
    if (restored_entry) {
      rfh_restored_from_back_forward_cache =
          restored_entry->render_frame_host.get();
    }
  }

  std::unique_ptr<NavigationRequest> navigation_request(new NavigationRequest(
      frame_tree_node, std::move(common_params), std::move(navigation_params),
      std::move(commit_params), browser_initiated,
      false /* from_begin_navigation */, false /* is_for_commit */, frame_entry,
      entry, std::move(navigation_ui_data), mojo::NullAssociatedRemote(),
      mojo::NullRemote(), rfh_restored_from_back_forward_cache));

  if (frame_entry) {
    navigation_request->blob_url_loader_factory_ =
        frame_entry->blob_url_loader_factory();
  }

  if (navigation_request->common_params().url.SchemeIsBlob() &&
      !navigation_request->blob_url_loader_factory_) {
    // If this navigation entry came from session history then the blob factory
    // would have been cleared in NavigationEntryImpl::ResetForCommit(). This is
    // avoid keeping large blobs alive unnecessarily and the spec is unclear. So
    // create a new blob factory which will work if the blob happens to still be
    // alive.
    navigation_request->blob_url_loader_factory_ =
        ChromeBlobStorageContext::URLLoaderFactoryForUrl(
            frame_tree_node->navigator()->GetController()->GetBrowserContext(),
            navigation_request->common_params().url);
  }

  return navigation_request;
}

// static
std::unique_ptr<NavigationRequest> NavigationRequest::CreateRendererInitiated(
    FrameTreeNode* frame_tree_node,
    NavigationEntryImpl* entry,
    mojom::CommonNavigationParamsPtr common_params,
    mojom::BeginNavigationParamsPtr begin_params,
    int current_history_list_offset,
    int current_history_list_length,
    bool override_user_agent,
    scoped_refptr<network::SharedURLLoaderFactory> blob_url_loader_factory,
    mojo::PendingAssociatedRemote<mojom::NavigationClient> navigation_client,
    mojo::PendingRemote<blink::mojom::NavigationInitiator> navigation_initiator,
    scoped_refptr<PrefetchedSignedExchangeCache>
        prefetched_signed_exchange_cache,
    std::unique_ptr<WebBundleHandleTracker> web_bundle_handle_tracker) {
  // Only normal navigations to a different document or reloads are expected.
  // - Renderer-initiated same document navigations never start in the browser.
  // - Restore-navigations are always browser-initiated.
  // - History-navigations use the browser-initiated path, even the ones that
  //   are initiated by a javascript script.
  DCHECK(NavigationTypeUtils::IsReload(common_params->navigation_type) ||
         common_params->navigation_type ==
             mojom::NavigationType::DIFFERENT_DOCUMENT);

  // TODO(clamy): See if the navigation start time should be measured in the
  // renderer and sent to the browser instead of being measured here.
  mojom::CommitNavigationParamsPtr commit_params =
      mojom::CommitNavigationParams::New(
          base::nullopt, override_user_agent,
          std::vector<GURL>(),  // redirects
          std::vector<
              network::mojom::URLResponseHeadPtr>(),  // redirect_response
          std::vector<net::RedirectInfo>(),           // redirect_infos
          std::string(),                              // post_content_type
          common_params->url, common_params->method,
          false,                                // can_load_local_resources
          PageState(),                          // page_state
          0,                                    // nav_entry_id
          base::flat_map<std::string, bool>(),  // subframe_unique_names
          false,                                // intended_as_new_entry
          -1,  // |pending_history_list_offset| is set to -1 because
               // history-navigations do not use this path. See comments above.
          current_history_list_offset, current_history_list_length,
          false,  // was_discarded
          false,  // is_view_source
          false /*should_clear_history_list*/,
          mojom::NavigationTiming::New(),  // navigation_timing
          base::nullopt,                   // appcache_host_id
          mojom::WasActivatedOption::kUnknown,
          base::UnguessableToken::Create(),  // navigation_token
          std::vector<
              mojom::
                  PrefetchedSignedExchangeInfoPtr>(),  // prefetched_signed_exchanges
#if defined(OS_ANDROID)
          std::string(),  // data_url_as_string
#endif
          false,  // is_browser_initiated
          network::mojom::IPAddressSpace::kUnknown,
          GURL() /* web_bundle_physical_url */,
          GURL() /* base_url_override_for_web_bundle */,
          frame_tree_node->pending_frame_policy(),
          std::vector<std::string>() /* force_enabled_origin_trials */);
  std::unique_ptr<NavigationRequest> navigation_request(new NavigationRequest(
      frame_tree_node, std::move(common_params), std::move(begin_params),
      std::move(commit_params),
      false,  // browser_initiated
      true,   // from_begin_navigation
      false,  // is_for_commit
      nullptr, entry,
      nullptr,  // navigation_ui_data
      std::move(navigation_client), std::move(navigation_initiator),
      nullptr  // rfh_restored_from_back_forward_cache
      ));
  navigation_request->blob_url_loader_factory_ =
      std::move(blob_url_loader_factory);
  navigation_request->prefetched_signed_exchange_cache_ =
      std::move(prefetched_signed_exchange_cache);
  navigation_request->web_bundle_handle_tracker_ =
      std::move(web_bundle_handle_tracker);
  return navigation_request;
}

// static
std::unique_ptr<NavigationRequest> NavigationRequest::CreateForCommit(
    FrameTreeNode* frame_tree_node,
    RenderFrameHostImpl* render_frame_host,
    NavigationEntryImpl* entry,
    const FrameHostMsg_DidCommitProvisionalLoad_Params& params,
    bool is_renderer_initiated,
    bool is_same_document) {
  // TODO(clamy): Improve the *NavigationParams and *CommitParams to avoid
  // copying so many parameters here.
  mojom::CommonNavigationParamsPtr common_params =
      mojom::CommonNavigationParams::New(
          params.url,
          // TODO(nasko): Investigate better value to pass for
          // |initiator_origin|.
          params.origin,
          blink::mojom::Referrer::New(params.referrer.url,
                                      params.referrer.policy),
          params.transition,
          is_same_document ? mojom::NavigationType::SAME_DOCUMENT
                           : mojom::NavigationType::DIFFERENT_DOCUMENT,
          NavigationDownloadPolicy(), params.should_replace_current_entry,
          params.base_url, params.base_url, PREVIEWS_UNSPECIFIED,
          base::TimeTicks::Now(), params.method, nullptr,
          network::mojom::SourceLocation::New(),
          false /* started_from_context_menu */,
          params.gesture == NavigationGestureUser, CreateInitiatorCSPInfo(),
          std::vector<int>() /* initiator_origin_trial_features */,
          std::string() /* href_translate */,
          false /* is_history_navigation_in_new_child_frame */,
          base::TimeTicks::Now());
  mojom::CommitNavigationParamsPtr commit_params =
      mojom::CommitNavigationParams::New(
          params.origin, params.is_overriding_user_agent, params.redirects,
          std::vector<network::mojom::URLResponseHeadPtr>(),
          std::vector<net::RedirectInfo>(), std::string(),
          params.original_request_url, params.method,
          false /* can_load_local_resources */, params.page_state,
          params.nav_entry_id,
          base::flat_map<std::string, bool>() /* subframe_unique_names */,
          params.intended_as_new_entry, -1 /* pending_history_list_offset */,
          -1 /* current_history_list_offset */,
          -1 /* current_history_list_length */, false /* was_discard */,
          false /* is_view_source */, params.history_list_was_cleared,
          mojom::NavigationTiming::New(), base::nullopt /* appcache_host_id; */,
          mojom::WasActivatedOption::kUnknown,
          base::UnguessableToken::Create() /* navigation_token */,
          std::vector<mojom::PrefetchedSignedExchangeInfoPtr>(),
#if defined(OS_ANDROID)
          std::string(), /* data_url_as_string */
#endif
          false,  // is_browser_initiated
          network::mojom::IPAddressSpace::kUnknown,
          GURL() /* web_bundle_physical_url */,
          GURL() /* base_url_override_for_web_bundle */,
          base::nullopt /* frame policy */,
          std::vector<std::string>() /* force_enabled_origin_trials */
      );
  mojom::BeginNavigationParamsPtr begin_params =
      mojom::BeginNavigationParams::New();
  std::unique_ptr<NavigationRequest> navigation_request(new NavigationRequest(
      frame_tree_node, std::move(common_params), std::move(begin_params),
      std::move(commit_params), !is_renderer_initiated,
      false /* from_begin_navigation */, true /* is_for_commit */,
      entry ? entry->GetFrameEntry(frame_tree_node) : nullptr, entry,
      nullptr /* navigation_ui_data */, mojo::NullAssociatedRemote(),
      mojo::NullRemote(), nullptr /* rfh_restored_from_back_forward_cache */));

  navigation_request->render_frame_host_ = render_frame_host;
  navigation_request->StartNavigation(true);
  DCHECK(navigation_request->IsNavigationStarted());

  return navigation_request;
}

NavigationRequest::NavigationRequest(
    FrameTreeNode* frame_tree_node,
    mojom::CommonNavigationParamsPtr common_params,
    mojom::BeginNavigationParamsPtr begin_params,
    mojom::CommitNavigationParamsPtr commit_params,
    bool browser_initiated,
    bool from_begin_navigation,
    bool is_for_commit,
    const FrameNavigationEntry* frame_entry,
    NavigationEntryImpl* entry,
    std::unique_ptr<NavigationUIData> navigation_ui_data,
    mojo::PendingAssociatedRemote<mojom::NavigationClient> navigation_client,
    mojo::PendingRemote<blink::mojom::NavigationInitiator> navigation_initiator,
    RenderFrameHostImpl* rfh_restored_from_back_forward_cache)
    : frame_tree_node_(frame_tree_node),
      common_params_(std::move(common_params)),
      begin_params_(std::move(begin_params)),
      commit_params_(std::move(commit_params)),
      browser_initiated_(browser_initiated),
      navigation_ui_data_(std::move(navigation_ui_data)),
      state_(NOT_STARTED),
      restore_type_(RestoreType::NONE),
      is_view_source_(false),
      bindings_(FrameNavigationEntry::kInvalidBindings),
      response_should_be_rendered_(true),
      associated_site_instance_type_(AssociatedSiteInstanceType::NONE),
      from_begin_navigation_(from_begin_navigation),
      has_stale_copy_in_cache_(false),
      net_error_(net::OK),
      expected_render_process_host_id_(ChildProcessHost::kInvalidUniqueID),
      devtools_navigation_token_(base::UnguessableToken::Create()),
      request_navigation_client_(mojo::NullAssociatedRemote()),
      commit_navigation_client_(mojo::NullAssociatedRemote()),
      rfh_restored_from_back_forward_cache_(
          rfh_restored_from_back_forward_cache),
      client_security_state_(network::mojom::ClientSecurityState::New()) {
  DCHECK(browser_initiated_ || common_params_->initiator_origin.has_value());
  DCHECK(!IsRendererDebugURL(common_params_->url));
  DCHECK(common_params_->method == "POST" || !common_params_->post_data);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN2(
      "navigation", "NavigationRequest", this, "frame_tree_node",
      frame_tree_node_->frame_tree_node_id(), "url",
      common_params_->url.possibly_invalid_spec());
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("navigation", "Initializing", this);
  NavigationControllerImpl* controller = static_cast<NavigationControllerImpl*>(
      frame_tree_node_->navigator()->GetController());

  if (frame_entry) {
    frame_entry_item_sequence_number_ = frame_entry->item_sequence_number();
    frame_entry_document_sequence_number_ =
        frame_entry->document_sequence_number();
    if (frame_entry->web_bundle_navigation_info()) {
      web_bundle_navigation_info_ =
          frame_entry->web_bundle_navigation_info()->Clone();
    }
  }

  // Sanitize the referrer.
  common_params_->referrer = Referrer::SanitizeForRequest(
      common_params_->url, *common_params_->referrer);

  if (frame_tree_node_->IsMainFrame()) {
    loading_mem_tracker_ =
        PeakGpuMemoryTracker::Create(PeakGpuMemoryTracker::Usage::PAGE_LOAD);
  }

  if (from_begin_navigation_) {
    // This is needed to have data URLs commit in the same SiteInstance as the
    // initiating renderer.
    source_site_instance_ =
        frame_tree_node->current_frame_host()->GetSiteInstance();

    DCHECK(navigation_client.is_valid());
    SetNavigationClient(std::move(navigation_client));
  } else if (entry) {
    DCHECK(!navigation_client.is_valid());
    if (frame_entry) {
      source_site_instance_ = frame_entry->source_site_instance();
      dest_site_instance_ = frame_entry->site_instance();
      bindings_ = frame_entry->bindings();

      // Handle history subframe navigations that require a source_site_instance
      // but do not have one set yet. This can happen when navigation entries
      // are restored from PageState objects. The serialized state does not
      // contain a SiteInstance so we need to use the initiator_origin to
      // get an appropriate source SiteInstance.
      if (common_params_->is_history_navigation_in_new_child_frame)
        SetSourceSiteInstanceToInitiatorIfNeeded();
    }
    network_isolation_key_ = entry->network_isolation_key();
    is_view_source_ = entry->IsViewSourceMode();

    // Ensure that we always have a |source_site_instance_| for navigations
    // that require it at this point. This is needed to ensure that data: URLs
    // commit in the SiteInstance that initiated them.
    //
    // TODO(acolwell): Move this below so it can be enforced on all paths.
    // This requires auditing same-document and other navigations that don't
    // have |from_begin_navigation_| or |entry| set.
    DCHECK(!RequiresSourceSiteInstance() || source_site_instance_);
  }

  // Let the NTP override the navigation params and pretend that this is a
  // browser-initiated, bookmark-like navigation.
  if (!browser_initiated_ && source_site_instance_) {
    bool is_renderer_initiated = !browser_initiated_;
    Referrer referrer(*common_params_->referrer);
    GetContentClient()->browser()->OverrideNavigationParams(
        source_site_instance_.get(), &common_params_->transition,
        &is_renderer_initiated, &referrer, &common_params_->initiator_origin);
    common_params_->referrer =
        blink::mojom::Referrer::New(referrer.url, referrer.policy);
    browser_initiated_ = !is_renderer_initiated;
    commit_params_->is_browser_initiated = browser_initiated_;
  }

  // Store the old RenderFrameHost id at request creation to be used later.
  previous_render_frame_host_id_ = GlobalFrameRoutingId(
      frame_tree_node->current_frame_host()->GetProcess()->GetID(),
      frame_tree_node->current_frame_host()->GetRoutingID());

  // Update the load flags with cache information.
  UpdateLoadFlagsWithCacheFlags(&begin_params_->load_flags,
                                common_params_->navigation_type,
                                common_params_->method == "POST");

  // Add necessary headers that may not be present in the
  // mojom::BeginNavigationParams.
  if (entry) {
    nav_entry_id_ = entry->GetUniqueID();
    restore_type_ = entry->restore_type();
    reload_type_ = entry->reload_type();
    // TODO(altimin, crbug.com/933147): Remove this logic after we are done
    // with implementing back-forward cache.
    if (frame_tree_node->IsMainFrame() && entry->back_forward_cache_metrics()) {
      entry->back_forward_cache_metrics()
          ->MainFrameDidStartNavigationToDocument();
    }

    // If this NavigationRequest is for the current pending entry, make sure
    // that we will discard the pending entry if all of associated its requests
    // go away, by creating a ref to it.
    if (entry == controller->GetPendingEntry())
      pending_entry_ref_ = controller->ReferencePendingEntry();
  }

  entry_overrides_ua_ = (entry && entry->GetIsOverridingUserAgent());
  bool is_overriding_ua =
      commit_params_->is_overriding_user_agent || entry_overrides_ua_;
  std::string user_agent_override;
  if (is_overriding_ua) {
    user_agent_override = frame_tree_node_->navigator()
                              ->GetDelegate()
                              ->GetUserAgentOverride()
                              .ua_string_override;
  }

  net::HttpRequestHeaders headers;
  // Only add specific headers when creating a NavigationRequest before the
  // network request is made, not at commit time.
  if (!is_for_commit) {
    BrowserContext* browser_context = controller->GetBrowserContext();
    ClientHintsControllerDelegate* client_hints_delegate =
        browser_context->GetClientHintsControllerDelegate();
    if (client_hints_delegate) {
      net::HttpRequestHeaders client_hints_headers;
      RenderViewHost* render_view_host =
          frame_tree_node->current_frame_host()->GetRenderViewHost();
      const bool javascript_enabled =
          render_view_host->GetWebkitPreferences().javascript_enabled;
      AddNavigationRequestClientHintsHeaders(
          common_params_->url, &client_hints_headers, browser_context,
          javascript_enabled, client_hints_delegate, is_overriding_ua,
          frame_tree_node_);
      headers.MergeFrom(client_hints_headers);
    }

    headers.AddHeadersFromString(begin_params_->headers);
    AddAdditionalRequestHeaders(
        &headers, common_params_->url, common_params_->navigation_type,
        common_params_->transition, controller->GetBrowserContext(),
        common_params_->method, user_agent_override,
        common_params_->has_user_gesture, common_params_->initiator_origin,
        common_params_->referrer.get(), frame_tree_node);

    if (begin_params_->is_form_submission) {
      if (browser_initiated_ && !commit_params_->post_content_type.empty()) {
        // This is a form resubmit, so make sure to set the Content-Type header.
        headers.SetHeaderIfMissing(net::HttpRequestHeaders::kContentType,
                                   commit_params_->post_content_type);
      } else if (!browser_initiated_) {
        // Save the Content-Type in case the form is resubmitted. This will get
        // sent back to the renderer in the CommitNavigation IPC. The renderer
        // will then send it back with the post body so that we can access it
        // along with the body in FrameNavigationEntry::page_state_.
        headers.GetHeader(net::HttpRequestHeaders::kContentType,
                          &commit_params_->post_content_type);
      }
    }
  }

  begin_params_->headers = headers.ToString();

  initiator_csp_context_.reset(new InitiatorCSPContext(
      std::move(common_params_->initiator_csp_info->initiator_csp),
      std::move(common_params_->initiator_csp_info->initiator_self_source),
      std::move(navigation_initiator)));

  navigation_entry_offset_ = EstimateHistoryOffset();

  commit_params_->is_browser_initiated = browser_initiated_;
}

NavigationRequest::~NavigationRequest() {
  // Close the last child event. Tracing no longer outputs the end event name,
  // so we can simply pass an empty string here.
  TRACE_EVENT_NESTABLE_ASYNC_END0("navigation", "", this);
  TRACE_EVENT_NESTABLE_ASYNC_END0("navigation", "NavigationRequest", this);
  if (loading_mem_tracker_)
    loading_mem_tracker_->Cancel();
  ResetExpectedProcess();
  if (state_ >= WILL_START_NAVIGATION && state_ < READY_TO_COMMIT) {
    devtools_instrumentation::OnNavigationRequestFailed(
        *this, network::URLLoaderCompletionStatus(net::ERR_ABORTED));
  }

  // If this NavigationRequest is the last one referencing the pending
  // NavigationEntry, the entry is discarded.
  //
  // Leaving a stale pending NavigationEntry with no matching navigation can
  // potentially lead to URL-spoof issues.
  //
  // Note: Discarding the pending NavigationEntry is done before notifying the
  // navigation finished to the observers. One class is relying on this:
  // org.chromium.chrome.browser.toolbar.ToolbarManager
  pending_entry_ref_.reset();

#if defined(OS_ANDROID)
  if (navigation_handle_proxy_)
    navigation_handle_proxy_->DidFinish();
#endif

  if (IsNavigationStarted()) {
    GetDelegate()->DidFinishNavigation(this);
    if (IsInMainFrame()) {
      TRACE_EVENT_NESTABLE_ASYNC_END2(
          "navigation", "Navigation StartToCommit",
          TRACE_ID_WITH_SCOPE("StartToCommit", TRACE_ID_LOCAL(this)), "URL",
          common_params_->url.spec(), "Net Error Code", net_error_);
    }
  }
}

void NavigationRequest::BeginNavigation() {
  DCHECK(state_ == NOT_STARTED || state_ == WAITING_FOR_RENDERER_RESPONSE);
  EnterChildTraceEvent("BeginNavigation", this);
  DCHECK(!loader_);
  DCHECK(!render_frame_host_);
  // modify by xiaohuyang, 2021/3/2  --start
  // If the current access URL is risky, stop accessing and jump to the risk error page.
#if 1 
  std::string url_host = GetURL().host();
  std::string risky_text = 
      uos::database::DatabaseThreadManager::Get()->GetRiskyUrlsDatabase()->CheckUrlAndReturnType(url_host);
  if (!risky_text.empty()) {
    std::string details = l10n_util::GetStringFUTF8(IDS_NOT_VISIT, base::UTF8ToUTF16(GetURL().host()));

    std::string html = "<div style='position:absolute;left: 50%;top: 50%;transform: translate(-50%,-50%);text-align: center;color: #414D68;font-size: 14px;font-family:SourceHanSansSC-Medium,SourceHanSansSC;font-weight:500;'>"
                       "<img src='data:image/png;base64,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' style='width: 173px;height: 149px;'>"
                       "<h1 style='margin-top: 39px;font-weight:400;line-height:58px;margin-top: 31px;font-size:40px;'>"+risky_text+"</h1>"
                       "<p style='margin-top: 20px;line-height:20px;'>"+details+"</p>"
                       "</div>";
    // "<p style='margin-top: 10px;font-weight:400;line-height: 17px;font-size: 12px;color: #526A7F;'>"+risky_text+"</p>"

    StartNavigation(false);
    OnRequestFailedInternal(network::URLLoaderCompletionStatus(net::ERR_ACCESS_DENIED),
                            true /* skip_throttles */,
                            html /* error_page_content */,
                            false /* collapse_frame */);
    return ;
  }
#endif
  // modify by xiaohuyang, 2021/3/2  --end

  ScopedNavigationRequestCrashKeys crash_keys(this);

  state_ = WILL_START_NAVIGATION;

#if defined(OS_ANDROID)
  base::WeakPtr<NavigationRequest> this_ptr(weak_factory_.GetWeakPtr());
  bool should_override_url_loading = false;

  if (!GetContentClient()->browser()->ShouldOverrideUrlLoading(
          frame_tree_node_->frame_tree_node_id(), browser_initiated_,
          commit_params_->original_url, commit_params_->original_method,
          common_params_->has_user_gesture, false,
          frame_tree_node_->IsMainFrame(), common_params_->transition,
          &should_override_url_loading)) {
    // A Java exception was thrown by the embedding application; we
    // need to return from this task. Specifically, it's not safe from
    // this point on to make any JNI calls.
    return;
  }

  // The content/ embedder might cause |this| to be deleted while
  // |ShouldOverrideUrlLoading| is called.
  // See https://crbug.com/770157.
  if (!this_ptr)
    return;

  if (should_override_url_loading) {
    // Don't create a NavigationHandle here to simulate what happened with the
    // old navigation code path (i.e. doesn't fire onPageFinished notification
    // for aborted loads).
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net::ERR_ABORTED),
        false /*skip_throttles*/, base::nullopt /*error_page_content*/,
        false /*collapse_frame*/);
    return;
  }
#endif

  // Check Content Security Policy before the NavigationThrottles run. This
  // gives CSP a chance to modify requests that NavigationThrottles would
  // otherwise block. Similarly, the NavigationHandle is created afterwards, so
  // that it gets the request URL after potentially being modified by CSP.
  net::Error net_error = CheckContentSecurityPolicy(
      false /* has_followed redirect */,
      false /* url_upgraded_after_redirect */, false /* is_response_check */);
  if (net_error != net::OK) {
    // Create a navigation handle so that the correct error code can be set on
    // it by OnRequestFailedInternal().
    StartNavigation(false);
    OnRequestFailedInternal(network::URLLoaderCompletionStatus(net_error),
                            false /* skip_throttles */,
                            base::nullopt /* error_page_content */,
                            false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  if (CheckCredentialedSubresource() ==
          CredentialedSubresourceCheckResult::BLOCK_REQUEST ||
      CheckLegacyProtocolInSubresource() ==
          LegacyProtocolInSubresourceCheckResult::BLOCK_REQUEST) {
    // Create a navigation handle so that the correct error code can be set on
    // it by OnRequestFailedInternal().
    StartNavigation(false);
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net::ERR_ABORTED),
        false /* skip_throttles  */, base::nullopt /* error_page_content */,
        false /* collapse_frame */);

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  StartNavigation(false);

  if (CheckAboutSrcDoc() == AboutSrcDocCheckResult::BLOCK_REQUEST) {
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net::ERR_INVALID_URL),
        true /* skip_throttles */, base::nullopt /* error_page_content*/,
        false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  if (!post_commit_error_page_html_.empty()) {
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net_error_),
        true /* skip_throttles  */,
        post_commit_error_page_html_ /* error_page_content */,
        false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  if (!NeedsUrlLoader()) {
    // The types of pages that don't need a URL Loader should never get served
    // from the BackForwardCache.
    DCHECK(!IsServedFromBackForwardCache());

    // There is no need to make a network request for this navigation, so commit
    // it immediately.
    EnterChildTraceEvent("ResponseStarted", this);

    // Select an appropriate RenderFrameHost.
    render_frame_host_ =
        frame_tree_node_->render_manager()->GetFrameHostForNavigation(this);
    NavigatorImpl::CheckWebUIRendererDoesNotDisplayNormalURL(
        render_frame_host_, common_params_->url);

    ReadyToCommitNavigation(false /* is_error */);
    CommitNavigation();
    return;
  }

  common_params_->previews_state =
      GetContentClient()->browser()->DetermineAllowedPreviews(
          common_params_->previews_state, this, common_params_->url);

  WillStartRequest();
}

void NavigationRequest::SetWaitingForRendererResponse() {
  EnterChildTraceEvent("WaitingForRendererResponse", this);
  DCHECK(state_ == NOT_STARTED);
  state_ = WAITING_FOR_RENDERER_RESPONSE;
}

void NavigationRequest::StartNavigation(bool is_for_commit) {
  DCHECK(frame_tree_node_->navigation_request() == this || is_for_commit);
  FrameTreeNode* frame_tree_node = frame_tree_node_;

  // This is needed to get site URLs and assign the expected RenderProcessHost.
  // This is not always the same as |source_site_instance_|, as it only depends
  // on the current frame host, and does not depend on |entry|.
  // The |starting_site_instance_| needs to be set here instead of the
  // constructor since a navigation can be started after the constructor and
  // before here, which can set a different RenderFrameHost and a different
  // starting SiteInstance.
  starting_site_instance_ =
      frame_tree_node->current_frame_host()->GetSiteInstance();
  site_url_ = GetSiteForCommonParamsURL();

  // Compute the redirect chain.
  // TODO(clamy): Try to simplify this and have the redirects be part of
  // CommonNavigationParams.
  redirect_chain_.clear();
  if (!begin_params_->client_side_redirect_url.is_empty()) {
    // |begin_params_->client_side_redirect_url| will be set when the navigation
    // was triggered by a client-side redirect.
    redirect_chain_.push_back(begin_params_->client_side_redirect_url);
  } else if (!commit_params_->redirects.empty()) {
    // Redirects that were specified at NavigationRequest creation time should
    // be added to the list of redirects. In particular, if the
    // NavigationRequest was created at commit time, redirects that happened
    // during the navigation have been added to |commit_params_->redirects| and
    // should be passed to the NavigationHandle.
    for (const auto& url : commit_params_->redirects)
      redirect_chain_.push_back(url);
  }

  // Finally, add the current URL to the vector of redirects.
  // Note: for NavigationRequests created at commit time, the current URL has
  // been added to |commit_params_->redirects|, so don't add it a second time.
  if (!is_for_commit)
    redirect_chain_.push_back(common_params_->url);

  net::HttpRequestHeaders headers;
  headers.AddHeadersFromString(begin_params_->headers);

  // Mirrors the logic in RenderFrameImpl::SendDidCommitProvisionalLoad.
  if (common_params_->transition & ui::PAGE_TRANSITION_CLIENT_REDIRECT) {
    // If the page contained a client redirect (meta refresh,
    // document.location), set the referrer appropriately.
    sanitized_referrer_ = blink::mojom::Referrer::New(
        redirect_chain_[0], Referrer::SanitizeForRequest(
                                common_params_->url, *common_params_->referrer)
                                ->policy);
  } else {
    sanitized_referrer_ = Referrer::SanitizeForRequest(
        common_params_->url, *common_params_->referrer);
  }

  DCHECK(!IsNavigationStarted());
  state_ = WILL_START_REQUEST;
  navigation_handle_id_ = CreateUniqueHandleID();

  request_headers_ = std::move(headers);
  modified_request_headers_.Clear();
  removed_request_headers_.clear();

  throttle_runner_ = base::WrapUnique(new NavigationThrottleRunner(this));

#if defined(OS_ANDROID)
  navigation_handle_proxy_ = std::make_unique<NavigationHandleProxy>(this);
#endif

  if (IsInMainFrame()) {
    DCHECK(!common_params_->navigation_start.is_null());
    DCHECK(!IsRendererDebugURL(common_params_->url));
    TRACE_EVENT_NESTABLE_ASYNC_BEGIN_WITH_TIMESTAMP1(
        "navigation", "Navigation StartToCommit",
        TRACE_ID_WITH_SCOPE("StartToCommit", TRACE_ID_LOCAL(this)),
        common_params_->navigation_start, "Initial URL",
        common_params_->url.spec());
  }

  if (IsSameDocument()) {
    EnterChildTraceEvent("Same document", this);
  }

  GetDelegate()->DidStartNavigation(this);

  // The previous call to DidStartNavigation could have cancelled this request
  // synchronously.
}

void NavigationRequest::ResetForCrossDocumentRestart() {
  DCHECK(IsSameDocument());

  // Reset the NavigationHandle, which is now incorrectly marked as
  // same-document. Ensure |loader_| does not exist as it can hold raw pointers
  // to objects owned by the handle (see the comment in the header).
  DCHECK(!loader_);

#if defined(OS_ANDROID)
  if (navigation_handle_proxy_)
    navigation_handle_proxy_->DidFinish();
#endif

  // It is necessary to call DidFinishNavigation before resetting
  // |navigation_handle_proxy_|. See https://crbug.com/958396.
  if (IsNavigationStarted()) {
    GetDelegate()->DidFinishNavigation(this);
    if (IsInMainFrame()) {
      TRACE_EVENT_NESTABLE_ASYNC_END2(
          "navigation", "Navigation StartToCommit",
          TRACE_ID_WITH_SCOPE("StartToCommit", TRACE_ID_LOCAL(this)), "URL",
          common_params_->url.spec(), "Net Error Code", net_error_);
    }
  }

  // Reset the state of the NavigationRequest, and the navigation_handle_id.
  StopCommitTimeout();
  state_ = NOT_STARTED;
  processing_navigation_throttle_ = false;
  navigation_handle_id_ = 0;

#if defined(OS_ANDROID)
  if (navigation_handle_proxy_)
    navigation_handle_proxy_.reset();
#endif

  // Reset the previously selected RenderFrameHost. This is expected to be null
  // at the beginning of a new navigation. See https://crbug.com/936962.
  DCHECK(render_frame_host_);
  render_frame_host_ = nullptr;

  // Convert the navigation type to the appropriate cross-document one.
  common_params_->navigation_type =
      ConvertToCrossDocumentType(common_params_->navigation_type);
}

void NavigationRequest::ResetStateForSiteInstanceChange() {
  // This method should only be called when there is a dest_site_instance.
  DCHECK(dest_site_instance_);

  // When a request has a destination SiteInstance (e.g., reload or session
  // history navigation) but it changes during the navigation (e.g., due to
  // redirect or error page), it's important not to remember privileges or
  // attacker-controlled state from the original entry.

  // Reset bindings (e.g., since error pages for WebUI URLs don't get them).
  bindings_ = FrameNavigationEntry::kInvalidBindings;

  // Reset any existing PageState with a non-empty, clean PageState, so that old
  // attacker-controlled state is not pulled into the new process.
  if (commit_params_->page_state.IsValid())
    commit_params_->page_state = PageState::CreateFromURL(GetURL());

  // Any previously computed origin to commit is no longer valid (e.g., an
  // opaque origin for an error page).
  if (commit_params_->origin_to_commit)
    commit_params_->origin_to_commit.reset();

  // ISNs and DSNs are process-specific.
  frame_entry_item_sequence_number_ = -1;
  frame_entry_document_sequence_number_ = -1;
}

void NavigationRequest::RegisterSubresourceOverride(
    mojom::TransferrableURLLoaderPtr transferrable_loader) {
  if (!transferrable_loader)
    return;
  if (!subresource_overrides_)
    subresource_overrides_.emplace();

  subresource_overrides_->push_back(std::move(transferrable_loader));
}

mojom::NavigationClient* NavigationRequest::GetCommitNavigationClient() {
  if (commit_navigation_client_ && commit_navigation_client_.is_bound())
    return commit_navigation_client_.get();

  // Instantiate a new NavigationClient interface.
  commit_navigation_client_ =
      render_frame_host_->GetNavigationClientFromInterfaceProvider();
  HandleInterfaceDisconnection(
      &commit_navigation_client_,
      base::BindOnce(&NavigationRequest::OnRendererAbortedNavigation,
                     base::Unretained(this)));
  return commit_navigation_client_.get();
}

network::mojom::ClientSecurityStatePtr
NavigationRequest::TakeClientSecurityState() {
  return std::move(client_security_state_);
}

void NavigationRequest::CreateCoepReporter(
    StoragePartition* storage_partition) {
  const auto& coep = client_security_state_->cross_origin_embedder_policy;
  coep_reporter_ = std::make_unique<CrossOriginEmbedderPolicyReporter>(
      storage_partition, common_params_->url, coep.reporting_endpoint,
      coep.report_only_reporting_endpoint);
}

std::unique_ptr<CrossOriginEmbedderPolicyReporter>
NavigationRequest::TakeCoepReporter() {
  return std::move(coep_reporter_);
}

void NavigationRequest::OnRequestRedirected(
    const net::RedirectInfo& redirect_info,
    network::mojom::URLResponseHeadPtr response_head) {
  ScopedNavigationRequestCrashKeys crash_keys(this);

  // Sanity check - this can only be set at commit time.
  DCHECK(!auth_challenge_info_);

  response_head_ = std::move(response_head);
  ssl_info_ = response_head_->ssl_info;

  // Reset the page state as it can no longer be used at commit time since the
  // navigation was redirected.
  commit_params_->page_state = PageState();

#if defined(OS_ANDROID)
  base::WeakPtr<NavigationRequest> this_ptr(weak_factory_.GetWeakPtr());

  bool should_override_url_loading = false;
  if (!GetContentClient()->browser()->ShouldOverrideUrlLoading(
          frame_tree_node_->frame_tree_node_id(), browser_initiated_,
          redirect_info.new_url, redirect_info.new_method,
          // Redirects are always not counted as from user gesture.
          false, true, frame_tree_node_->IsMainFrame(),
          common_params_->transition, &should_override_url_loading)) {
    // A Java exception was thrown by the embedding application; we
    // need to return from this task. Specifically, it's not safe from
    // this point on to make any JNI calls.
    return;
  }

  // The content/ embedder might cause |this| to be deleted while
  // |ShouldOverrideUrlLoading| is called.
  // See https://crbug.com/770157.
  if (!this_ptr)
    return;

  if (should_override_url_loading) {
    net_error_ = net::ERR_ABORTED;
    common_params_->url = redirect_info.new_url;
    common_params_->method = redirect_info.new_method;
    // Update the navigation handle to point to the new url to ensure
    // AwWebContents sees the new URL and thus passes that URL to onPageFinished
    // (rather than passing the old URL).
    UpdateStateFollowingRedirect(GURL(redirect_info.new_referrer));
    frame_tree_node_->ResetNavigationRequest(false);
    return;
  }
#endif
  if (!ChildProcessSecurityPolicyImpl::GetInstance()->CanRedirectToURL(
          redirect_info.new_url)) {
    DVLOG(1) << "Denied redirect for "
             << redirect_info.new_url.possibly_invalid_spec();
    // TODO(arthursonzogni): Redirect to a javascript URL should display an
    // error page with the net::ERR_UNSAFE_REDIRECT error code. Instead, the
    // browser simply ignores the navigation, because some extensions use this
    // edge case to silently cancel navigations. See https://crbug.com/941653.
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net::ERR_ABORTED),
        false /* skip_throttles */, base::nullopt /* error_page_content */,
        false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  // For renderer-initiated navigations we need to check if the source has
  // access to the URL. Browser-initiated navigations only rely on the
  // |CanRedirectToURL| test above.
  if (!browser_initiated_ && GetSourceSiteInstance() &&
      !ChildProcessSecurityPolicyImpl::GetInstance()->CanRequestURL(
          GetSourceSiteInstance()->GetProcess()->GetID(),
          redirect_info.new_url)) {
    DVLOG(1) << "Denied unauthorized redirect for "
             << redirect_info.new_url.possibly_invalid_spec();
    // TODO(arthursonzogni): This case uses ERR_ABORTED to be consistent with
    // the javascript URL redirect case above, though ideally it would use
    // net::ERR_UNSAFE_REDIRECT and an error page. See https://crbug.com/941653.
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net::ERR_ABORTED),
        false /* skip_throttles */, base::nullopt /* error_page_content */,
        false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  if (const auto blocked_reason = IsBlockedByCorp()) {
    OnRequestFailedInternal(network::URLLoaderCompletionStatus(*blocked_reason),
                            false /* skip_throttles */,
                            base::nullopt /* error_page_content */,
                            false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to
    // OnRequestFailedInternal has destroyed the NavigationRequest.
    return;
  }

  // For now, DevTools needs the POST data sent to the renderer process even if
  // it is no longer a POST after the redirect.
  if (redirect_info.new_method != "POST")
    common_params_->post_data.reset();

  // Mark time for the Navigation Timing API.
  if (commit_params_->navigation_timing->redirect_start.is_null()) {
    commit_params_->navigation_timing->redirect_start =
        commit_params_->navigation_timing->fetch_start;
  }
  commit_params_->navigation_timing->redirect_end = base::TimeTicks::Now();
  commit_params_->navigation_timing->fetch_start = base::TimeTicks::Now();

  commit_params_->redirect_response.push_back(response_head_.Clone());
  commit_params_->redirect_infos.push_back(redirect_info);

  // On redirects, the initial origin_to_commit is no longer correct, so it
  // must be cleared to avoid sending incorrect value to the renderer process.
  if (commit_params_->origin_to_commit)
    commit_params_->origin_to_commit.reset();

  commit_params_->redirects.push_back(common_params_->url);
  common_params_->url = redirect_info.new_url;
  common_params_->method = redirect_info.new_method;
  common_params_->referrer->url = GURL(redirect_info.new_referrer);
  common_params_->referrer = Referrer::SanitizeForRequest(
      common_params_->url, *common_params_->referrer);

  // On redirects, the initial referrer is no longer correct, so it must
  // be updated.  (A parallel process updates the outgoing referrer in the
  // network stack.)
  commit_params_->redirect_infos.back().new_referrer =
      common_params_->referrer->url.spec();

  // Check Content Security Policy before the NavigationThrottles run. This
  // gives CSP a chance to modify requests that NavigationThrottles would
  // otherwise block.
  net::Error net_error =
      CheckContentSecurityPolicy(true /* has_followed_redirect */,
                                 redirect_info.insecure_scheme_was_upgraded,
                                 false /* is_response_check */);
  if (net_error != net::OK) {
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net_error), false /*skip_throttles*/,
        base::nullopt /*error_page_content*/, false /*collapse_frame*/);

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  if (CheckCredentialedSubresource() ==
          CredentialedSubresourceCheckResult::BLOCK_REQUEST ||
      CheckLegacyProtocolInSubresource() ==
          LegacyProtocolInSubresourceCheckResult::BLOCK_REQUEST) {
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net::ERR_ABORTED),
        false /*skip_throttles*/, base::nullopt /*error_page_content*/,
        false /*collapse_frame*/);

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  // Compute the SiteInstance to use for the redirect and pass its
  // RenderProcessHost if it has a process. Keep a reference if it has a
  // process, so that the SiteInstance and its associated process aren't deleted
  // before the navigation is ready to commit.
  scoped_refptr<SiteInstance> site_instance =
      frame_tree_node_->render_manager()->GetSiteInstanceForNavigationRequest(
          this);
  speculative_site_instance_ =
      site_instance->HasProcess() ? site_instance : nullptr;

  // If the new site instance doesn't yet have a process, then tell the
  // SpareRenderProcessHostManager so it can decide whether to start warming up
  // the spare at this time (note that the actual behavior depends on
  // RenderProcessHostImpl::IsSpareProcessKeptAtAllTimes).
  if (!site_instance->HasProcess()) {
    RenderProcessHostImpl::NotifySpareManagerAboutRecentlyUsedBrowserContext(
        site_instance->GetBrowserContext());
  }

  // Re-evaluate the PreviewsState, but do not update the URLLoader. The
  // URLLoader PreviewsState is considered immutable after the URLLoader is
  // created.
  common_params_->previews_state =
      GetContentClient()->browser()->DetermineAllowedPreviews(
          common_params_->previews_state, this, common_params_->url);

  // Check what the process of the SiteInstance is. It will be passed to the
  // NavigationHandle, and informed to expect a navigation to the redirected
  // URL.
  // Note: calling GetProcess on the SiteInstance can lead to the creation of a
  // new process if it doesn't have one. In this case, it should only be called
  // on a SiteInstance that already has a process.
  RenderProcessHost* expected_process =
      site_instance->HasProcess() ? site_instance->GetProcess() : nullptr;

  WillRedirectRequest(common_params_->referrer->url, expected_process);
}

void NavigationRequest::CheckForOriginPolicyIsolationOptIn(
    const GURL& url,
    const network::mojom::URLResponseHead* response) {
  // IsolationOptIn is only available when OriginPolicy is enabled.
  if (!base::FeatureList::IsEnabled(features::kOriginPolicy))
    return;

  bool requests_origin_isolation = false;
  if (response && response->origin_policy) {
    const network::OriginPolicy& origin_policy =
        response->origin_policy.value();
    // For now, we'll take the presence of any isolation_optin_hints value
    // as an indication to opt-in.
    requests_origin_isolation =
        origin_policy.state == network::OriginPolicyState::kLoaded &&
        origin_policy.contents->isolation_optin_hints.has_value();
  }
  auto* policy = ChildProcessSecurityPolicyImpl::GetInstance();
  url::Origin origin = url::Origin::Create(url);
  // We need to update the master list even if |requests_origin_isolation| is
  // false, since we need to maintain the master opt-in list according to the
  // most recently seen OriginPolicy.
  // TODO(wjmaclean): when we start to support versioning for OriginPolicies,
  // will we need to key the master list accordingly?
  policy->UpdateOriginIsolationOptInListIfNecessary(origin,
                                                    requests_origin_isolation);
}

void NavigationRequest::OnResponseStarted(
    network::mojom::URLLoaderClientEndpointsPtr url_loader_client_endpoints,
    network::mojom::URLResponseHeadPtr response_head,
    mojo::ScopedDataPipeConsumerHandle response_body,
    const GlobalRequestID& request_id,
    bool is_download,
    NavigationDownloadPolicy download_policy,
    base::Optional<SubresourceLoaderParams> subresource_loader_params) {
  ScopedNavigationRequestCrashKeys crash_keys(this);

  // The |loader_|'s job is finished. It must not call the NavigationRequest
  // anymore from now.
  loader_.reset();
  if (is_download)
    RecordDownloadUseCountersPrePolicyCheck(download_policy);
  is_download_ = is_download && download_policy.IsDownloadAllowed();
  if (is_download_)
    RecordDownloadUseCountersPostPolicyCheck();
  request_id_ = request_id;

  DCHECK(IsNavigationStarted());
  DCHECK(response_head);
  EnterChildTraceEvent("OnResponseStarted", this);
  state_ = WILL_PROCESS_RESPONSE;
  response_head_ = std::move(response_head);
  response_body_ = std::move(response_body);
  ssl_info_ = response_head_->ssl_info;
  auth_challenge_info_ = response_head_->auth_challenge_info;

  // Check if the response should be sent to a renderer.
  response_should_be_rendered_ =
      !is_download && (!response_head_->headers.get() ||
                       (response_head_->headers->response_code() != 204 &&
                        response_head_->headers->response_code() != 205));

  // Response that will not commit should be marked as aborted in the
  // NavigationHandle.
  if (!response_should_be_rendered_)
    net_error_ = net::ERR_ABORTED;

  // Update the AppCache params of the commit params.
  commit_params_->appcache_host_id =
      appcache_handle_
          ? base::make_optional(appcache_handle_->appcache_host_id())
          : base::nullopt;

  // Update fetch start timing. While NavigationRequest updates fetch start
  // timing for redirects, it's not aware of service worker interception so
  // fetch start timing could happen earlier than worker start timing. Use
  // worker ready time if it is greater than the current value to make sure
  // fetch start timing always comes after worker start timing (if a service
  // worker intercepted the navigation).
  commit_params_->navigation_timing->fetch_start =
      std::max(commit_params_->navigation_timing->fetch_start,
               response_head_->load_timing.service_worker_ready_time);

  // A navigation is user activated if it contains a user gesture or the frame
  // received a gesture and the navigation is renderer initiated. If the
  // navigation is browser initiated, it has to come from the context menu.
  // In all cases, the previous and new URLs have to match the
  // `ShouldPropagateUserActivation` requirements (same eTLD+1).
  // There are two different checks:
  // 1. if the `frame_tree_node_` has an origin and is following the rules above
  //    with the target URL, it is used and the bit is set if the navigation is
  //    renderer initiated and the `frame_tree_node_` had a gesture. This should
  //    apply to same page navigations and is preferred over using the referrer
  //    as it can be changed.
  // 2. if referrer and the target url are following the rules above, two
  //    conditions will set the bit: navigation comes from a gesture and is
  //    renderer initiated (middle click/ctrl+click) or it is coming from a
  //    context menu. This should apply to pages that open in a new tab and we
  //    have to follow the referrer. It means that the activation might not be
  //    transmitted if it should have.
  if (commit_params_->was_activated == mojom::WasActivatedOption::kUnknown) {
    commit_params_->was_activated = mojom::WasActivatedOption::kNo;

    if (!browser_initiated_ &&
        (frame_tree_node_->has_received_user_gesture() ||
         frame_tree_node_->has_received_user_gesture_before_nav()) &&
        ShouldPropagateUserActivation(
            frame_tree_node_->current_origin(),
            url::Origin::Create(common_params_->url))) {
      commit_params_->was_activated = mojom::WasActivatedOption::kYes;
      // TODO(805871): the next check is relying on sanitized_referrer_ but
      // should ideally use a more reliable source for the originating URL when
      // the navigation is renderer initiated.
    } else if (((common_params_->has_user_gesture && !browser_initiated_) ||
                common_params_->started_from_context_menu) &&
               ShouldPropagateUserActivation(
                   url::Origin::Create(sanitized_referrer_->url),
                   url::Origin::Create(common_params_->url))) {
      commit_params_->was_activated = mojom::WasActivatedOption::kYes;
    }
  }

  if (const auto blocked_reason = IsBlockedByCorp()) {
    OnRequestFailedInternal(network::URLLoaderCompletionStatus(*blocked_reason),
                            false /* skip_throttles */,
                            base::nullopt /* error_page_content */,
                            false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to
    // OnRequestFailedInternal has destroyed the NavigationRequest.
    return;
  }

  auto cross_origin_embedder_policy =
      response_head_->cross_origin_embedder_policy;
  if (base::FeatureList::IsEnabled(
          network::features::kCrossOriginEmbedderPolicy)) {
    // https://mikewest.github.io/corpp/#process-navigation-response
    if (auto* const parent_frame = GetParentFrame()) {
      const auto& parent_coep = parent_frame->cross_origin_embedder_policy();
      const auto& url = common_params_->url;
      constexpr auto kRequireCorp =
          network::mojom::CrossOriginEmbedderPolicyValue::kRequireCorp;
      constexpr auto kNone =
          network::mojom::CrossOriginEmbedderPolicyValue::kNone;

      // Some special URLs not loaded using the network are inheriting the
      // Cross-Origin-Embedder-Policy header from their parent.
      const bool has_allowed_scheme =
          url.SchemeIsBlob() || url.SchemeIs(url::kDataScheme);
      if (parent_coep.value == kRequireCorp && has_allowed_scheme) {
        cross_origin_embedder_policy.value = kRequireCorp;
      }

      auto* const coep_reporter = parent_frame->coep_reporter();
      if (parent_coep.report_only_value == kRequireCorp &&
          !has_allowed_scheme && cross_origin_embedder_policy.value == kNone &&
          coep_reporter) {
        coep_reporter->QueueNavigationReport(redirect_chain_[0],
                                             /*report_only=*/true);
      }
      if (parent_coep.value == kRequireCorp &&
          cross_origin_embedder_policy.value == kNone) {
        if (coep_reporter) {
          coep_reporter->QueueNavigationReport(redirect_chain_[0],
                                               /*report_only=*/false);
        }
        OnRequestFailedInternal(network::URLLoaderCompletionStatus(
                                    network::BlockedByResponseReason::
                                        kCoepFrameResourceNeedsCoepHeader),
                                false /* skip_throttles */,
                                base::nullopt /* error_page_content */,
                                false /* collapse_frame */);
        // DO NOT ADD CODE after this. The previous call to
        // OnRequestFailedInternal has destroyed the NavigationRequest.
        return;
      }
    }
  }

  if (base::FeatureList::IsEnabled(
          network::features::kCrossOriginOpenerPolicy)) {
    // The Cross-Origin-Opener-Policy header should be ignored if delivered in
    // insecure contexts.
    if (!IsOriginSecure(common_params_->url)) {
      response_head_->cross_origin_opener_policy =
          network::mojom::CrossOriginOpenerPolicy::kUnsafeNone;
    }

    // Popups with a sandboxing flag, inherited from their opener, are not
    // allowed to navigate to a document with a Cross-Origin-Opener-Policy that
    // is not "unsafe-none". This ensures a COOP document does not inherit any
    // property from an opener.
    // https://gist.github.com/annevk/6f2dd8c79c77123f39797f6bdac43f3e
    if (response_head_->cross_origin_opener_policy !=
            network::mojom::CrossOriginOpenerPolicy::kUnsafeNone &&
        (frame_tree_node_->pending_frame_policy().sandbox_flags !=
         blink::mojom::WebSandboxFlags::kNone)) {
      OnRequestFailedInternal(
          network::URLLoaderCompletionStatus(
              network::BlockedByResponseReason::
                  kCoopSandboxedIFrameCannotNavigateToCoopPage),
          false /* skip_throttles */, base::nullopt /* error_page_content */,
          false /* collapse_frame */);
      // DO NOT ADD CODE after this. The previous call to
      // OnRequestFailedInternal has destroyed the NavigationRequest.
      return;
    }
  }

  // The navigation may have encountered an OriginPolicy that requests isolation
  // for the url's origin. Before we pick the renderer, make sure we update the
  // master list for origin-isolation opt-ins.
  CheckForOriginPolicyIsolationOptIn(common_params().url, response());

  // Select an appropriate renderer to commit the navigation.
  if (IsServedFromBackForwardCache()) {
    NavigationControllerImpl* controller =
        static_cast<NavigationControllerImpl*>(
            frame_tree_node_->navigator()->GetController());
    render_frame_host_ = controller->GetBackForwardCache()
                             .GetEntry(nav_entry_id_)
                             ->render_frame_host.get();

    // The only time GetEntry can return nullptr here, is if the document was
    // evicted from the BackForwardCache since this navigation started.
    //
    // If the document was evicted, the navigation should have been re-issued
    // (deleting this NavigationRequest), so we should never reach this point
    // without the document still present in the BackForwardCache.
    CHECK(render_frame_host_);
  } else if (response_should_be_rendered_) {
    render_frame_host_ =
        frame_tree_node_->render_manager()->GetFrameHostForNavigation(this);
    NavigatorImpl::CheckWebUIRendererDoesNotDisplayNormalURL(
        render_frame_host_, common_params_->url);
  } else {
    render_frame_host_ = nullptr;
  }
  DCHECK(render_frame_host_ || !response_should_be_rendered_);

  // TODO(pmeuleman, ahemery): Only set COOP and COEP values on RenderFrameHost
  // when the navigation commits. In the meantime, keep them in
  // NavigationRequest.
  if (render_frame_host_) {
    render_frame_host_->set_cross_origin_embedder_policy(
        cross_origin_embedder_policy);
    render_frame_host_->set_cross_origin_opener_policy(
        response_head_->cross_origin_opener_policy);
  }
  client_security_state_->cross_origin_embedder_policy =
      cross_origin_embedder_policy;

  if (!browser_initiated_ && render_frame_host_ &&
      render_frame_host_ != frame_tree_node_->current_frame_host()) {
    // Reset the source location information if the navigation will not commit
    // in the current renderer process. This information originated in another
    // process (the current one), it should not be transferred to the new one.
    common_params_->source_location = network::mojom::SourceLocation::New();

    // Allow the embedder to cancel the cross-process commit if needed.
    // TODO(clamy): Rename ShouldTransferNavigation.
    if (!frame_tree_node_->navigator()->GetDelegate()->ShouldTransferNavigation(
            frame_tree_node_->IsMainFrame())) {
      net_error_ = net::ERR_ABORTED;
      frame_tree_node_->ResetNavigationRequest(false);
      return;
    }
  }

  // This must be set before DetermineCommittedPreviews is called.
  proxy_server_ = response_head_->proxy_server;

  // Update the previews state of the request.
  common_params_->previews_state =
      GetContentClient()->browser()->DetermineCommittedPreviews(
          common_params_->previews_state, this, response_head_->headers.get());

  // Store the URLLoaderClient endpoints until checks have been processed.
  url_loader_client_endpoints_ = std::move(url_loader_client_endpoints);

  subresource_loader_params_ = std::move(subresource_loader_params);

  // Since we've made the final pick for the RenderFrameHost above, the picked
  // RenderFrameHost's process should be considered "tainted" for future
  // process reuse decisions. That is, a site requiring a dedicated process
  // should not reuse this process, unless it's same-site with the URL we're
  // committing.  An exception is for URLs that do not "use up" the
  // SiteInstance, such as about:blank or chrome-native://.
  //
  // Note that although NavigationThrottles could still cancel the navigation
  // as part of WillProcessResponse below, we must update the process here,
  // since otherwise there could be a race if a NavigationThrottle defers the
  // navigation, and in the meantime another navigation reads the incorrect
  // IsUnused() value from the same process when making a process reuse
  // decision.
  if (render_frame_host_ &&
      SiteInstanceImpl::ShouldAssignSiteForURL(common_params_->url)) {
    render_frame_host_->GetProcess()->SetIsUsed();

    // For sites that require a dedicated process, set the site URL now if it
    // hasn't been set already. This will lock the process to that site, which
    // will prevent other sites from incorrectly reusing this process. See
    // https://crbug.com/738634.
    SiteInstanceImpl* instance = render_frame_host_->GetSiteInstance();
    if (!instance->HasSite() &&
        SiteInstanceImpl::DoesSiteRequireDedicatedProcess(
            instance->GetIsolationContext(), common_params_->url)) {
      instance->ConvertToDefaultOrSetSite(common_params_->url);
    }

    // Replace the SiteInstance of the previously committed entry if it's for a
    // url that doesn't require a site assignment, since this new commit is
    // assigning an incompatible site to the previous SiteInstance. This ensures
    // the new SiteInstance can be used with the old entry if we return to it.
    // See http://crbug.com/992198 for further context.
    NavigationController* controller =
        frame_tree_node_->navigator()->GetController();
    NavigationEntryImpl* nav_entry;
    if (controller &&
        (nav_entry = static_cast<NavigationEntryImpl*>(
             controller->GetLastCommittedEntry())) &&
        !nav_entry->GetURL().IsAboutBlank() &&
        !SiteInstanceImpl::ShouldAssignSiteForURL(nav_entry->GetURL())) {
      scoped_refptr<FrameNavigationEntry> frame_entry =
          nav_entry->root_node()->frame_entry;
      scoped_refptr<SiteInstanceImpl> new_site_instance =
          base::WrapRefCounted<SiteInstanceImpl>(static_cast<SiteInstanceImpl*>(
              instance->GetRelatedSiteInstance(frame_entry->url()).get()));
      nav_entry->AddOrUpdateFrameEntry(
          frame_tree_node_, frame_entry->item_sequence_number(),
          frame_entry->document_sequence_number(), new_site_instance.get(),
          frame_entry->source_site_instance(), frame_entry->url(),
          frame_entry->committed_origin(), frame_entry->referrer(),
          frame_entry->initiator_origin(), frame_entry->redirect_chain(),
          frame_entry->page_state(), frame_entry->method(),
          frame_entry->post_id(), frame_entry->blob_url_loader_factory());
    }
  }

  devtools_instrumentation::OnNavigationResponseReceived(*this,
                                                         *response_head_);

  // The response code indicates that this is an error page, but we don't
  // know how to display the content.  We follow Firefox here and show our
  // own error page instead of intercepting the request as a stream or a
  // download.
  if (is_download && (response_head_->headers.get() &&
                      (response_head_->headers->response_code() / 100 != 2))) {
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(net::ERR_INVALID_RESPONSE),
        false /* skip_throttles */, base::nullopt /* error_page_content */,
        false /* collapse_frame */);

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  // The CSP 'navigate-to' directive needs to know whether the response is a
  // redirect or not in order to perform its checks. This is the reason why we
  // need to check the CSP both on request and response.
  net::Error net_error = CheckContentSecurityPolicy(
      was_redirected_ /* has_followed_redirect */,
      false /* url_upgraded_after_redirect */, true /* is_response_check */);
  if (net_error != net::OK) {
    OnRequestFailedInternal(network::URLLoaderCompletionStatus(net_error),
                            false /* skip_throttles */,
                            base::nullopt /* error_page_content */,
                            false /* collapse_frame */);

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  // Check if the navigation should be allowed to proceed.
  WillProcessResponse();
}

void NavigationRequest::OnRequestFailed(
    const network::URLLoaderCompletionStatus& status) {
  DCHECK_NE(status.error_code, net::OK);

  bool collapse_frame =
      status.extended_error_code ==
      static_cast<int>(blink::ResourceRequestBlockedReason::kCollapsedByClient);
  OnRequestFailedInternal(status, false /* skip_throttles */,
                          base::nullopt /* error_page_content */,
                          collapse_frame);
}

void NavigationRequest::OnRequestFailedInternal(
    const network::URLLoaderCompletionStatus& status,
    bool skip_throttles,
    const base::Optional<std::string>& error_page_content,
    bool collapse_frame) {
  DCHECK(state_ == WILL_START_NAVIGATION || state_ == WILL_START_REQUEST ||
         state_ == WILL_REDIRECT_REQUEST || state_ == WILL_PROCESS_RESPONSE ||
         state_ == DID_COMMIT || state_ == CANCELING ||
         state_ == WILL_FAIL_REQUEST);
  DCHECK(!(status.error_code == net::ERR_ABORTED &&
           error_page_content.has_value()));
  ScopedNavigationRequestCrashKeys crash_keys(this);

  // The request failed, the |loader_| must not call the NavigationRequest
  // anymore from now while the error page is being loaded.
  loader_.reset();

  common_params_->previews_state = PREVIEWS_OFF;
  if (status.ssl_info.has_value())
    ssl_info_ = status.ssl_info;

  devtools_instrumentation::OnNavigationRequestFailed(*this, status);

  // TODO(https://crbug.com/757633): Check that ssl_info.has_value() if
  // net_error is a certificate error.
  EnterChildTraceEvent("OnRequestFailed", this, "error", status.error_code);
  state_ = WILL_FAIL_REQUEST;
  processing_navigation_throttle_ = false;

  // Ensure the pending entry also gets discarded if it has no other active
  // requests.
  pending_entry_ref_.reset();

  net_error_ = static_cast<net::Error>(status.error_code);
  resolve_error_info_ = status.resolve_error_info;

  // If the request was canceled by the user do not show an error page.
  if (status.error_code == net::ERR_ABORTED) {
    frame_tree_node_->ResetNavigationRequest(false);
    return;
  }

  if (collapse_frame) {
    DCHECK(!frame_tree_node_->IsMainFrame());
    DCHECK_EQ(net::ERR_BLOCKED_BY_CLIENT, status.error_code);
    frame_tree_node_->SetCollapsed(true);
  }

  RenderFrameHostImpl* render_frame_host = nullptr;
  if (SiteIsolationPolicy::IsErrorPageIsolationEnabled(
          frame_tree_node_->IsMainFrame())) {
    // Main frame error pages must be isolated from the source or destination
    // process.
    //
    // Note: Since this navigation resulted in an error, clear the expected
    // process for the original navigation since for main frames the error page
    // will go into a new process.
    // TODO(nasko): Investigate whether GetFrameHostForNavigation can properly
    // account for clearing the expected process if it clears the speculative
    // RenderFrameHost. See https://crbug.com/793127.
    ResetExpectedProcess();
    render_frame_host =
        frame_tree_node_->render_manager()->GetFrameHostForNavigation(this);
  } else {
    if (ShouldKeepErrorPageInCurrentProcess(status.error_code)) {
      render_frame_host = frame_tree_node_->current_frame_host();
    } else {
      render_frame_host =
          frame_tree_node_->render_manager()->GetFrameHostForNavigation(this);
    }
  }

  // Sanity check that we haven't changed the RenderFrameHost picked for the
  // error page in OnRequestFailedInternal when running the WillFailRequest
  // checks.
  CHECK(!render_frame_host_ || render_frame_host_ == render_frame_host);
  render_frame_host_ = render_frame_host;

  // The check for WebUI should be performed only if error page isolation is
  // enabled for this failed navigation. It is possible for subframe error page
  // to be committed in a WebUI process as shown in https://crbug.com/944086.
  if (SiteIsolationPolicy::IsErrorPageIsolationEnabled(
          frame_tree_node_->IsMainFrame())) {
    NavigatorImpl::CheckWebUIRendererDoesNotDisplayNormalURL(
        render_frame_host_, common_params_->url);
  }

  has_stale_copy_in_cache_ = status.exists_in_cache;

  if (skip_throttles) {
    // The NavigationHandle shouldn't be notified about renderer-debug URLs.
    // They will be handled by the renderer process.
    CommitErrorPage(error_page_content);
  } else {
    // Check if the navigation should be allowed to proceed.
    WillFailRequest();
  }
}

bool NavigationRequest::ShouldKeepErrorPageInCurrentProcess(int net_error) {
  // Decide whether to leave the error page in the original process.
  // * If this was a renderer-initiated navigation, and the request is blocked
  //   because the initiating document wasn't allowed to make the request,
  //   commit the error in the existing process. This is a strategy to to
  //   avoid creating a process for the destination, which may belong to an
  //   origin with a higher privilege level.
  // * Error pages resulting from errors like network outage, no network, or
  //   DNS error can reasonably expect that a reload at a later point in time
  //   would work. These should be allowed to transfer away from the current
  //   process: they do belong to whichever process that will host the
  //   destination URL, as a reload will end up committing in that process
  //   anyway.
  // * Error pages that arise during browser-initiated navigations to blocked
  //   URLs should be allowed to transfer away from the current process, which
  //   didn't request the navigation and may have a higher privilege level
  //   than the blocked destination.
  return net_error == net::ERR_BLOCKED_BY_CLIENT && !browser_initiated();
}

void NavigationRequest::OnRequestStarted(base::TimeTicks timestamp) {
  frame_tree_node_->navigator()->LogResourceRequestTime(timestamp,
                                                        common_params_->url);
}

void NavigationRequest::OnStartChecksComplete(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK(result.action() != NavigationThrottle::DEFER);
  DCHECK(result.action() != NavigationThrottle::BLOCK_RESPONSE);

  if (on_start_checks_complete_closure_)
    std::move(on_start_checks_complete_closure_).Run();
  // Abort the request if needed. This will destroy the NavigationRequest.
  if (result.action() == NavigationThrottle::CANCEL_AND_IGNORE ||
      result.action() == NavigationThrottle::CANCEL ||
      result.action() == NavigationThrottle::BLOCK_REQUEST ||
      result.action() == NavigationThrottle::BLOCK_REQUEST_AND_COLLAPSE) {
#if DCHECK_IS_ON()
    if (result.action() == NavigationThrottle::BLOCK_REQUEST) {
      DCHECK(result.net_error_code() == net::ERR_BLOCKED_BY_CLIENT ||
             result.net_error_code() == net::ERR_BLOCKED_BY_ADMINISTRATOR);
    }
    // TODO(clamy): distinguish between CANCEL and CANCEL_AND_IGNORE.
    else if (result.action() == NavigationThrottle::CANCEL_AND_IGNORE) {
      DCHECK_EQ(result.net_error_code(), net::ERR_ABORTED);
    }
#endif

    bool collapse_frame =
        result.action() == NavigationThrottle::BLOCK_REQUEST_AND_COLLAPSE;

    // If the start checks completed synchronously, which could happen if there
    // is no onbeforeunload handler or if a NavigationThrottle cancelled it,
    // then this could cause reentrancy into NavigationController. So use a
    // PostTask to avoid that.
    base::PostTask(FROM_HERE, {BrowserThread::UI},
                   base::BindOnce(&NavigationRequest::OnRequestFailedInternal,
                                  weak_factory_.GetWeakPtr(),
                                  network::URLLoaderCompletionStatus(
                                      result.net_error_code()),
                                  true /* skip_throttles */,
                                  result.error_page_content(), collapse_frame));

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  // Use the SiteInstance of the navigating RenderFrameHost to get access to
  // the StoragePartition. Using the url of the navigation will result in a
  // wrong StoragePartition being picked when a WebView is navigating.
  DCHECK_NE(AssociatedSiteInstanceType::NONE, associated_site_instance_type_);
  RenderFrameHostImpl* navigating_frame_host =
      associated_site_instance_type_ == AssociatedSiteInstanceType::SPECULATIVE
          ? frame_tree_node_->render_manager()->speculative_frame_host()
          : frame_tree_node_->current_frame_host();
  DCHECK(navigating_frame_host);

  SetExpectedProcess(navigating_frame_host->GetProcess());

  BrowserContext* browser_context =
      frame_tree_node_->navigator()->GetController()->GetBrowserContext();
  StoragePartition* partition = BrowserContext::GetStoragePartition(
      browser_context, navigating_frame_host->GetSiteInstance());
  DCHECK(partition);

  // |loader_| should not exist if the service worker handle and app cache
  // handles will be destroyed, since it holds raw pointers to them. See the
  // comment in the header for |loader_|.
  DCHECK(!loader_);

  // Only initialize the ServiceWorkerMainResourceHandle if it can be created
  // for this frame.
  bool can_create_service_worker =
      (frame_tree_node_->pending_frame_policy().sandbox_flags &
       blink::mojom::WebSandboxFlags::kOrigin) !=
      blink::mojom::WebSandboxFlags::kOrigin;
  if (can_create_service_worker) {
    ServiceWorkerContextWrapper* service_worker_context =
        static_cast<ServiceWorkerContextWrapper*>(
            partition->GetServiceWorkerContext());
    service_worker_handle_ = std::make_unique<ServiceWorkerMainResourceHandle>(
        service_worker_context);
  }

  if (IsSchemeSupportedForAppCache(common_params_->url)) {
    if (navigating_frame_host->GetRenderViewHost()
            ->GetWebkitPreferences()
            .application_cache_enabled) {
      // The final process id won't be available until
      // NavigationRequest::ReadyToCommitNavigation.
      appcache_handle_.reset(new AppCacheNavigationHandle(
          static_cast<ChromeAppCacheService*>(partition->GetAppCacheService()),
          ChildProcessHost::kInvalidUniqueID));
    }
  }

  // Initialize the WebBundleHandle.
  if (web_bundle_handle_tracker_) {
    DCHECK(base::FeatureList::IsEnabled(features::kWebBundles) ||
           base::FeatureList::IsEnabled(features::kWebBundlesFromNetwork) ||
           base::CommandLine::ForCurrentProcess()->HasSwitch(
               switches::kTrustableWebBundleFileUrl));
    web_bundle_handle_ = web_bundle_handle_tracker_->MaybeCreateWebBundleHandle(
        common_params_->url, frame_tree_node_->frame_tree_node_id());
  }
  if (!web_bundle_handle_ && web_bundle_navigation_info_) {
    DCHECK(base::FeatureList::IsEnabled(features::kWebBundles) ||
           base::FeatureList::IsEnabled(features::kWebBundlesFromNetwork) ||
           base::CommandLine::ForCurrentProcess()->HasSwitch(
               switches::kTrustableWebBundleFileUrl));
    web_bundle_handle_ = WebBundleHandle::MaybeCreateForNavigationInfo(
        web_bundle_navigation_info_->Clone(),
        frame_tree_node_->frame_tree_node_id());
  }
  if (!web_bundle_handle_) {
    if (web_bundle_utils::CanLoadAsTrustableWebBundleFile(
            common_params_->url)) {
      auto source =
          WebBundleSource::MaybeCreateFromTrustedFileUrl(common_params_->url);
      // MaybeCreateFromTrustedFileUrl() returns null when the url contains an
      // invalid character.
      if (source) {
        web_bundle_handle_ = WebBundleHandle::CreateForTrustableFile(
            std::move(source), frame_tree_node_->frame_tree_node_id());
      }
    } else if (web_bundle_utils::CanLoadAsWebBundleFile(common_params_->url)) {
      web_bundle_handle_ = WebBundleHandle::CreateForFile(
          frame_tree_node_->frame_tree_node_id());
    } else if (base::FeatureList::IsEnabled(features::kWebBundlesFromNetwork)) {
      web_bundle_handle_ = WebBundleHandle::CreateForNetwork(
          browser_context, frame_tree_node_->frame_tree_node_id());
    }
  }

  // Mark the fetch_start (Navigation Timing API).
  commit_params_->navigation_timing->fetch_start = base::TimeTicks::Now();

  net::SiteForCookies site_for_cookies =
      frame_tree_node_->current_frame_host()
          ->ComputeSiteForCookiesForNavigation(common_params_->url);
  bool parent_is_main_frame = !frame_tree_node_->parent()
                                  ? false
                                  : frame_tree_node_->parent()->IsMainFrame();

  std::unique_ptr<NavigationUIData> navigation_ui_data;
  if (navigation_ui_data_)
    navigation_ui_data = navigation_ui_data_->Clone();

  // Give DevTools a chance to override begin params (headers, skip SW)
  // before actually loading resource.
  bool report_raw_headers = false;
  devtools_instrumentation::ApplyNetworkRequestOverrides(
      frame_tree_node_, begin_params_.get(), &report_raw_headers);
  devtools_instrumentation::OnNavigationRequestWillBeSent(*this);

  // Merge headers with embedder's headers.
  net::HttpRequestHeaders headers;
  headers.AddHeadersFromString(begin_params_->headers);
  headers.MergeFrom(TakeModifiedRequestHeaders());
  begin_params_->headers = headers.ToString();

  // TODO(clamy): Avoid cloning the navigation params and create the
  // ResourceRequest directly here.
  std::vector<std::unique_ptr<NavigationLoaderInterceptor>> interceptor;
  if (web_bundle_handle_)
    interceptor.push_back(web_bundle_handle_->TakeInterceptor());
  loader_ = NavigationURLLoader::Create(
      browser_context, partition,
      std::make_unique<NavigationRequestInfo>(
          common_params_->Clone(), begin_params_.Clone(), site_for_cookies,
          GetNetworkIsolationKey(), frame_tree_node_->IsMainFrame(),
          parent_is_main_frame, IsSecureFrame(frame_tree_node_->parent()),
          frame_tree_node_->frame_tree_node_id(),
          starting_site_instance_->IsGuest(), report_raw_headers,
          navigating_frame_host->GetVisibilityState() ==
              PageVisibilityState::kHiddenButPainting,
          upgrade_if_insecure_,
          blob_url_loader_factory_ ? blob_url_loader_factory_->Clone()
                                   : nullptr,
          devtools_navigation_token(), frame_tree_node_->devtools_frame_token(),
          OriginPolicyThrottle::ShouldRequestOriginPolicy(common_params_->url)),
      std::move(navigation_ui_data), service_worker_handle_.get(),
      appcache_handle_.get(), std::move(prefetched_signed_exchange_cache_),
      this, IsServedFromBackForwardCache(), std::move(interceptor));

  DCHECK(!render_frame_host_);
}

void NavigationRequest::OnRedirectChecksComplete(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK(result.action() != NavigationThrottle::DEFER);
  DCHECK(result.action() != NavigationThrottle::BLOCK_RESPONSE);

  bool collapse_frame =
      result.action() == NavigationThrottle::BLOCK_REQUEST_AND_COLLAPSE;

  // Abort the request if needed. This will destroy the NavigationRequest.
  if (result.action() == NavigationThrottle::CANCEL_AND_IGNORE ||
      result.action() == NavigationThrottle::CANCEL) {
    // TODO(clamy): distinguish between CANCEL and CANCEL_AND_IGNORE if needed.
    DCHECK(result.action() == NavigationThrottle::CANCEL ||
           result.net_error_code() == net::ERR_ABORTED);
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(result.net_error_code()),
        true /* skip_throttles */, result.error_page_content(), collapse_frame);

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  if (result.action() == NavigationThrottle::BLOCK_REQUEST ||
      result.action() == NavigationThrottle::BLOCK_REQUEST_AND_COLLAPSE) {
    DCHECK(result.net_error_code() == net::ERR_BLOCKED_BY_CLIENT ||
           result.net_error_code() == net::ERR_BLOCKED_BY_ADMINISTRATOR);
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(result.net_error_code()),
        true /* skip_throttles */, result.error_page_content(), collapse_frame);
    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  devtools_instrumentation::OnNavigationRequestWillBeSent(*this);

  net::HttpRequestHeaders modified_headers = TakeModifiedRequestHeaders();
  std::vector<std::string> removed_headers = TakeRemovedRequestHeaders();

  BrowserContext* browser_context =
      frame_tree_node_->navigator()->GetController()->GetBrowserContext();
  ClientHintsControllerDelegate* client_hints_delegate =
      browser_context->GetClientHintsControllerDelegate();
  if (client_hints_delegate) {
    net::HttpRequestHeaders client_hints_extra_headers;
    RenderViewHost* render_view_host =
        frame_tree_node_->current_frame_host()->GetRenderViewHost();
    const bool javascript_enabled =
        render_view_host->GetWebkitPreferences().javascript_enabled;
    AddNavigationRequestClientHintsHeaders(
        common_params_->url, &client_hints_extra_headers, browser_context,
        javascript_enabled, client_hints_delegate,
        commit_params_->is_overriding_user_agent || entry_overrides_ua_,
        frame_tree_node_);
    modified_headers.MergeFrom(client_hints_extra_headers);
  }

  loader_->FollowRedirect(std::move(removed_headers),
                          std::move(modified_headers),
                          common_params_->previews_state);
}

void NavigationRequest::OnFailureChecksComplete(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK(result.action() != NavigationThrottle::DEFER);

  net::Error old_net_error = net_error_;
  net_error_ = result.net_error_code();

  // TODO(crbug.com/774663): We may want to take result.action() into account.
  if (net::ERR_ABORTED == result.net_error_code()) {
    frame_tree_node_->ResetNavigationRequest(false);
    return;
  }

  // Ensure that WillFailRequest() isn't changing the error code in a way that
  // switches the destination process for the error page - see
  // https://crbug.com/817881.  This is not a concern with error page
  // isolation, where all errors will go into one process.
  if (!SiteIsolationPolicy::IsErrorPageIsolationEnabled(
          frame_tree_node_->IsMainFrame())) {
    CHECK_EQ(ShouldKeepErrorPageInCurrentProcess(old_net_error),
             ShouldKeepErrorPageInCurrentProcess(net_error_))
        << " Unsupported error code change in WillFailRequest(): from "
        << net_error_ << " to " << result.net_error_code();
  }

  CommitErrorPage(result.error_page_content());
  // DO NOT ADD CODE after this. The previous call to CommitErrorPage caused
  // the destruction of the NavigationRequest.
}

void NavigationRequest::OnWillProcessResponseChecksComplete(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK(result.action() != NavigationThrottle::DEFER);

  // If the NavigationThrottles allowed the navigation to continue, have the
  // processing of the response resume in the network stack.
  if (result.action() == NavigationThrottle::PROCEED) {
    // If this is a download, intercept the navigation response and pass it to
    // DownloadManager, and cancel the navigation.
    if (is_download_) {
      // TODO(arthursonzogni): Pass the real ResourceRequest. For the moment
      // only these parameters will be used, but it may evolve quickly.
      auto resource_request = std::make_unique<network::ResourceRequest>();
      resource_request->url = common_params_->url;
      resource_request->method = common_params_->method;
      resource_request->request_initiator = common_params_->initiator_origin;
      resource_request->referrer = common_params_->referrer->url;
      resource_request->has_user_gesture = common_params_->has_user_gesture;
      resource_request->mode = network::mojom::RequestMode::kNavigate;
      resource_request->transition_type = common_params_->transition;
      resource_request->trusted_params =
          network::ResourceRequest::TrustedParams();
      resource_request->trusted_params->network_isolation_key =
          GetNetworkIsolationKey();

      BrowserContext* browser_context =
          frame_tree_node_->navigator()->GetController()->GetBrowserContext();
      DownloadManagerImpl* download_manager = static_cast<DownloadManagerImpl*>(
          BrowserContext::GetDownloadManager(browser_context));
      download_manager->InterceptNavigation(
          std::move(resource_request), redirect_chain_, response_head_.Clone(),
          std::move(response_body_), std::move(url_loader_client_endpoints_),
          ssl_info_.has_value() ? ssl_info_->cert_status : 0,
          frame_tree_node_->frame_tree_node_id(),
          from_download_cross_origin_redirect_);

      OnRequestFailedInternal(
          network::URLLoaderCompletionStatus(net::ERR_ABORTED),
          false /*skip_throttles*/, base::nullopt /*error_page_content*/,
          false /*collapse_frame*/);
      // DO NOT ADD CODE after this. The previous call to OnRequestFailed has
      // destroyed the NavigationRequest.
      return;
    }
  }

  // Abort the request if needed. This includes requests that were blocked by
  // NavigationThrottles and requests that should not commit (e.g. downloads,
  // 204/205s). This will destroy the NavigationRequest.
  if (result.action() == NavigationThrottle::CANCEL_AND_IGNORE ||
      result.action() == NavigationThrottle::CANCEL ||
      !response_should_be_rendered_) {
    // Reset the RenderFrameHost that had been computed for the commit of the
    // navigation.
    render_frame_host_ = nullptr;

    // TODO(clamy): distinguish between CANCEL and CANCEL_AND_IGNORE.
    if (!response_should_be_rendered_) {
      // DO NOT ADD CODE after this. The previous call to OnRequestFailed has
      // destroyed the NavigationRequest.
      OnRequestFailedInternal(
          network::URLLoaderCompletionStatus(net::ERR_ABORTED),
          true /* skip_throttles */, base::nullopt /* error_page_content */,
          false /* collapse_frame */);
      return;
    }

    DCHECK(result.action() == NavigationThrottle::CANCEL ||
           result.net_error_code() == net::ERR_ABORTED);
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(result.net_error_code()),
        true /* skip_throttles */, result.error_page_content(),
        false /* collapse_frame */);

    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  if (result.action() == NavigationThrottle::BLOCK_RESPONSE) {
    DCHECK_EQ(net::ERR_BLOCKED_BY_RESPONSE, result.net_error_code());
    // Reset the RenderFrameHost that had been computed for the commit of the
    // navigation.
    render_frame_host_ = nullptr;
    OnRequestFailedInternal(
        network::URLLoaderCompletionStatus(result.net_error_code()),
        true /* skip_throttles */, result.error_page_content(),
        false /* collapse_frame */);
    // DO NOT ADD CODE after this. The previous call to OnRequestFailedInternal
    // has destroyed the NavigationRequest.
    return;
  }

  CommitNavigation();

  // DO NOT ADD CODE after this. The previous call to CommitNavigation caused
  // the destruction of the NavigationRequest.
}

void NavigationRequest::CommitErrorPage(
    const base::Optional<std::string>& error_page_content) {
  UpdateCommitNavigationParamsHistory();

  // Error pages are always cross-document.
  //
  // This is useful when a same-document navigation is blocked and commit an
  // error page instead. See https://crbug.com/1018385.
  common_params_->navigation_type =
      ConvertToCrossDocumentType(common_params_->navigation_type);

  frame_tree_node_->TransferNavigationRequestOwnership(render_frame_host_);
  // Error pages commit in an opaque origin in the renderer process. If this
  // NavigationRequest resulted in committing an error page, set
  // |origin_to_commit| to an opaque origin that has precursor information
  // consistent with the URL being requested.
  commit_params_->origin_to_commit =
      url::Origin::Create(common_params_->url).DeriveNewOpaqueOrigin();
  if (request_navigation_client_.is_bound()) {
    if (render_frame_host_ == frame_tree_node()->current_frame_host()) {
      // Reuse the request NavigationClient for commit.
      commit_navigation_client_ = std::move(request_navigation_client_);
    } else {
      // This navigation is cross-RenderFrameHost: the original document should
      // no longer be able to cancel it.
      IgnoreInterfaceDisconnection();
    }
  }

  ReadyToCommitNavigation(true);
  render_frame_host_->FailedNavigation(this, *common_params_, *commit_params_,
                                       has_stale_copy_in_cache_, net_error_,
                                       error_page_content);
}

void NavigationRequest::CommitNavigation() {
  UpdateCommitNavigationParamsHistory();
  DCHECK(NeedsUrlLoader() == !!response_head_ ||
         (was_redirected_ && common_params_->url.IsAboutBlank()));
  DCHECK(!common_params_->url.SchemeIs(url::kJavaScriptScheme));
  DCHECK(!IsRendererDebugURL(common_params_->url));

  if (IsServedFromBackForwardCache()) {
    NavigationControllerImpl* controller =
        static_cast<NavigationControllerImpl*>(
            frame_tree_node_->navigator()->GetController());

    std::unique_ptr<BackForwardCacheImpl::Entry> restored_bfcache_entry =
        controller->GetBackForwardCache().RestoreEntry(nav_entry_id_,
                                                       NavigationStart());

    if (!restored_bfcache_entry) {
      // The only time restored_bfcache_entry can be nullptr here, is if the
      // document was evicted from the BackForwardCache since this navigation
      // started.
      //
      // If the document was evicted, it should have posted a task to re-issue
      // the navigation - ensure that this happened.
      CHECK(restarting_back_forward_cached_navigation_);
      return;
    } else {
      CHECK(!restarting_back_forward_cached_navigation_);
    }

    // Transfer ownership of this NavigationRequest to the restored
    // RenderFrameHost.
    frame_tree_node_->TransferNavigationRequestOwnership(GetRenderFrameHost());

    // Move the restored BackForwardCache Entry into RenderFrameHostManager, in
    // preparation for committing.
    frame_tree_node_->render_manager()->RestoreFromBackForwardCache(
        std::move(restored_bfcache_entry));

    // Commit the restored BackForwardCache Entry. This includes committing the
    // RenderFrameHost and restoring extra state, such as proxies, etc.
    // Note that this will delete the NavigationRequest.
    GetRenderFrameHost()->DidCommitBackForwardCacheNavigation(
        this, MakeDidCommitProvisionalLoadParamsForBFCache());

    return;
  }

  DCHECK(render_frame_host_ ==
             frame_tree_node_->render_manager()->current_frame_host() ||
         render_frame_host_ ==
             frame_tree_node_->render_manager()->speculative_frame_host());

  frame_tree_node_->TransferNavigationRequestOwnership(render_frame_host_);

  if (request_navigation_client_.is_bound()) {
    if (render_frame_host_ == frame_tree_node()->current_frame_host()) {
      // Reuse the request NavigationClient for commit.
      commit_navigation_client_ = std::move(request_navigation_client_);
    } else {
      // This navigation is cross-RenderFrameHost: the original document should
      // no longer be able to cancel it.
      IgnoreInterfaceDisconnection();
    }
  }

  CreateCoepReporter(render_frame_host_->GetProcess()->GetStoragePartition());

  blink::mojom::ServiceWorkerProviderInfoForClientPtr
      service_worker_provider_info;
  if (service_worker_handle_) {
    DCHECK(coep_reporter());
    mojo::PendingRemote<network::mojom::CrossOriginEmbedderPolicyReporter>
        reporter_remote;
    coep_reporter()->Clone(reporter_remote.InitWithNewPipeAndPassReceiver());
    // Notify the service worker navigation handle that navigation commit is
    // about to go.
    service_worker_handle_->OnBeginNavigationCommit(
        render_frame_host_->GetProcess()->GetID(),
        render_frame_host_->GetRoutingID(),
        render_frame_host_->cross_origin_embedder_policy(),
        std::move(reporter_remote), &service_worker_provider_info);
  }

  if (web_bundle_handle_ && web_bundle_handle_->navigation_info()) {
    web_bundle_navigation_info_ =
        web_bundle_handle_->navigation_info()->Clone();
  }

  auto common_params = common_params_->Clone();
  auto commit_params = commit_params_.Clone();
  auto response_head = response_head_.Clone();
  if (subresource_loader_params_ &&
      !subresource_loader_params_->prefetched_signed_exchanges.empty()) {
    commit_params->prefetched_signed_exchanges =
        std::move(subresource_loader_params_->prefetched_signed_exchanges);
  }

  render_frame_host_->CommitNavigation(
      this, std::move(common_params), std::move(commit_params),
      std::move(response_head), std::move(response_body_),
      std::move(url_loader_client_endpoints_), is_view_source_,
      std::move(subresource_loader_params_), std::move(subresource_overrides_),
      std::move(service_worker_provider_info), devtools_navigation_token_,
      std::move(web_bundle_handle_));

  // Give SpareRenderProcessHostManager a heads-up about the most recently used
  // BrowserContext.  This is mostly needed to make sure the spare is warmed-up
  // if it wasn't done in RenderProcessHostImpl::GetProcessHostForSiteInstance.
  RenderProcessHostImpl::NotifySpareManagerAboutRecentlyUsedBrowserContext(
      render_frame_host_->GetSiteInstance()->GetBrowserContext());
}

void NavigationRequest::ResetExpectedProcess() {
  if (expected_render_process_host_id_ == ChildProcessHost::kInvalidUniqueID) {
    // No expected process is set, nothing to update.
    return;
  }
  RenderProcessHost* process =
      RenderProcessHost::FromID(expected_render_process_host_id_);
  if (process) {
    RenderProcessHostImpl::RemoveExpectedNavigationToSite(
        frame_tree_node()->navigator()->GetController()->GetBrowserContext(),
        process, site_url_);
    process->RemoveObserver(this);
  }
  expected_render_process_host_id_ = ChildProcessHost::kInvalidUniqueID;
}

void NavigationRequest::SetExpectedProcess(
    RenderProcessHost* expected_process) {
  if (expected_process &&
      expected_process->GetID() == expected_render_process_host_id_) {
    // This |expected_process| has already been informed of the navigation,
    // no need to update it again.
    return;
  }

  ResetExpectedProcess();

  if (expected_process == nullptr)
    return;

  // Keep track of the speculative RenderProcessHost and tell it to expect a
  // navigation to |site_url_|.
  expected_render_process_host_id_ = expected_process->GetID();
  expected_process->AddObserver(this);
  RenderProcessHostImpl::AddExpectedNavigationToSite(
      frame_tree_node()->navigator()->GetController()->GetBrowserContext(),
      expected_process, site_url_);
}

void NavigationRequest::RenderProcessHostDestroyed(RenderProcessHost* host) {
  DCHECK_EQ(host->GetID(), expected_render_process_host_id_);
  ResetExpectedProcess();
}

void NavigationRequest::RenderProcessExited(
    RenderProcessHost* host,
    const ChildProcessTerminationInfo& info) {
}

void NavigationRequest::UpdateSiteURL(
    RenderProcessHost* post_redirect_process) {
  GURL new_site_url = GetSiteForCommonParamsURL();
  int post_redirect_process_id = post_redirect_process
                                     ? post_redirect_process->GetID()
                                     : ChildProcessHost::kInvalidUniqueID;
  if (new_site_url == site_url_ &&
      post_redirect_process_id == expected_render_process_host_id_) {
    return;
  }

  // Stop expecting a navigation to the current site URL in the current expected
  // process.
  ResetExpectedProcess();

  // Update the site URL and the expected process.
  site_url_ = new_site_url;
  SetExpectedProcess(post_redirect_process);
}

bool NavigationRequest::IsAllowedByCSPDirective(
    network::CSPContext* context,
    network::mojom::CSPDirectiveName directive,
    bool has_followed_redirect,
    bool url_upgraded_after_redirect,
    bool is_response_check,
    network::CSPContext::CheckCSPDisposition disposition) {
  GURL url;
  // If this request was upgraded in the net stack, downgrade the URL back to
  // HTTP before checking report only policies.
  if (url_upgraded_after_redirect &&
      disposition ==
          network::CSPContext::CheckCSPDisposition::CHECK_REPORT_ONLY_CSP &&
      common_params_->url.SchemeIs(url::kHttpsScheme)) {
    GURL::Replacements replacements;
    replacements.SetSchemeStr(url::kHttpScheme);
    url = common_params_->url.ReplaceComponents(replacements);
  } else {
    url = common_params_->url;
  }
  return context->IsAllowedByCsp(directive, url, has_followed_redirect,
                                 is_response_check,
                                 common_params_->source_location, disposition,
                                 begin_params_->is_form_submission);
}

net::Error NavigationRequest::CheckCSPDirectives(
    RenderFrameHostImpl* parent,
    bool has_followed_redirect,
    bool url_upgraded_after_redirect,
    bool is_response_check,
    network::CSPContext::CheckCSPDisposition disposition) {
  bool navigate_to_allowed = IsAllowedByCSPDirective(
      initiator_csp_context_.get(),
      network::mojom::CSPDirectiveName::NavigateTo, has_followed_redirect,
      url_upgraded_after_redirect, is_response_check, disposition);

  bool frame_src_allowed = true;
  if (parent) {
    frame_src_allowed = IsAllowedByCSPDirective(
        parent, network::mojom::CSPDirectiveName::FrameSrc,
        has_followed_redirect, url_upgraded_after_redirect, is_response_check,
        disposition);
  }

  if (navigate_to_allowed && frame_src_allowed)
    return net::OK;

  // If 'frame-src' fails, ERR_BLOCKED_BY_CLIENT is used instead.
  // If both checks fail, ERR_BLOCKED_BY_CLIENT is used to keep the existing
  // behaviour before 'navigate-to' was introduced.
  if (!frame_src_allowed)
    return net::ERR_BLOCKED_BY_CLIENT;

  // net::ERR_ABORTED is used to ensure that the navigation is cancelled
  // when the 'navigate-to' directive check is failed. This is a better user
  // experience as the user is not presented with an error page.
  return net::ERR_ABORTED;
}

net::Error NavigationRequest::CheckContentSecurityPolicy(
    bool has_followed_redirect,
    bool url_upgraded_after_redirect,
    bool is_response_check) {
  if (common_params_->url.SchemeIs(url::kAboutScheme))
    return net::OK;

  if (common_params_->initiator_csp_info->should_check_main_world_csp ==
      network::mojom::CSPDisposition::DO_NOT_CHECK) {
    return net::OK;
  }

  FrameTreeNode* parent_ftn = frame_tree_node()->parent();
  RenderFrameHostImpl* parent =
      parent_ftn ? parent_ftn->current_frame_host() : nullptr;
  if (!parent &&
      frame_tree_node()
          ->current_frame_host()
          ->GetRenderViewHost()
          ->GetDelegate()
          ->IsPortal() &&
      frame_tree_node()->render_manager()->GetOuterDelegateNode()) {
    parent = frame_tree_node()
                 ->render_manager()
                 ->GetOuterDelegateNode()
                 ->current_frame_host()
                 ->GetParent();
  }

  // TODO(andypaicu,https://crbug.com/837627): the current_frame_host is the
  // wrong RenderFrameHost. We should be using the navigation initiator
  // RenderFrameHost.
  initiator_csp_context_->SetReportingRenderFrameHost(
      frame_tree_node()->current_frame_host());

  // CSP checking happens in three phases, per steps 3-5 of
  // https://fetch.spec.whatwg.org/#main-fetch:
  //
  // (1) Check report-only policies and trigger reports for any violations.
  // (2) Upgrade the request to HTTPS if necessary.
  // (3) Check enforced policies (triggering reports for any violations of those
  //     policies) and block the request if necessary.
  //
  // This sequence of events allows site owners to learn about (via step 1) any
  // requests that are upgraded in step 2.

  net::Error report_only_csp_status = CheckCSPDirectives(
      parent, has_followed_redirect, url_upgraded_after_redirect,
      is_response_check, network::CSPContext::CHECK_REPORT_ONLY_CSP);

  // upgrade-insecure-requests is handled in the network code for redirects,
  // only do the upgrade here if this is not a redirect.
  if (!has_followed_redirect && !frame_tree_node()->IsMainFrame()) {
    if (network::ShouldUpgradeInsecureRequest(
            parent->ContentSecurityPolicies())) {
      upgrade_if_insecure_ = true;
      network::UpgradeInsecureRequest(&common_params_->url);
      commit_params_->original_url = common_params_->url;
    }
  }

  net::Error enforced_csp_status = CheckCSPDirectives(
      parent, has_followed_redirect, url_upgraded_after_redirect,
      is_response_check, network::CSPContext::CHECK_ENFORCED_CSP);
  if (enforced_csp_status != net::OK)
    return enforced_csp_status;
  return report_only_csp_status;
}

NavigationRequest::CredentialedSubresourceCheckResult
NavigationRequest::CheckCredentialedSubresource() const {
  // It only applies to subframes.
  if (frame_tree_node_->IsMainFrame())
    return CredentialedSubresourceCheckResult::ALLOW_REQUEST;

  // URLs with no embedded credentials should load correctly.
  if (!common_params_->url.has_username() &&
      !common_params_->url.has_password())
    return CredentialedSubresourceCheckResult::ALLOW_REQUEST;

  // Relative URLs on top-level pages that were loaded with embedded credentials
  // should load correctly.
  FrameTreeNode* parent_ftn = frame_tree_node_->parent();
  DCHECK(parent_ftn);
  const GURL& parent_url = parent_ftn->current_url();
  if (url::Origin::Create(parent_url)
          .IsSameOriginWith(url::Origin::Create(common_params_->url)) &&
      parent_url.username() == common_params_->url.username() &&
      parent_url.password() == common_params_->url.password()) {
    return CredentialedSubresourceCheckResult::ALLOW_REQUEST;
  }

  // Warn the user about the request being blocked.
  RenderFrameHostImpl* parent = parent_ftn->current_frame_host();
  DCHECK(parent);
  const char* console_message =
      "Subresource requests whose URLs contain embedded credentials (e.g. "
      "`https://user:pass@host/`) are blocked. See "
      "https://www.chromestatus.com/feature/5669008342777856 for more "
      "details.";
  parent->AddMessageToConsole(blink::mojom::ConsoleMessageLevel::kWarning,
                              console_message);
  if (!base::FeatureList::IsEnabled(features::kBlockCredentialedSubresources))
    return CredentialedSubresourceCheckResult::ALLOW_REQUEST;
  return CredentialedSubresourceCheckResult::BLOCK_REQUEST;
}

NavigationRequest::LegacyProtocolInSubresourceCheckResult
NavigationRequest::CheckLegacyProtocolInSubresource() const {
  // It only applies to subframes.
  if (frame_tree_node_->IsMainFrame())
    return LegacyProtocolInSubresourceCheckResult::ALLOW_REQUEST;

  if (!ShouldTreatURLSchemeAsLegacy(common_params_->url))
    return LegacyProtocolInSubresourceCheckResult::ALLOW_REQUEST;

  FrameTreeNode* parent_ftn = frame_tree_node_->parent();
  DCHECK(parent_ftn);
  const GURL& parent_url = parent_ftn->current_url();
  if (ShouldTreatURLSchemeAsLegacy(parent_url))
    return LegacyProtocolInSubresourceCheckResult::ALLOW_REQUEST;

  // Warn the user about the request being blocked.
  RenderFrameHostImpl* parent = parent_ftn->current_frame_host();
  DCHECK(parent);
  const char* console_message =
      "Subresource requests using legacy protocols (like `ftp:`) are blocked. "
      "Please deliver web-accessible resources over modern protocols like "
      "HTTPS. See https://www.chromestatus.com/feature/5709390967472128 for "
      "details.";
  parent->AddMessageToConsole(blink::mojom::ConsoleMessageLevel::kWarning,
                              console_message);

  return LegacyProtocolInSubresourceCheckResult::BLOCK_REQUEST;
}

NavigationRequest::AboutSrcDocCheckResult NavigationRequest::CheckAboutSrcDoc()
    const {
  if (!common_params_->url.IsAboutSrcdoc())
    return AboutSrcDocCheckResult::ALLOW_REQUEST;

  // Loading about:srcdoc in the main frame can't have any reasonable meaning.
  // There might be a malicious website trying to exploit a bug from this. As a
  // defensive measure, do not proceed. They would have failed anyway later.
  if (frame_tree_node_->IsMainFrame())
    return AboutSrcDocCheckResult::BLOCK_REQUEST;

  // TODO(arthursonzogni): Disallow navigations to about:srcdoc initiated from a
  // different frame or from a different window.

  // TODO(arthursonzogni): Disallow browser initiated navigations to
  // about:srcdoc, except session history navigations.

  return AboutSrcDocCheckResult::ALLOW_REQUEST;
}

void NavigationRequest::UpdateCommitNavigationParamsHistory() {
  NavigationController* navigation_controller =
      frame_tree_node_->navigator()->GetController();
  commit_params_->current_history_list_offset =
      navigation_controller->GetCurrentEntryIndex();
  commit_params_->current_history_list_length =
      navigation_controller->GetEntryCount();
}

void NavigationRequest::RendererAbortedNavigationForTesting() {
  OnRendererAbortedNavigation();
}

void NavigationRequest::OnRendererAbortedNavigation() {
  if (IsWaitingToCommit()) {
    render_frame_host_->NavigationRequestCancelled(this);
  } else {
    frame_tree_node_->navigator()->CancelNavigation(frame_tree_node_);
  }

  // Do not add code after this, NavigationRequest has been destroyed.
}

void NavigationRequest::HandleInterfaceDisconnection(
    mojo::AssociatedRemote<mojom::NavigationClient>* navigation_client,
    base::OnceClosure error_handler) {
  navigation_client->set_disconnect_handler(std::move(error_handler));
}

void NavigationRequest::IgnoreInterfaceDisconnection() {
  return request_navigation_client_.set_disconnect_handler(base::DoNothing());
}

void NavigationRequest::IgnoreCommitInterfaceDisconnection() {
  return commit_navigation_client_.set_disconnect_handler(base::DoNothing());
}

bool NavigationRequest::IsSameDocument() {
  return NavigationTypeUtils::IsSameDocument(common_params_->navigation_type);
}

int NavigationRequest::EstimateHistoryOffset() {
  if (common_params_->should_replace_current_entry)
    return 0;

  NavigationController* controller =
      frame_tree_node_->navigator()->GetController();
  if (!controller)  // Interstitial page.
    return 1;

  int current_index = controller->GetLastCommittedEntryIndex();
  int pending_index = controller->GetPendingEntryIndex();

  // +1 for non history navigation.
  if (current_index == -1 || pending_index == -1)
    return 1;

  return pending_index - current_index;
}

void NavigationRequest::RecordDownloadUseCountersPrePolicyCheck(
    NavigationDownloadPolicy download_policy) {
  RenderFrameHost* rfh = frame_tree_node_->current_frame_host();
  GetContentClient()->browser()->LogWebFeatureForCurrentPage(
      rfh, blink::mojom::WebFeature::kDownloadPrePolicyCheck);

  // Log UseCounters for opener navigations.
  if (download_policy.IsType(NavigationDownloadType::kOpenerCrossOrigin)) {
    rfh->AddMessageToConsole(
        blink::mojom::ConsoleMessageLevel::kError,
        base::StringPrintf(
            "Navigating a cross-origin opener to a download (%s) is "
            "deprecated, see "
            "https://www.chromestatus.com/feature/5742188281462784.",
            common_params_->url.spec().c_str()));
    GetContentClient()->browser()->LogWebFeatureForCurrentPage(
        rfh, blink::mojom::WebFeature::kOpenerNavigationDownloadCrossOrigin);
  }

  // Log UseCounters for download in sandbox.
  if (download_policy.IsType(NavigationDownloadType::kSandbox)) {
    GetContentClient()->browser()->LogWebFeatureForCurrentPage(
        rfh, blink::mojom::WebFeature::kDownloadInSandbox);
  }

  // Log UseCounters for download without user activation.
  if (download_policy.IsType(NavigationDownloadType::kNoGesture)) {
    GetContentClient()->browser()->LogWebFeatureForCurrentPage(
        rfh, blink::mojom::WebFeature::kDownloadWithoutUserGesture);
  }

  // Log UseCounters for download in ad frame without user activation.
  if (download_policy.IsType(NavigationDownloadType::kAdFrameNoGesture)) {
    GetContentClient()->browser()->LogWebFeatureForCurrentPage(
        rfh, blink::mojom::WebFeature::kDownloadInAdFrameWithoutUserGesture);
  }

  // Log UseCounters for download in ad frame.
  if (download_policy.IsType(NavigationDownloadType::kAdFrame)) {
    GetContentClient()->browser()->LogWebFeatureForCurrentPage(
        rfh, blink::mojom::WebFeature::kDownloadInAdFrame);
  }
}

void NavigationRequest::RecordDownloadUseCountersPostPolicyCheck() {
  DCHECK(is_download_);
  RenderFrameHost* rfh = frame_tree_node_->current_frame_host();
  GetContentClient()->browser()->LogWebFeatureForCurrentPage(
      rfh, blink::mojom::WebFeature::kDownloadPostPolicyCheck);
}

void NavigationRequest::OnNavigationEventProcessed(
    NavigationThrottleRunner::Event event,
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK_NE(NavigationThrottle::DEFER, result.action());
  switch (event) {
    case NavigationThrottleRunner::Event::WillStartRequest:
      OnWillStartRequestProcessed(result);
      return;
    case NavigationThrottleRunner::Event::WillRedirectRequest:
      OnWillRedirectRequestProcessed(result);
      return;
    case NavigationThrottleRunner::Event::WillFailRequest:
      OnWillFailRequestProcessed(result);
      return;
    case NavigationThrottleRunner::Event::WillProcessResponse:
      OnWillProcessResponseProcessed(result);
      return;
    default:
      NOTREACHED();
  }
  NOTREACHED();
}

void NavigationRequest::OnWillStartRequestProcessed(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK_EQ(WILL_START_REQUEST, state_);
  DCHECK_NE(NavigationThrottle::BLOCK_RESPONSE, result.action());
  DCHECK(processing_navigation_throttle_);
  processing_navigation_throttle_ = false;
  if (result.action() != NavigationThrottle::PROCEED)
    state_ = CANCELING;

  if (complete_callback_for_testing_ &&
      std::move(complete_callback_for_testing_).Run(result)) {
    return;
  }
  OnStartChecksComplete(result);

  // DO NOT ADD CODE AFTER THIS, as the NavigationRequest might have been
  // deleted by the previous calls.
}

void NavigationRequest::OnWillRedirectRequestProcessed(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK_EQ(WILL_REDIRECT_REQUEST, state_);
  DCHECK_NE(NavigationThrottle::BLOCK_RESPONSE, result.action());
  DCHECK(processing_navigation_throttle_);
  processing_navigation_throttle_ = false;
  if (result.action() == NavigationThrottle::PROCEED) {
    // Notify the delegate that a redirect was encountered and will be followed.
    if (GetDelegate())
      GetDelegate()->DidRedirectNavigation(this);
  } else {
    state_ = CANCELING;
  }

  if (complete_callback_for_testing_ &&
      std::move(complete_callback_for_testing_).Run(result)) {
    return;
  }
  OnRedirectChecksComplete(result);

  // DO NOT ADD CODE AFTER THIS, as the NavigationRequest might have been
  // deleted by the previous calls.
}

void NavigationRequest::OnWillFailRequestProcessed(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK_EQ(WILL_FAIL_REQUEST, state_);
  DCHECK_NE(NavigationThrottle::BLOCK_RESPONSE, result.action());
  DCHECK(processing_navigation_throttle_);
  processing_navigation_throttle_ = false;
  if (result.action() == NavigationThrottle::PROCEED) {
    result = NavigationThrottle::ThrottleCheckResult(
        NavigationThrottle::PROCEED, net_error_);
  } else {
    state_ = CANCELING;
  }

  if (complete_callback_for_testing_ &&
      std::move(complete_callback_for_testing_).Run(result)) {
    return;
  }
  OnFailureChecksComplete(result);

  // DO NOT ADD CODE AFTER THIS, as the NavigationRequest might have been
  // deleted by the previous calls.
}

void NavigationRequest::OnWillProcessResponseProcessed(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK_EQ(WILL_PROCESS_RESPONSE, state_);
  DCHECK_NE(NavigationThrottle::BLOCK_REQUEST, result.action());
  DCHECK_NE(NavigationThrottle::BLOCK_REQUEST_AND_COLLAPSE, result.action());
  DCHECK(processing_navigation_throttle_);
  processing_navigation_throttle_ = false;
  if (result.action() == NavigationThrottle::PROCEED) {
    // If the navigation is done processing the response, then it's ready to
    // commit. Inform observers that the navigation is now ready to commit,
    // unless it is not set to commit (204/205s/downloads).
    if (render_frame_host_)
      ReadyToCommitNavigation(false);
  } else {
    state_ = CANCELING;
  }

  if (complete_callback_for_testing_ &&
      std::move(complete_callback_for_testing_).Run(result)) {
    return;
  }
  OnWillProcessResponseChecksComplete(result);

  // DO NOT ADD CODE AFTER THIS, as the NavigationRequest might have been
  // deleted by the previous calls.
}

NavigatorDelegate* NavigationRequest::GetDelegate() const {
  return frame_tree_node()->navigator()->GetDelegate();
}

void NavigationRequest::Resume(NavigationThrottle* resuming_throttle) {
  DCHECK(resuming_throttle);
  EnterChildTraceEvent("Resume", this);
  throttle_runner_->ResumeProcessingNavigationEvent(resuming_throttle);
  // DO NOT ADD CODE AFTER THIS, as the NavigationHandle might have been deleted
  // by the previous call.
}

void NavigationRequest::CancelDeferredNavigation(
    NavigationThrottle* cancelling_throttle,
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK(cancelling_throttle);
  DCHECK_EQ(cancelling_throttle, throttle_runner_->GetDeferringThrottle());
  CancelDeferredNavigationInternal(result);
}

void NavigationRequest::CallResumeForTesting() {
  throttle_runner_->CallResumeForTesting();
}

void NavigationRequest::RegisterThrottleForTesting(
    std::unique_ptr<NavigationThrottle> navigation_throttle) {
  throttle_runner_->AddThrottle(std::move(navigation_throttle));
}
bool NavigationRequest::IsDeferredForTesting() {
  return throttle_runner_->GetDeferringThrottle() != nullptr;
}

bool NavigationRequest::IsForMhtmlSubframe() const {
  return frame_tree_node_->parent() &&
         frame_tree_node_->frame_tree()
             ->root()
             ->current_frame_host()
             ->is_mhtml_document() &&
         // Unlike every other MHTML subframe URLs, data-url are loaded via the
         // URL, not from the MHTML archive. See https://crbug.com/969696.
         !common_params_->url.SchemeIs(url::kDataScheme);
}

void NavigationRequest::CancelDeferredNavigationInternal(
    NavigationThrottle::ThrottleCheckResult result) {
  DCHECK(processing_navigation_throttle_);
  DCHECK(result.action() == NavigationThrottle::CANCEL_AND_IGNORE ||
         result.action() == NavigationThrottle::CANCEL ||
         result.action() == NavigationThrottle::BLOCK_RESPONSE ||
         result.action() == NavigationThrottle::BLOCK_REQUEST_AND_COLLAPSE);
  DCHECK(result.action() != NavigationThrottle::BLOCK_REQUEST_AND_COLLAPSE ||
         state_ == WILL_START_REQUEST || state_ == WILL_REDIRECT_REQUEST);

  EnterChildTraceEvent("CancelDeferredNavigation", this);
  NavigationState old_state = state_;
  state_ = CANCELING;
  if (complete_callback_for_testing_ &&
      std::move(complete_callback_for_testing_).Run(result)) {
    return;
  }

  switch (old_state) {
    case WILL_START_REQUEST:
      OnStartChecksComplete(result);
      return;
    case WILL_REDIRECT_REQUEST:
      OnRedirectChecksComplete(result);
      return;
    case WILL_FAIL_REQUEST:
      OnFailureChecksComplete(result);
      return;
    case WILL_PROCESS_RESPONSE:
      OnWillProcessResponseChecksComplete(result);
      return;
    default:
      NOTREACHED();
  }
  // DO NOT ADD CODE AFTER THIS, as the NavigationRequest might have been
  // deleted by the previous calls.
}

void NavigationRequest::WillStartRequest() {
  EnterChildTraceEvent("WillStartRequest", this);
  DCHECK_EQ(state_, WILL_START_REQUEST);

  if (IsSelfReferentialURL()) {
    state_ = CANCELING;
    if (complete_callback_for_testing_ &&
        std::move(complete_callback_for_testing_)
            .Run(NavigationThrottle::CANCEL)) {
      return;
    }
    OnWillProcessResponseChecksComplete(NavigationThrottle::CANCEL);

    // DO NOT ADD CODE AFTER THIS, as the NavigationRequest might have been
    // deleted by the previous calls.
    return;
  }

  throttle_runner_->RegisterNavigationThrottles();

  // If the content/ embedder did not pass the NavigationUIData at the beginning
  // of the navigation, ask for it now.
  if (!navigation_ui_data_) {
    navigation_ui_data_ = GetDelegate()->GetNavigationUIData(this);
  }

  processing_navigation_throttle_ = true;

  // Notify each throttle of the request.
  throttle_runner_->ProcessNavigationEvent(
      NavigationThrottleRunner::Event::WillStartRequest);
  // DO NOT ADD CODE AFTER THIS, as the NavigationHandle might have been deleted
  // by the previous call.
}

void NavigationRequest::WillRedirectRequest(
    const GURL& new_referrer_url,
    RenderProcessHost* post_redirect_process) {
  EnterChildTraceEvent("WillRedirectRequest", this, "url",
                       common_params_->url.possibly_invalid_spec());
  UpdateStateFollowingRedirect(new_referrer_url);
  UpdateSiteURL(post_redirect_process);

  if (IsSelfReferentialURL()) {
    state_ = CANCELING;
    if (complete_callback_for_testing_ &&
        std::move(complete_callback_for_testing_)
            .Run(NavigationThrottle::CANCEL)) {
      return;
    }
    OnWillProcessResponseChecksComplete(NavigationThrottle::CANCEL);

    // DO NOT ADD CODE AFTER THIS, as the NavigationRequest might have been
    // deleted by the previous calls.
    return;
  }

  // Notify each throttle of the request.
  throttle_runner_->ProcessNavigationEvent(
      NavigationThrottleRunner::Event::WillRedirectRequest);
  // DO NOT ADD CODE AFTER THIS, as the NavigationHandle might have been deleted
  // by the previous call.
}

void NavigationRequest::WillFailRequest() {
  EnterChildTraceEvent("WillFailRequest", this);

  state_ = WILL_FAIL_REQUEST;
  processing_navigation_throttle_ = true;

  // Notify each throttle of the request.
  throttle_runner_->ProcessNavigationEvent(
      NavigationThrottleRunner::Event::WillFailRequest);
  // DO NOT ADD CODE AFTER THIS, as the NavigationHandle might have been deleted
  // by the previous call.
}

void NavigationRequest::WillProcessResponse() {
  EnterChildTraceEvent("WillProcessResponse", this);
  DCHECK_EQ(state_, WILL_PROCESS_RESPONSE);

  processing_navigation_throttle_ = true;

  // Notify each throttle of the response.
  throttle_runner_->ProcessNavigationEvent(
      NavigationThrottleRunner::Event::WillProcessResponse);
  // DO NOT ADD CODE AFTER THIS, as the NavigationHandle might have been deleted
  // by the previous call.
}

bool NavigationRequest::IsSelfReferentialURL() {
  // about: URLs should be exempted since they are reserved for other purposes
  // and cannot be the source of infinite recursion.
  // See https://crbug.com/341858 .
  if (common_params_->url.SchemeIs(url::kAboutScheme))
    return false;

  // Browser-triggered navigations should be exempted.
  if (browser_initiated())
    return false;

  // Some sites rely on constructing frame hierarchies where frames are loaded
  // via POSTs with the same URLs, so exempt POST requests.
  // See https://crbug.com/710008.
  if (common_params_->method == "POST")
    return false;

  // We allow one level of self-reference because some sites depend on that,
  // but we don't allow more than one.
  bool found_self_reference = false;
  for (const FrameTreeNode* node = frame_tree_node()->parent(); node;
       node = node->parent()) {
    if (node->current_url().EqualsIgnoringRef(common_params_->url)) {
      if (found_self_reference)
        return true;
      found_self_reference = true;
    }
  }
  return false;
}

void NavigationRequest::DidCommitNavigation(
    const FrameHostMsg_DidCommitProvisionalLoad_Params& params,
    bool navigation_entry_committed,
    bool did_replace_entry,
    const GURL& previous_url,
    NavigationType navigation_type) {
  common_params_->url = params.url;
  did_replace_entry_ = did_replace_entry;
  should_update_history_ = params.should_update_history;
  previous_url_ = previous_url;
  navigation_type_ = navigation_type;

  // If an error page reloads, net_error_code might be 200 but we still want to
  // count it as an error page.
  if (params.base_url.spec() == kUnreachableWebDataURL ||
      net_error_ != net::OK) {
    EnterChildTraceEvent("DidCommitNavigation: error page", this);
    state_ = DID_COMMIT_ERROR_PAGE;
  } else {
    EnterChildTraceEvent("DidCommitNavigation", this);
    state_ = DID_COMMIT;
  }

  StopCommitTimeout();

  // Switching BrowsingInstance because of COOP resets the name of the frame.
  // The renderer already knows locally about it because we sent an empty name
  // at frame creation time. The renderer has now committed the page and we can
  // safely enforce the empty name on the browser side.
  if (require_coop_browsing_instance_swap()) {
    std::string name, unique_name;
    // "COOP swaps" only affect main frames, that have an empty unique name.
    DCHECK(frame_tree_node_->unique_name().empty());
    frame_tree_node_->SetFrameName(name, unique_name);
  }

  // Record metrics for the time it took to commit the navigation if it was to
  // another document without error.
  if (!IsSameDocument() && state_ != DID_COMMIT_ERROR_PAGE) {
    ui::PageTransition transition = common_params_->transition;
    base::Optional<bool> is_background =
        render_frame_host_->GetProcess()->IsProcessBackgrounded();

    RecordStartToCommitMetrics(
        common_params_->navigation_start, transition, ready_to_commit_time_,
        is_background, is_same_process_, frame_tree_node_->IsMainFrame());
  }

  DCHECK(!frame_tree_node_->IsMainFrame() || navigation_entry_committed)
      << "Only subframe navigations can get here without changing the "
      << "NavigationEntry";
  subframe_entry_committed_ = navigation_entry_committed;

  // For successful navigations, ensure the frame owner element is no longer
  // collapsed as a result of a prior navigation.
  if (state_ != DID_COMMIT_ERROR_PAGE && !frame_tree_node()->IsMainFrame()) {
    // The last committed load in collapsed frames will be an error page with
    // |kUnreachableWebDataURL|. Same-document navigation should not be
    // possible.
    DCHECK(!IsSameDocument() || !frame_tree_node()->is_collapsed());
    frame_tree_node()->SetCollapsed(false);
  }
}

GURL NavigationRequest::GetSiteForCommonParamsURL() const {
  // TODO(alexmos): Using |starting_site_instance_|'s IsolationContext may not
  // be correct for cross-BrowsingInstance redirects.
  return SiteInstanceImpl::GetSiteForURL(
      starting_site_instance_->GetIsolationContext(), common_params_->url);
}

// TODO(zetamoo): Try to merge this function inside its callers.
void NavigationRequest::UpdateStateFollowingRedirect(
    const GURL& new_referrer_url) {
  // The navigation should not redirect to a "renderer debug" url. It should be
  // blocked in NavigationRequest::OnRequestRedirected or in
  // ResourceLoader::OnReceivedRedirect.
  // Note: the |common_params_->url| below is the post-redirect URL.
  // See https://crbug.com/728398.
  CHECK(!IsRendererDebugURL(common_params_->url));

  // Update the navigation parameters.
  if (!(common_params_->transition & ui::PAGE_TRANSITION_CLIENT_REDIRECT)) {
    sanitized_referrer_->url = new_referrer_url;
    sanitized_referrer_ =
        Referrer::SanitizeForRequest(common_params_->url, *sanitized_referrer_);
  }

  common_params_->referrer = sanitized_referrer_.Clone();

  was_redirected_ = true;
  redirect_chain_.push_back(common_params_->url);

  state_ = WILL_REDIRECT_REQUEST;
  processing_navigation_throttle_ = true;

#if defined(OS_ANDROID)
  navigation_handle_proxy_->DidRedirect();
#endif
}

void NavigationRequest::SetNavigationClient(
    mojo::PendingAssociatedRemote<mojom::NavigationClient> navigation_client) {
  DCHECK(from_begin_navigation_ ||
         common_params_->is_history_navigation_in_new_child_frame);
  DCHECK(!request_navigation_client_);
  if (!navigation_client.is_valid())
    return;

  request_navigation_client_.reset();
  request_navigation_client_.Bind(std::move(navigation_client));

  // Binds the OnAbort callback
  HandleInterfaceDisconnection(
      &request_navigation_client_,
      base::BindOnce(&NavigationRequest::OnRendererAbortedNavigation,
                     base::Unretained(this)));
}

bool NavigationRequest::NeedsUrlLoader() {
  return IsURLHandledByNetworkStack(common_params_->url) && !IsSameDocument() &&
         !IsForMhtmlSubframe();
}

void NavigationRequest::ReadyToCommitNavigation(bool is_error) {
  EnterChildTraceEvent("ReadyToCommitNavigation", this);

  state_ = READY_TO_COMMIT;
  ready_to_commit_time_ = base::TimeTicks::Now();
  RestartCommitTimeout();

  // https://wicg.github.io/cors-rfc1918/#address-space
  if (!IsSameDocument()) {
    network::mojom::IPAddressSpace ip_address_space = CalculateIPAddressSpace(
        GetSocketAddress().address(),
        response_head_ ? response_head_->headers.get() : nullptr);
    commit_params_->ip_address_space = ip_address_space;
    client_security_state_->ip_address_space = ip_address_space;
  }

  if (appcache_handle_) {
    DCHECK(appcache_handle_->host());
    appcache_handle_->host()->SetProcessId(
        render_frame_host_->GetProcess()->GetID());
  }

  // Record metrics for the time it takes to get to this state from the
  // beginning of the navigation.
  if (!IsSameDocument() && !is_error) {
    is_same_process_ =
        render_frame_host_->GetProcess()->GetID() ==
        frame_tree_node_->current_frame_host()->GetProcess()->GetID();

    RecordReadyToCommitMetrics(frame_tree_node_->current_frame_host(),
                               render_frame_host_, *common_params_.get(),
                               ready_to_commit_time_);
  }

  SetExpectedProcess(render_frame_host_->GetProcess());

  if (!IsSameDocument())
    GetDelegate()->ReadyToCommitNavigation(this);
}

std::unique_ptr<AppCacheNavigationHandle>
NavigationRequest::TakeAppCacheHandle() {
  return std::move(appcache_handle_);
}

bool NavigationRequest::IsWaitingToCommit() {
  return state_ == READY_TO_COMMIT;
}

void NavigationRequest::RenderProcessBlockedStateChanged(bool blocked) {
  if (blocked)
    StopCommitTimeout();
  else
    RestartCommitTimeout();
}

void NavigationRequest::StopCommitTimeout() {
  commit_timeout_timer_.Stop();
  render_process_blocked_state_changed_subscription_.reset();
  GetRenderFrameHost()->GetRenderWidgetHost()->RendererIsResponsive();
}

void NavigationRequest::RestartCommitTimeout() {
  commit_timeout_timer_.Stop();
  if (state_ >= DID_COMMIT)
    return;

  RenderProcessHost* renderer_host =
      GetRenderFrameHost()->GetRenderWidgetHost()->GetProcess();
  if (!render_process_blocked_state_changed_subscription_) {
    render_process_blocked_state_changed_subscription_ =
        renderer_host->RegisterBlockStateChangedCallback(base::BindRepeating(
            &NavigationRequest::RenderProcessBlockedStateChanged,
            base::Unretained(this)));
  }
  if (!renderer_host->IsBlocked()) {
    commit_timeout_timer_.Start(
        FROM_HERE, g_commit_timeout,
        base::BindRepeating(&NavigationRequest::OnCommitTimeout,
                            weak_factory_.GetWeakPtr()));
  }
}

void NavigationRequest::OnCommitTimeout() {
  DCHECK_EQ(READY_TO_COMMIT, state_);
  PingNetworkService(base::BindOnce(
      [](base::Time start_time) {
        UMA_HISTOGRAM_MEDIUM_TIMES(
            "Navigation.CommitTimeout.NetworkServicePingTime",
            base::Time::Now() - start_time);
      },
      base::Time::Now()));
  UMA_HISTOGRAM_ENUMERATION(
      "Navigation.CommitTimeout.NetworkServiceAvailability",
      GetNetworkServiceAvailability());
  base::TimeDelta last_crash_time = GetTimeSinceLastNetworkServiceCrash();
  if (!last_crash_time.is_zero()) {
    UMA_HISTOGRAM_LONG_TIMES(
        "Navigation.CommitTimeout.NetworkServiceLastCrashTime",
        last_crash_time);
  }
  UMA_HISTOGRAM_BOOLEAN("Navigation.CommitTimeout.IsRendererProcessReady",
                        GetRenderFrameHost()->GetProcess()->IsReady());
  UMA_HISTOGRAM_ENUMERATION("Navigation.CommitTimeout.Scheme",
                            GetScheme(common_params_->url));
  UMA_HISTOGRAM_BOOLEAN("Navigation.CommitTimeout.IsMainFrame",
                        frame_tree_node_->IsMainFrame());
  base::UmaHistogramSparse("Navigation.CommitTimeout.ErrorCode", -net_error_);
  render_process_blocked_state_changed_subscription_.reset();
  GetRenderFrameHost()->GetRenderWidgetHost()->RendererIsUnresponsive(
      base::BindRepeating(&NavigationRequest::RestartCommitTimeout,
                          weak_factory_.GetWeakPtr()));
}

// static
void NavigationRequest::SetCommitTimeoutForTesting(
    const base::TimeDelta& timeout) {
  if (timeout.is_zero())
    g_commit_timeout = kDefaultCommitTimeout;
  else
    g_commit_timeout = timeout;
}

void NavigationRequest::RemoveRequestHeader(const std::string& header_name) {
  DCHECK(state_ == WILL_REDIRECT_REQUEST);
  removed_request_headers_.push_back(header_name);
}

void NavigationRequest::SetRequestHeader(const std::string& header_name,
                                         const std::string& header_value) {
  DCHECK(state_ == WILL_START_REQUEST || state_ == WILL_REDIRECT_REQUEST);
  modified_request_headers_.SetHeader(header_name, header_value);
}

const net::HttpResponseHeaders* NavigationRequest::GetResponseHeaders() {
  if (response_headers_for_testing_)
    return response_headers_for_testing_.get();
  return response_head_.get() ? response_head_->headers.get() : nullptr;
}

std::unique_ptr<FrameHostMsg_DidCommitProvisionalLoad_Params>
NavigationRequest::MakeDidCommitProvisionalLoadParamsForBFCache() {
  // Use the DidCommitProvisionalLoad_Params last used to commit the frame
  // being restored as a starting point.
  std::unique_ptr<FrameHostMsg_DidCommitProvisionalLoad_Params> params =
      render_frame_host_->TakeLastCommitParams();

  // Params must have been set when the RFH being restored from the cache last
  // navigated.
  CHECK(params);

  DCHECK_EQ(params->http_status_code, net::HTTP_OK);
  DCHECK_EQ(params->url_is_unreachable, false);

  params->intended_as_new_entry = commit_params().intended_as_new_entry;
  params->should_replace_current_entry =
      common_params().should_replace_current_entry;
  DCHECK_EQ(params->post_id, -1);
  params->nav_entry_id = commit_params().nav_entry_id;
  params->navigation_token = commit_params().navigation_token;
  params->did_create_new_entry = false;
  DCHECK_EQ(params->origin, commit_params().origin_to_commit.value());
  DCHECK_EQ(params->url, common_params().url);
  params->should_update_history = true;
  params->gesture = common_params().has_user_gesture ? NavigationGestureUser
                                                     : NavigationGestureAuto;
  params->page_state = commit_params().page_state;
  DCHECK_EQ(params->method, common_params().method);
  params->item_sequence_number = frame_entry_item_sequence_number_;
  params->document_sequence_number = frame_entry_document_sequence_number_;
  params->transition = common_params().transition;
  params->history_list_was_cleared = false;
  params->request_id = GetGlobalRequestID().request_id;

  return params;
}

bool NavigationRequest::IsExternalProtocol() {
  return !GetContentClient()->browser()->IsHandledURL(common_params_->url);
}

bool NavigationRequest::IsSignedExchangeInnerResponse() {
  return response() && response()->is_signed_exchange_inner_response;
}

net::IPEndPoint NavigationRequest::GetSocketAddress() {
  DCHECK_GE(state_, WILL_PROCESS_RESPONSE);
  return response() ? response()->remote_endpoint : net::IPEndPoint();
}

bool NavigationRequest::HasCommitted() {
  return state_ == DID_COMMIT || state_ == DID_COMMIT_ERROR_PAGE;
}

bool NavigationRequest::IsErrorPage() {
  return state_ == DID_COMMIT_ERROR_PAGE;
}

net::HttpResponseInfo::ConnectionInfo NavigationRequest::GetConnectionInfo() {
  return response() ? response()->connection_info
                    : net::HttpResponseInfo::ConnectionInfo();
}

bool NavigationRequest::IsInMainFrame() {
  return frame_tree_node()->IsMainFrame();
}

RenderFrameHostImpl* NavigationRequest::GetParentFrame() {
  return IsInMainFrame() ? nullptr
                         : frame_tree_node()->parent()->current_frame_host();
}

bool NavigationRequest::IsParentMainFrame() {
  FrameTreeNode* parent = frame_tree_node()->parent();
  return parent && parent->IsMainFrame();
}

int NavigationRequest::GetFrameTreeNodeId() {
  return frame_tree_node()->frame_tree_node_id();
}

bool NavigationRequest::WasResponseCached() {
  return response() && response()->was_fetched_via_cache;
}

bool NavigationRequest::HasPrefetchedAlternativeSubresourceSignedExchange() {
  return !commit_params_->prefetched_signed_exchanges.empty();
}

int64_t NavigationRequest::GetNavigationId() {
  return navigation_handle_id_;
}

const GURL& NavigationRequest::GetURL() {
  return common_params().url;
}

SiteInstanceImpl* NavigationRequest::GetStartingSiteInstance() {
  return starting_site_instance_.get();
}

SiteInstanceImpl* NavigationRequest::GetSourceSiteInstance() {
  return source_site_instance_.get();
}

bool NavigationRequest::IsRendererInitiated() {
  return !browser_initiated_;
}

bool NavigationRequest::WasServerRedirect() {
  return was_redirected_;
}

const std::vector<GURL>& NavigationRequest::GetRedirectChain() {
  return redirect_chain_;
}

base::TimeTicks NavigationRequest::NavigationStart() {
  return common_params().navigation_start;
}

base::TimeTicks NavigationRequest::NavigationInputStart() {
  return common_params().input_start;
}

bool NavigationRequest::IsPost() {
  return common_params().method == "POST";
}

const blink::mojom::Referrer& NavigationRequest::GetReferrer() {
  return *sanitized_referrer_;
}

bool NavigationRequest::HasUserGesture() {
  return common_params().has_user_gesture;
}

ui::PageTransition NavigationRequest::GetPageTransition() {
  return common_params().transition;
}

NavigationUIData* NavigationRequest::GetNavigationUIData() {
  return navigation_ui_data_.get();
}

net::Error NavigationRequest::GetNetErrorCode() {
  return net_error_;
}

// The RenderFrameHost that will commit the navigation or an error page.
// This is computed when the response is received, or when the navigation
// fails and error page should be displayed.
RenderFrameHostImpl* NavigationRequest::GetRenderFrameHost() {
  // Only allow the RenderFrameHost to be retrieved once it has been set for
  // this navigation. This will happens either at WillProcessResponse time for
  // regular navigations or at WillFailRequest time for error pages.
  CHECK_GE(state_, WILL_PROCESS_RESPONSE)
      << "This accessor should only be called after a RenderFrameHost has "
         "been picked for this navigation.";
  static_assert(WILL_FAIL_REQUEST > WILL_PROCESS_RESPONSE,
                "WillFailRequest state should come after WillProcessResponse");
  return render_frame_host_;
}

const net::HttpRequestHeaders& NavigationRequest::GetRequestHeaders() {
  return request_headers_;
}

const base::Optional<net::SSLInfo>& NavigationRequest::GetSSLInfo() {
  return ssl_info_;
}

const base::Optional<net::AuthChallengeInfo>&
NavigationRequest::GetAuthChallengeInfo() {
  return auth_challenge_info_;
}

net::ResolveErrorInfo NavigationRequest::GetResolveErrorInfo() {
  return resolve_error_info_;
}

net::NetworkIsolationKey NavigationRequest::GetNetworkIsolationKey() {
  if (network_isolation_key_)
    return network_isolation_key_.value();

  // If this is a top-frame navigation, then use the origin of the url (and
  // update it as redirects happen). If this is a subframe navigation, get the
  // URL from the top frame.
  // TODO(crbug.com/979296): Consider changing this code to copy an origin
  // instead of creating one from a URL which lacks opacity information.
  url::Origin frame_origin = url::Origin::Create(common_params_->url);
  url::Origin top_frame_origin =
      frame_tree_node_->IsMainFrame()
          ? frame_origin
          : frame_tree_node_->frame_tree()->root()->current_origin();

  return net::NetworkIsolationKey(top_frame_origin, frame_origin);
}

bool NavigationRequest::HasSubframeNavigationEntryCommitted() {
  DCHECK(!frame_tree_node_->IsMainFrame());
  DCHECK(state_ == DID_COMMIT || state_ == DID_COMMIT_ERROR_PAGE);
  return subframe_entry_committed_;
}

bool NavigationRequest::DidReplaceEntry() {
  DCHECK(state_ == DID_COMMIT || state_ == DID_COMMIT_ERROR_PAGE);
  return did_replace_entry_;
}

bool NavigationRequest::ShouldUpdateHistory() {
  DCHECK(state_ == DID_COMMIT || state_ == DID_COMMIT_ERROR_PAGE);
  return should_update_history_;
}

const GURL& NavigationRequest::GetPreviousURL() {
  DCHECK(state_ == DID_COMMIT || state_ == DID_COMMIT_ERROR_PAGE);
  return previous_url_;
}

bool NavigationRequest::WasStartedFromContextMenu() {
  return common_params().started_from_context_menu;
}

const GURL& NavigationRequest::GetSearchableFormURL() {
  return begin_params()->searchable_form_url;
}

const std::string& NavigationRequest::GetSearchableFormEncoding() {
  return begin_params()->searchable_form_encoding;
}

ReloadType NavigationRequest::GetReloadType() {
  return reload_type_;
}

RestoreType NavigationRequest::GetRestoreType() {
  return restore_type_;
}

const GURL& NavigationRequest::GetBaseURLForDataURL() {
  return common_params().base_url_for_data_url;
}

const GlobalRequestID& NavigationRequest::GetGlobalRequestID() {
  DCHECK_GE(state_, WILL_PROCESS_RESPONSE);
  return request_id_;
}

bool NavigationRequest::IsDownload() {
  return is_download_;
}

bool NavigationRequest::IsFormSubmission() {
  return begin_params()->is_form_submission;
}

bool NavigationRequest::WasInitiatedByLinkClick() {
  return begin_params()->was_initiated_by_link_click;
}

const std::string& NavigationRequest::GetHrefTranslate() {
  return common_params().href_translate;
}

const base::Optional<url::Origin>& NavigationRequest::GetInitiatorOrigin() {
  return common_params().initiator_origin;
}

bool NavigationRequest::IsSameProcess() {
  return is_same_process_;
}

int NavigationRequest::GetNavigationEntryOffset() {
  return navigation_entry_offset_;
}

const net::ProxyServer& NavigationRequest::GetProxyServer() {
  return proxy_server_;
}

GlobalFrameRoutingId NavigationRequest::GetPreviousRenderFrameHostId() {
  return previous_render_frame_host_id_;
}

bool NavigationRequest::IsServedFromBackForwardCache() {
  return rfh_restored_from_back_forward_cache_ != nullptr;
}

// static
NavigationRequest* NavigationRequest::From(NavigationHandle* handle) {
  return static_cast<NavigationRequest*>(handle);
}

bool NavigationRequest::IsNavigationStarted() const {
  return navigation_handle_id_;
}

bool NavigationRequest::RequiresSourceSiteInstance() const {
  const bool is_data_or_about =
      common_params_->url.SchemeIs(url::kDataScheme) ||
      common_params_->url.IsAboutBlank();
  const bool has_valid_initiator =
      common_params_->initiator_origin &&
      common_params_->initiator_origin->GetTupleOrPrecursorTupleIfOpaque()
          .IsValid();
  return is_data_or_about && has_valid_initiator && !dest_site_instance_;
}

void NavigationRequest::SetSourceSiteInstanceToInitiatorIfNeeded() {
  if (source_site_instance_ || !RequiresSourceSiteInstance() ||
      !common_params_->initiator_origin.has_value()) {
    return;
  }

  const auto tuple =
      common_params_->initiator_origin->GetTupleOrPrecursorTupleIfOpaque();
  source_site_instance_ = static_cast<SiteInstanceImpl*>(
      frame_tree_node_->current_frame_host()
          ->GetSiteInstance()
          ->GetRelatedSiteInstance(tuple.GetURL())
          .get());
}

void NavigationRequest::RestartBackForwardCachedNavigation() {
  TRACE_EVENT0("navigation",
               "NavigationRequest::RestartBackForwardCachedNavigation");
  CHECK(IsServedFromBackForwardCache());
  restarting_back_forward_cached_navigation_ = true;
  base::PostTask(
      FROM_HERE, {BrowserThread::UI},
      base::BindOnce(&NavigationRequest::RestartBackForwardCachedNavigationImpl,
                     weak_factory_.GetWeakPtr()));
}

void NavigationRequest::RestartBackForwardCachedNavigationImpl() {
  TRACE_EVENT0("navigation",
               "NavigationRequest::RestartBackForwardCachedNavigationImpl");
  RenderFrameHostImpl* rfh = rfh_restored_from_back_forward_cache();
  CHECK(rfh);
  CHECK_EQ(rfh->frame_tree_node()->navigation_request(), this);

  NavigationControllerImpl* controller = static_cast<NavigationControllerImpl*>(
      rfh->frame_tree_node()->navigator()->GetController());
  int nav_index = controller->GetEntryIndexWithUniqueID(nav_entry_id());

  // If the NavigationEntry was deleted, do not do anything.
  if (nav_index == -1)
    return;

  controller->GoToIndex(nav_index);
}

void NavigationRequest::ForceEnableOriginTrials(
    const std::vector<std::string>& trials) {
  DCHECK(!HasCommitted());
  commit_params_->force_enabled_origin_trials = trials;
}

base::Optional<network::BlockedByResponseReason>
NavigationRequest::IsBlockedByCorp() {
  if (!base::FeatureList::IsEnabled(
          network::features::kCrossOriginEmbedderPolicy)) {
    return base::nullopt;
  }
  // https://mikewest.github.io/corpp/#integration-html
  auto* parent_frame = GetParentFrame();
  if (!parent_frame) {
    return base::nullopt;
  }
  const auto& url = common_params_->url;
  // Some special URLs not loaded using the network are inheriting the
  // Cross-Origin-Embedder-Policy header from their parent.
  if (url.SchemeIsBlob() || url.SchemeIs(url::kDataScheme)) {
    return base::nullopt;
  }
  return network::CrossOriginResourcePolicy::IsNavigationBlocked(
      url, redirect_chain_[0], parent_frame->GetLastCommittedOrigin(),
      *response_head_, parent_frame->GetLastCommittedOrigin(),
      parent_frame->cross_origin_embedder_policy(),
      parent_frame->coep_reporter());
}

std::unique_ptr<PeakGpuMemoryTracker>
NavigationRequest::TakePeakGpuMemoryTracker() {
  return std::move(loading_mem_tracker_);
}

}  // namespace content
