<?php

namespace Drupal\uwauth\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\PageCache\ResponsePolicy\KillSwitch;
use Drupal\Core\Routing\CurrentRouteMatch;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\user\Entity\User;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Routing\LocalRedirectResponse;
use Drupal\uwauth\Debug;
use Drupal\uwauth\Form\UwAuthSettingsForm;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Session\Attribute\AttributeBag;
use Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * UW Auth event subscriber.
 */
class UwAuthSubscriber implements EventSubscriberInterface {
  use StringTranslationTrait;

  /**
   * The current_user service.
   */
  protected AccountProxyInterface $currentUser;

  /**
   * A diagnostic display service.
   */
  protected Debug $debug;

  /**
   * The entity manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The page_cache_kill_switch service.
   */
  protected KillSwitch $killSwitch;

  /**
   * The logger.channel.uwauth service.
   */
  protected LoggerInterface $logger;

  /**
   * The request.
   */
  protected RequestStack $requestStack;

  /**
   * The current_route_match service.
   */
  protected CurrentRouteMatch $route;

  /**
   * The module settings.
   */
  protected ImmutableConfig $settings;

  /**
   * A hash of severity level by group sync method.
   */
  protected array $severity;

  /**
   * Constructs a UW Auth event subscriber.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_manager
   *   The entity manager service.
   * @param \Drupal\uwauth\Debug $debug
   *   A diagnostic display service.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config
   *   The config factory service.
   * @param \Drupal\Core\PageCache\ResponsePolicy\KillSwitch $killSwitch
   *   The page_cache_kill_switch service.
   * @param \Drupal\Core\Routing\CurrentRouteMatch $route
   *   The current_route_match service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The logger.channel.uwauth logger channel.
   * @param array $severity
   *   The severity levels to use for each role sync method.
   */
  public function __construct(
    RequestStack $requestStack,
    EntityTypeManagerInterface $entity_manager,
    Debug $debug,
    AccountProxyInterface $currentUser,
    ConfigFactoryInterface $config,
    KillSwitch $killSwitch,
    CurrentRouteMatch $route,
    LoggerInterface $logger,
    array $severity,
  ) {
    $this->currentUser = $currentUser;
    $this->debug = $debug;
    $this->entityTypeManager = $entity_manager;
    $this->killSwitch = $killSwitch;
    $this->logger = $logger;
    $this->requestStack = $requestStack;
    $this->route = $route;
    $this->settings = $config->get(UwAuthSettingsForm::SETTINGS_NAME);
    $this->severity = $severity;
  }

  /**
   * Create a user object from defaults, username and filtered attributes.
   *
   * @param string $username
   *   The user machine name.
   * @param \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface $attributes
   *   The filtered attributes to inject in the user creation.
   *
   * @return \Drupal\user\Entity\User
   *   The new or existing user account.
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   *
   * @see https://tools.ietf.org/html/rfc2606#section-2
   * @todo Add support for more attributes.
   */
  protected function createUser(string $username, AttributeBagInterface $attributes): User {
    $mail = $attributes->get('mail') ?: $username . '@uw.edu';
    $domain = mb_substr(strrchr($mail, "@"), 1);
    $validDomains = $this->settings->get('mail.valid_domains');
    // Ensure an invalid, non-reservable domain, to ensure mails are not being
    // sent to an unknown server; as per RFC 2606 section 2.
    if (!\in_array($domain, $validDomains)) {
      $mail = "$username@uwauth.invalid";
    }
    $account = User::create([
      'init' => $mail,
      'mail' => $mail,
      'name' => $username,
      'status' => 1,
    ]);
    $account->setPassword(mb_substr(password_hash(openssl_random_pseudo_bytes(8), PASSWORD_DEFAULT), random_int(4, 16), 32));
    $account->save();
    return $account;
  }

  /**
   * Fetch group membership from Active Directory.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   A user object.
   *
   * @return array
   *   An array of group names.
   */
  private function fetchAdGroups(AccountInterface $account): array {
    $username = $account->getAccountName();

    // Search Filter.
    $search_filter = "(sAMAccountName=" . $username . ")";

    // Query Active Directory for user, and fetch group membership.
    $ad_conn = ldap_connect($this->settings->get('ad.uri'));
    if (($this->settings->get('ad.binddn') !== NULL) && ($this->settings->get('ad.bindpass') !== NULL)) {
      ldap_bind($ad_conn, $this->settings->get('ad.binddn'), $this->settings->get('ad.bindpass'));
    }
    $ad_search = ldap_search($ad_conn, $this->settings->get('ad.basedn'), $search_filter, ['memberOf']);
    $ad_search_results = ldap_get_entries($ad_conn, $ad_search);

    // Extract group names from DNs.
    $ad_groups = [];
    foreach ($ad_search_results[0]['memberof'] as $entry) {
      if (preg_match("/^CN=([a-zA-Z0-9_\- ]+)/", $entry, $matches)) {
        $ad_groups[] = (string) $matches[1];
      }
    }
    $this->logger->log($this->severity['ad_sync'], 'Fetched groups from AD for {name}: got {groups}.', [
      'name' => $account->getDisplayName(),
      'groups' => implode(', ', $ad_groups),
    ]);

    return $ad_groups;
  }

  /**
   * Fetch group membership from UW Groups.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   A user object.
   *
   * @return array
   *   An array of group names.
   */
  private function fetchGwsGroups(AccountInterface $account): array {

    $username = $account->getAccountName();

    // UW GWS URL.
    $uwgws_url = 'https://iam-ws.u.washington.edu/group_sws/v1/search?member=' . $username . '&type=effective&scope=all';

    // Query UW GWS for group membership.
    $uwgws = curl_init();
    curl_setopt_array($uwgws, [
      CURLOPT_RETURNTRANSFER => TRUE,
      CURLOPT_FOLLOWLOCATION => TRUE,
      CURLOPT_SSLCERT        => $this->settings->get('gws.cert'),
      CURLOPT_SSLKEY         => $this->settings->get('gws.key'),
      CURLOPT_CAINFO         => $this->settings->get('gws.cacert'),
      CURLOPT_URL            => $uwgws_url,
    ]);
    $uwgws_response = curl_exec($uwgws);
    curl_close($uwgws);

    // Extract groups from response.
    $uwgws_feed = simplexml_load_string(str_replace('xmlns=', 'ns=', $uwgws_response));
    $uwgws_entries = $uwgws_feed->xpath("//a[@class='name']");
    $uwgws_groups = [];
    foreach ($uwgws_entries as $uwgws_entry) {
      $uwgws_groups[] = (string) $uwgws_entry[0];
    }

    $this->logger->log($this->severity['ad_sync'], 'Fetched groups from GWS for {name}: got {groups}.', [
      'name' => $account->getDisplayName(),
      'groups' => implode(', ', $uwgws_groups),
    ]);

    return $uwgws_groups;
  }

  /**
   * Extract possibly usable attributes (and NameID) from the request.
   *
   * @return \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBag
   *   The "attributes".
   */
  protected function getFilteredAttributes(): AttributeBag {
    // Check for a UW NetID from Shibboleth.
    $attributes = new AttributeBag();
    $allowedAttributes = array_flip($this->settings->get('auth.allowed_attributes'));
    $attributeCandidates = $this->requestStack->getCurrentRequest()->server->all();
    foreach ($attributeCandidates as $k => $v) {
      $matches = [];
      if (preg_match('/^(REDIRECT_)?Shib-([-\w]+)/', $k, $matches)) {
        $this->debug->message($this->t('Shibboleth @name = @value.', [
          '@name' => $matches[2],
          '@value' => json_encode($v),
        ]));
      }
      elseif (preg_match('/^(REDIRECT_)?([\w]+)$/', $k, $matches)) {
        $name = $matches[2];
        if (isset($allowedAttributes[$name])) {
          $this->debug->message($this->t('Attribute @name = @value.', [
            '@name' => $name,
            '@value' => json_encode($v),
          ]));
          $attributes->set($name, $v);
        }
      }
    }

    return $attributes;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    $events[KernelEvents::REQUEST][] = ['handle', 29];
    return $events;
  }

  /**
   * Get an account User entity by username.
   *
   * @param string $username
   *   The username for which to load a User entity.
   *
   * @return \Drupal\user\Entity\User|false
   *   The loaded User entity, or FALSE if none matched the user name.
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   */
  protected function getUserByName(string $username): User|false {
    $accounts = $this->entityTypeManager
      ->getStorage('user')
      ->loadByProperties(['name' => $username]);
    return reset($accounts);
  }


  public function handle(RequestEvent $event): void {
    $this->debug->message($this->t('User id: @id', ['@id' => $this->currentUser->id()]));
    if ($this->isLoggedIn()
      || $this->isRouteExcluded()
      || !$this->needsLogin()
      || !$this->hasShibbolethSession()) {
      return;
    }

    $attributes = $this->getFilteredAttributes();
    $username = $attributes->get($this->settings->get('auth.name_id'));
    if (!isset($username)) {
      return;
    }

    $this->loginUser($username, $attributes);
    $event->setResponse($this->redirectUser());
  }

  /**
   * Check whether the current request describes a Shibboleth session.
   */
  protected function hasShibbolethSession(): bool {
    // Verify we're actually in a Shibboleth session.
    $server = $this->requestStack
      ->getCurrentRequest()
      ->server;
    $shib_session_id = $server->get('Shib-Session-ID');
    if (!isset($shib_session_id)) {
      $shib_session_id = $server->get('REDIRECT_Shib-Session-ID');
    }

    if (!isset($shib_session_id)) {
      $this->debug->message($this->t('Not in a Shibboleth session.'));
      return FALSE;
    }
    $this->debug->message($this->t("In Shibboleth session @id.", ['@id' => $shib_session_id]));
    return TRUE;
  }

  /**
   * Is the current user logged-in on Drupal ?
   */
  protected function isLoggedIn(): bool {
    if ($this->currentUser->isAuthenticated()) {
      $this->debug->message($this->t('Already authenticated'));
      return TRUE;
    }
    $this->debug->message($this->t('Not authenticated'));
    return FALSE;
  }

  /**
   * Is the current route excluded from using SSO ?
   */
  protected function isRouteExcluded(): bool {
    $routeName = $this->route->getCurrentRouteMatch()->getRouteName();
    $excludedRoutes = $this->settings->get('auth.excluded_routes');
    return \in_array($routeName, $excludedRoutes);
  }

  /**
   * Authenticate user, and log them in.
   *
   * @param string $username
   *   The Shibboleth NameID, to use for the Drupal username.
   * @param \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface $attributes
   *   The filtered attributes passed by the SP.
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   * @throws \Drupal\Core\Entity\EntityStorageException
   */
  private function loginUser(string $username, AttributeBagInterface $attributes): void {
    $account = $this->getUserByName($username);
    if (!$account) {
      $account = $this->createUser($username, $attributes);
    }

    // Set cookie_lifetime to on browser close.
    if (\is_null(ini_get('session.cookie_lifetime'))) {
      ini_set('session.cookie_lifetime', 0);
    }

    $this->syncRoles($account);

    // The user object may have been modified by syncRoles.
    $account = $this->getUserByName($username);

    user_login_finalize($account);
  }

  /**
   * Map UW Groups or AD group membership to roles.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   A user object.
   *
   * @return array
   *   An array of role names.
   */
  private function mapGroupsRoles(AccountInterface $account): array {
    $group_membership = match ($this->settings->get('group.source')) {
      UwAuthSettingsForm::SYNC_GROUPS => $this->fetchGwsGroups($account),
      UwAuthSettingsForm::SYNC_AD => $this->fetchAdGroups($account),
      UwAuthSettingsForm::SYNC_LOCAL => $account->getRoles(),
      default => [],
    };

    // Group to Role maps are stored as a multi-line string, containing pipe-
    // delimited key-value pairs.
    $group_role_map = [];
    foreach (preg_split("/((\r?\n)|(\r\n?))/", $this->settings->get('group.map')) as $entry) {
      $pair = explode('|', $entry);
      $group_role_map[(string) $pair[0]] = (string) $pair[1];
    }

    // Loop through group list, and extract matching roles.
    $mapped_roles = [];
    foreach ($group_membership as $group) {
      if (\array_key_exists($group, $group_role_map)) {
        $mapped_roles[] = (string) $group_role_map[$group];
      }
    }

    return $mapped_roles;
  }

  /**
   * Does the user need to be logged in using the Shibboleth session ?
   *
   * Only handle requests
   * - if
   *   - a group source is configured,
   *   - or if login without groups is chosen,
   * - and the current route is not excluded from SSO.
   *
   * @return bool
   *   Needed ?
   */
  protected function needsLogin(): bool {
    $group_source = $this->settings->get('group.source');
    $this->debug->message($this->t("Group source '@source'.", ['@source' => $group_source]));
    return $group_source !== UwAuthSettingsForm::SYNC_NONE;
  }

  /**
   * Redirect user back to the requested page.
   */
  private function redirectUser(): RedirectResponse {
    // Disable Page Cache to prevent redirect response from being cached.
    $this->killSwitch->trigger();
    $current_uri = $this->requestStack->getCurrentRequest()->getRequestUri();
    return LocalRedirectResponse::create($current_uri);
  }

  /**
   * Synchronize roles with UW Groups or Active Directory.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   A user object.
   */
  private function syncRoles(AccountInterface $account): void {
    // Local groups do not need to be resynchronized.
    if ($this->settings->get('group.source') == UwAuthSettingsForm::SYNC_LOCAL) {
      $this->logger->log($this->severity['local_sync'], 'Used local roles for {name}: no sync.', [
        'name' => $account->getDisplayName(),
      ]);
      return;
    }

    $roles_existing = user_roles(TRUE);
    $roles_assigned = $account->getRoles(TRUE);
    $mapped_roles = $this->mapGroupsRoles($account);

    // Remove from roles they are no longer assigned to.
    foreach ($roles_assigned as $role_assigned) {
      if (!\in_array($role_assigned, $mapped_roles)) {
        $account->removeRole($role_assigned);
      }
    }

    // Add to newly assigned roles.
    foreach ($mapped_roles as $mapped) {
      if (\array_key_exists($mapped, $roles_existing)) {
        $account->addRole($mapped);
      }
    }

    $account->save();
  }

}
