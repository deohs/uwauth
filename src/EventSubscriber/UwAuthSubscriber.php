<?php

namespace Drupal\uwauth\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\PageCache\ResponsePolicy\KillSwitch;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\user\Entity\User;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Routing\LocalRedirectResponse;
use Drupal\user\UserInterface;
use Drupal\uwauth\Debug;
use Drupal\uwauth\Form\UwAuthSettingsForm;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Session\Attribute\AttributeBag;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

/**
 * UW Auth event subscriber.
 */
class UwAuthSubscriber implements EventSubscriberInterface {
  use StringTranslationTrait;

  /**
   * The current_user service.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * A diagnostic display service.
   *
   * @var \Drupal\uwauth\Debug
   */
  protected $debug;

  /**
   * The entity manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * The page_cache_kill_switch service.
   *
   * @var \Drupal\Core\PageCache\ResponsePolicy\KillSwitch
   */
  protected $killSwitch;

  /**
   * The request.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * The module settings.
   *
   * @var array|mixed|null
   */
  protected $settings;

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
   *   The config.factory service.
   * @param \Drupal\Core\PageCache\ResponsePolicy\KillSwitch $killSwitch
   *   The page_cache_kill_switch service.
   */
  public function __construct(
    RequestStack $requestStack,
    EntityTypeManagerInterface $entity_manager,
    Debug $debug,
    AccountProxyInterface $currentUser,
    ConfigFactoryInterface $config,
    KillSwitch $killSwitch) {
    $this->debug = $debug;
    $this->entityTypeManager = $entity_manager;
    $this->requestStack = $requestStack;
    $this->currentUser = $currentUser;
    $this->settings = $config->get(UwAuthSettingsForm::SETTINGS_NAME);
    $this->killSwitch = $killSwitch;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[KernelEvents::REQUEST][] = array('handle', 29);
    return $events;
  }

  /**
   * {@inheritdoc}
   */
  public function handle(GetResponseEvent $event) {
    $this->debug->message($this->t('User id: @id', ['@id' => $this->currentUser->id()]));
    if ($this->currentUser->isAuthenticated()) {
      $this->debug->message($this->t('Already authenticated'));
      return;
    }
    $this->debug->message($this->t('Not authenticated'));

    // Only handle requests if a group source is configured.
    $group_source = $this->settings->get('group.source');
    if ($group_source === "none") {
      $this->debug->message("Group source: 'none'.");
      return;
    }
    $this->debug->message($this->t("Group source '@source'.", ['@source' => $group_source]));

    // Verify we're actually in a Shibboleth session.
    $shib_session_id = $this->requestStack
      ->getCurrentRequest()
      ->server
      ->get('REDIRECT_Shib-Session-ID');

    if (!isset($shib_session_id)) {
      $this->debug->message($this->t('Not in a Shibboleth session.'));
      return;
    }
    $this->debug->message($this->t("In Shibboleth session @id.", ['@id' => $shib_session_id]));

    // Check for a UW NetID from Shibboleth.
    $attributes = new AttributeBag();
    $allowedAttributes = array_flip([
      'cn',
      'sn',
      'givenName',
      'employeeType',
      'uid',
    ]);
    $attributeCandidates = $this->requestStack->getCurrentRequest()->server->all();
    foreach ($attributeCandidates as $k => $v) {
      $matches = [];
      if (preg_match('/^(REDIRECT_)?Shib-([-\w]+)/', $k, $matches)) {
        $this->debug->message($this->t('Shibboleth @name = @value.', [
          '@name' => $matches[2],
          '@value' => json_encode($v),
        ]));
      }
      elseif (preg_match('/^REDIRECT_([\w]+)$/', $k, $matches)) {
        $name = $matches[1];
        if (isset($allowedAttributes[$name])) {
          $this->debug->message($this->t('Attribute @name = @value.', [
            '@name' => $name,
            '@value' => json_encode($v),
          ]));
          $attributes->set($name, $v);
        }
      }
    }
    $username = $attributes->get('uid');

    if (!isset($username)) {
      return;
    }

    $this->loginUser();
    $event->setResponse($this->redirectUser());
  }

  /**
   * Authenticate user, and log them in.
   */
  private function loginUser() {
    $username = $this->requestStack->getCurrentRequest()->server->get('REDIRECT_uid');
    $accounts = $this->entityTypeManager->getStorage('user')->loadByProperties(['name' => $username]);
    $account = reset($accounts);

    // Create account if necessary.
    if (!$account) {
      $user = User::create([
        'name' => $username,
        'mail' => $username . '@uw.edu',
        'status' => 1,
      ]);
      $user->setPassword(substr(password_hash(openssl_random_pseudo_bytes(8), PASSWORD_DEFAULT), rand(4, 16), 32));
      $user->save();
    }

    // Set cookie_lifetime to on browser close.
    ini_set('session.cookie_lifetime', 0);

    // Sync roles, and reload the modified user object.
    $this->syncRoles($account);
    $accounts = $this->entityTypeManager->getStorage('user')->loadByProperties(['name' => $username]);
    $account = reset($accounts);
    user_login_finalize($account);

    return TRUE;
  }

  /**
   * Redirect user back to the requested page.
   */
  private function redirectUser() {
    // Disable Page Cache to prevent redirect response from being cached.
    $this->killSwitch->trigger();
    $current_uri = $this->requestStack->getCurrentRequest()->getRequestUri();
    $redirect = LocalRedirectResponse::create($current_uri);
    return $redirect;
  }

  /**
   * Synchronize roles with UW Groups or Active Directory.
   *
   * @param \Drupal\user\UserInterface $account
   *   A user object.
   */
  private function syncRoles(UserInterface $account) {
    $roles_existing = user_roles(TRUE);
    $roles_assigned = $account->getRoles(TRUE);
    $mapped_roles = $this->mapGroupsRoles($account);

    // Remove from roles they are no longer assigned to.
    foreach ($roles_assigned as $role_assigned) {
      if (!in_array($role_assigned, $mapped_roles)) {
        $account->removeRole($role_assigned);
      }
    }

    // Add to newly assigned roles.
    foreach ($mapped_roles as $mapped) {
      if (array_key_exists($mapped, $roles_existing)) {
        $account->addRole($mapped);
      }
    }

    $account->save();
  }

  /**
   * Map UW Groups or AD group membership to roles.
   *
   * @param \Drupal\user\UserInterface $account
   *   A user object.
   *
   * @return array<string>
   *   An array of role names.
   */
  private function mapGroupsRoles(UserInterface $account) {
    switch ($this->settings->get('group.source')) {
      case 'gws':
        $group_membership = $this->fetchGwsGroups($account);
        break;

      case 'ad':
        $group_membership = $this->fetchAdGroups($account);
        break;
    }

    // Group to Role maps are stored as a multi-line string, containing pipe-
    // delimited key-value pairs.
    $group_role_map = array();
    foreach (preg_split("/((\r?\n)|(\r\n?))/", $this->settings->get('group.map')) as $entry) {
      $pair = explode('|', $entry);
      $group_role_map[(string) $pair[0]] = (string) $pair[1];
    }

    // Loop through group list, and extract matching roles.
    $mapped_roles = array();
    foreach ($group_membership as $group) {
      if (array_key_exists($group, $group_role_map)) {
        $mapped_roles[] = (string) $group_role_map[$group];
      }
    }

    return $mapped_roles;
  }

  /**
   * Fetch group membership from UW Groups.
   *
   * @param \Drupal\user\UserInterface $account
   *   A user object.
   *
   * @return array<string>
   *   An array of group names.
   */
  private function fetchGwsGroups(UserInterface $account) {

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
    $uwgws_groups = array();
    foreach ($uwgws_entries as $uwgws_entry) {
      $uwgws_groups[] = (string) $uwgws_entry[0];
    }

    return $uwgws_groups;
  }

  /**
   * Fetch group membership from Active Directory.
   *
   * @param \Drupal\user\UserInterface $account
   *   A user object.
   *
   * @return array
   *   An array of group names.
   */
  private function fetchAdGroups(UserInterface $account) {
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

    return $ad_groups;
  }

}
