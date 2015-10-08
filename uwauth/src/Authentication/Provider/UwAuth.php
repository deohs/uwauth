<?php

/**
 * @file
 * Contains \Drupal\uwauth\Authentication\Provider\UwAuth.
 */

namespace Drupal\uwauth\Authentication\Provider;

use Drupal\Component\Utility\String;
use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Session\SessionConfigurationInterface;
use Symfony\Component\HttpFoundation\Request;
use Drupal\user\Entity\User;

/**
 * Shibboleth and UW Groups authentication provider.
 */
class UwAuth implements AuthenticationProviderInterface {

  /**
   * The entity manager.
   *
   * @var \Drupal\Core\Entity\EntityManagerInterface
   */
  protected $entityManager;

  /**
   * The session configuration.
   *
   * @var \Drupal\Core\Session\SessionConfigurationInterface
   */
  protected $sessionConfiguration;

  /**
   * Constructs a UW authentication provider object.
   *
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   *   The entity manager service.
   * @param \Drupal\Core\Session\SessionConfigurationInterface $session_configuration
   *   The session configuration.
   */
  public function __construct(EntityManagerInterface $entity_manager, SessionConfigurationInterface $session_configuration) {
    $this->entityManager = $entity_manager;
    $this->sessionConfiguration = $session_configuration;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    $username = $request->server->get('REMOTE_USER');
    $shib_session_id = $request->server->get('Shib-Session-ID');
    $group_source = \Drupal::config('uwauth.settings')->get('group.source');
    // We only handle requests with Shibboleth supplied usernames, that don't have Drupal sessions
    if (!$this->sessionConfiguration->hasSession($request) && isset($username) && isset($shib_session_id) && !($group_source === 'none')) {
      return TRUE;
    } else {
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $username = $request->server->get('REMOTE_USER');
    $account = reset($this->entityManager->getStorage('user')->loadByProperties(array('name' => $username)));

    // Create account if necessary, and log them in
    // After logon, force a refresh. This will let Drupal's cookie provider take over authentication.
    if ($account) {
      $this->sync_roles($account);
      user_login_finalize($account);
      header("Refresh: 0");
      return $account;
    } else {
      $user = User::create(array(
        'name' => $username,
        'mail' => $username.'@uw.edu',
        'status' => 1
      ));
      $user->save();
      $account = reset($this->entityManager->getStorage('user')->loadByProperties(array('name' => $username)));
      $this->sync_roles($account);
      user_login_finalize($account);
      header("Refresh: 0");
      return $account;
    }
    return [];
  }

  /**
   * Synchronize roles with UW Groups or Active Directory
   *
   * @param $account
   *   A user object.
   */
  private function sync_roles($account) {
    $roles_existing = user_role_names(TRUE);
    $roles_assigned = $account->getRoles(TRUE);
    $mapped_roles = $this->map_groups_roles($account);

    // Remove from roles they are no longer assigned to
    foreach($roles_assigned as $rid_assigned => $role_assigned) {
      if (!in_array($role_assigned, $mapped_roles)) {
        $account->removeRole($role_assigned);
      }
    }

    // Add to newly assigned roles
    foreach ($mapped_roles as $mapped) {
      if (in_array($mapped, $roles_existing)) {
        $account->addRole($mapped);
      }
    }

    $account->save();    
  }

  /**
   * Map UW Groups or AD group membership to roles
   *
   * @param $account
   *   A user object.
   */
  private function map_groups_roles($account) {
    switch (\Drupal::config('uwauth.settings')->get('group.source')) {
      case "gws":
        $group_membership = $this->fetch_gws_groups($account);
        break;
      case "ad":
        $group_membership = $this->fetch_ad_groups($account);
        break;
    }

    $group_role_map = array();

    foreach (preg_split("/((\r?\n)|(\r\n?))/", \Drupal::config('uwauth.settings')->get('group.map')) as $entry) {
      $pair = explode('|', $entry);
      $group_role_map[(string)$pair[0]] = (string)$pair[1];
    }

    // Loop through group list, and extract matching roles
    $mapped_roles = array();
    foreach ($group_membership as $group) {
      if (array_key_exists($group, $group_role_map)) {
        $mapped_roles[] = (string)$group_role_map[$group];
      }
    }

    return $mapped_roles;
  }

  /**
   * Fetch group membership from UW Groups
   *
   * @param $account
   *   A user object.
   */
  private function fetch_gws_groups($account) {
    $username = $account->getUsername();

    $uwauth_config = \Drupal::config('uwauth.settings');

    // UW GWS URL
    $uwgws_url = 'https://iam-ws.u.washington.edu/group_sws/v1/search?member=' . $username . '&type=effective&scope=all';

    // Query UW GWS for group membership
    $uwgws = curl_init();
    curl_setopt_array($uwgws, array(
                                CURLOPT_RETURNTRANSFER => TRUE,
                                CURLOPT_FOLLOWLOCATION => TRUE,
                                CURLOPT_SSLCERT        => $uwauth_config->get('gws.cert'),
                                CURLOPT_SSLKEY         => $uwauth_config->get('gws.key'),
                                CURLOPT_CAINFO         => $uwauth_config->get('gws.cacert'),
                                CURLOPT_URL            => $uwgws_url,
                                ));
    $uwgws_response = curl_exec($uwgws);
    curl_close($uwgws);

    // Extract groups from response 
    $uwgws_feed = simplexml_load_string(str_replace('xmlns=', 'ns=', $uwgws_response));
    $uwgws_entries = $uwgws_feed->xpath("//a[@class='name']");
    $uwgws_groups = array();
    foreach($uwgws_entries as $uwgws_entry) {
      $uwgws_groups[] = (string)$uwgws_entry[0];
    }

    return $uwgws_groups;
  }

  /**
   * Fetch group membership from Active Directory
   *
   * @param $account
   *   A user object.
   */
  private function fetch_ad_groups($account) {
    $username = $account->getUsername();

    $uwauth_config = \Drupal::config('uwauth.settings');

    // Search Filter
    $search_filter = "(sAMAccountName=" . $username . ")";

    // Query Active Directory for user, and fetch group membership
    $ad_conn = ldap_connect($uwauth_config->get('ad.uri'));
    $ad_search = ldap_search($ad_conn, $uwauth_config->get('ad.basedn'), $search_filter, array('memberOf'));
    $ad_search_results = ldap_get_entries($ad_conn, $ad_search);

    // Extract group names from DNs
    $ad_groups = array();
    foreach($ad_search_results[0]['memberof'] as $entry) {
      if(preg_match("/^CN=([a-zA-Z0-9_\- ]+)/", $entry, $matches)) {
      $ad_groups[] = (string)$matches[1];
      }
    }

    return $ad_groups;
  }
}
