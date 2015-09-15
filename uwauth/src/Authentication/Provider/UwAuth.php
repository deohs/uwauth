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
    // We only handle requests with Shibboleth supplied usernames, that don't have Drupal sessions
    if (!$this->sessionConfiguration->hasSession($request) && isset($username) && isset($shib_session_id)) {
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
   * Synchronize roles with UW Groups
   *
   * @param $account
   *   A user object.
   */
  private function sync_roles($account) {
    $roles_existing = user_role_names(TRUE);
    $roles_assigned = $account->getRoles(TRUE);
    $uwgws_groups = $this->fetch_uwgroups($account);

    // Remove from roles they are no longer assigned to
    foreach($roles_assigned as $rid_assigned => $role_assigned) {
      if (!in_array($role_assigned, $uwgws_groups)) {
        $account->removeRole($role_assigned);
      }
    }

    // Add to newly assigned roles
    foreach ($uwgws_groups as $uwgroup) {
      if (in_array($uwgroup, $roles_existing)) {
        $account->addRole($uwgroup);
      }
    }

    $account->save();    
  }

  /**
   * Fetch group membership from UW Groups
   *
   * @param $account
   *   A user object.
   */
  private function fetch_uwgroups($account) {
    $username = $account->getUsername();

    // UW CA cert base path
    $uwca_path = '/etc/ssl/drupal_uwca';

    // UW GWS URL
    $uwgws_url = 'https://iam-ws.u.washington.edu/group_sws/v1/search?member=' . $username . '&type=effective&scope=all';

    // Query UW GWS for group membership
    $uwgws = curl_init();
    curl_setopt_array($uwgws, array(
                                CURLOPT_RETURNTRANSFER => TRUE,
                                CURLOPT_FOLLOWLOCATION => TRUE,
                                CURLOPT_SSLCERT        => $uwca_path.'_cert.pem',
                                CURLOPT_SSLKEY         => $uwca_path.'_key.pem',
                                CURLOPT_CAINFO         => $uwca_path.'_ca.pem',
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
  private function fetch_adgroups($account) {
    $username = $account->getUsername();

    // LDAP Server URI
    $ldap_uri = "ldap://services.deohs.washington.edu";

    // Base DN
    $base_dn = "DC=deohs,DC=washington,DC=edu";

    // Search Filter
    $search_filter = "(sAMAccountName=" . $username . ")";

    // Query Active Directory for user, and fetch group membership
    $ad_conn = ldap_connect($ldap_uri);
    $ad_search = ldap_search($ad_conn, $base_dn, $search_filter, array("memberOf"));
    $ad_search_results = ldap_get_entries($ad_conn, $ad_search);

    // Extract group names from DNs
    $ad_groups = array();
    foreach($ad_search_results[0]["memberof"] as $entry) {
      if(preg_match("/^CN=([a-zA-Z0-9_\- ]+)/", $entry, $matches)) {
      $ad_groups[] = (string)$matches[1];
      }
    }

    return $ad_groups;
  }
}
