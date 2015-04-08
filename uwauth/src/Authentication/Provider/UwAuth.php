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
    if ($this->sessionConfiguration->hasSession($request) && isset($username) && isset($shib_session_id)) {
      return FALSE;
    } elseif ($this->sessionConfiguration->hasSession($request) && !isset($username) && !isset($shib_session_id)) {
      return FALSE;
    } elseif (!$this->sessionConfiguration->hasSession($request) && isset($username) && isset($shib_session_id)) {
      return TRUE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $username = $request->server->get('REMOTE_USER');
    $account = reset($this->entityManager->getStorage('user')->loadByProperties(array('name' => $username)));
    if ($account) {
      // Immediately refresh after generating session. This will let Drupal's cookie provider take over auth.
      $this->sync_roles($account,$username);
      user_login_finalize($account);
      header("Refresh: 0");
    } else {
      // User entity doesn't exist, so create it, and immediately login
      $user = User::create(array(
        'name' => $username,
        'mail' => $username.'@uw.edu',
        'status' => 1
      ));
      $user->save();
      $account = reset($this->entityManager->getStorage('user')->loadByProperties(array('name' => $username)));
      $this->sync_roles($account,$username);
      user_login_finalize($account);
      header("Refresh: 0");
    }
    return [];
  }

  /**
   * Synchronize roles with UW Groups
   *
   * @param $account
   *   A user object.
   * @param $username
   *   An authenticated username.
   */
  private function sync_roles($account, $username) {
    // $account->addRole('test_editor');
    // $account->removeRole('test_editor');
    // $account->save();
    // user_roles(TRUE);

    $roles_existing = user_role_names(TRUE);
    $roles_assigned = $account->getRoles(TRUE);
    $uwgws_groups = $this->fetch_uwgroups($username);

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
   * @param $username
   *   An authenticated username.
   */
  private function fetch_uwgroups($username) {
    // UW CA cert base path
    $uwca_path = '/etc/ssl/';

    // UW GWS URL
    $uwgws_url = 'https://iam-ws.u.washington.edu/group_sws/v1/search?member=' . $username . '&type=effective&scope=all';

    // Query UW GWS for group membership
    $uwgws = curl_init();
    curl_setopt_array($uwgws, array(
                                CURLOPT_RETURNTRANSFER => TRUE,
                                CURLOPT_HEADER         => FALSE,
                                CURLOPT_BINARYTRANSFER => FALSE,
                                CURLOPT_FOLLOWLOCATION => TRUE,
                                CURLOPT_SSL_VERIFYHOST => TRUE,
                                CURLOPT_SSL_VERIFYPEER => TRUE,
                                CURLOPT_SSLCERT        => $uwca_path.'ehrt_uwca_cert.pem',
                                CURLOPT_SSLKEY         => $uwca_path.'ehrt_uwca_key.pem',
                                CURLOPT_CAINFO         => $uwca_path.'ehrt_uwca_ca.pem',
                                CURLOPT_VERBOSE        => FALSE,
                                CURLOPT_URL            => $uwgws_url,
                                ));
    $uwgws_response = curl_exec($uwgws);
    curl_close($uwgws);

    // Extract groups from XML feed
    $uwgws_feed = simplexml_load_string(str_replace('xmlns=', 'ns=', $uwgws_response));
    $uwgws_entries = $uwgws_feed->xpath("//a[@class='name']");
    $uwgws_groups = array();
    while (list( , $node) = each($uwgws_entries)) {
      $uwgws_groups[] = (string)$node[0];
    }

    return $uwgws_groups;
  }
}
