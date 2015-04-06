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
      user_login_finalize($account);
      header("Refresh: 0");
    }
    return [];
  }

}
