<?php

/**
 * @file
 * Contains \Drupal\uwauth\Authentication\Provider\UwAuth.
 */

namespace Drupal\uwauth\Authentication\Provider;

use Drupal\Component\Utility\String;
use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Authentication\AuthenticationProviderChallengeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\user\UserAuthInterface;
use Drupal\Core\Session\SessionConfigurationInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * Shibboleth and UW Groups authentication provider.
 */
class UwAuth implements AuthenticationProviderInterface, AuthenticationProviderChallengeInterface {

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The user auth service.
   *
   * @var \Drupal\user\UserAuthInterface
   */
  protected $userAuth;

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
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\user\UserAuthInterface $user_auth
   *   The user authentication service.
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   *   The entity manager service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, UserAuthInterface $user_auth, EntityManagerInterface $entity_manager, SessionConfigurationInterface $session_configuration) {
    $this->configFactory = $config_factory;
    $this->userAuth = $user_auth;
    $this->entityManager = $entity_manager;
    $this->sessionConfiguration = $session_configuration;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    $username = $request->headers->get('PHP_AUTH_USER');

    if ($this->sessionConfiguration->hasSession($request) && isset($username)) {
      return FALSE;
    } elseif (($this->sessionConfiguration->hasSession($request) !== TRUE) && isset($username)) {
      return TRUE;
    } elseif ($this->sessionConfiguration->hasSession($request) && (isset($username) !== TRUE)) {
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $username = $request->headers->get('PHP_AUTH_USER');
    $accounts = $this->entityManager->getStorage('user')->loadByProperties(array('name' => $username, 'status' => 1));
    $account = reset($accounts);
    if ($account) {
      // $uid = $account->id();
      // return $this->entityManager->getStorage('user')->load($uid);
      user_login_finalize($account);
      header("Refresh: 0");
    }
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function challengeException(Request $request, \Exception $previous) {
    return new UnauthorizedHttpException(401, 'No authentication credentials provided.', $previous);
  }

}
