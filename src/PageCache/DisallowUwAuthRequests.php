<?php

/**
 * @file
 * Contains \Drupal\uwauth\PageCache\DisallowUwAuthRequests.
 */

namespace Drupal\uwauth\PageCache;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Symfony\Component\HttpFoundation\Request;


/**
 * Don't cache UW Auth requests
 */
class DisallowUwAuthRequests implements RequestPolicyInterface {

  /**
   * {@inheritdoc}
   */
  public function check(Request $request) {
    $username = $request->server->get('uwnetid');
    if (isset($username)) {
      return self::DENY;
    }
  }

}
