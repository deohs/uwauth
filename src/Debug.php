<?php

declare(strict_types = 1);

namespace Drupal\uwauth;

use Drupal\Core\Messenger\MessengerInterface;

/**
 * Class Debug provides configurable debug information.
 */
class Debug {

  /**
   * The messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * Debug flag.
   *
   * @var bool
   */
  protected $verbose;

  /**
   * Debug constructor.
   *
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param bool $verbose
   *   Display debug information ?
   */
  public function __construct(MessengerInterface $messenger, $verbose = FALSE) {
    $this->messenger = $messenger;
    $this->verbose = $verbose;
  }

  /**
   * Display diagnostic information if enabled.
   *
   * @param string $message
   *   The message to display.
   * @param string $type
   *   The message severity level.
   */
  public function message($message, $type = MessengerInterface::TYPE_STATUS) {
    if (!$this->verbose) {
      return;
    }
    $stack = debug_backtrace(TRUE, 2);
    $caller = $stack[1];
    $class = empty($caller['class']) ? NULL : $caller['class'];
    $function = $caller['function'];
    if (!empty($class)) {
      $classArray = explode('\\', $class);
      $shortClassArray = [];
      $len = count($classArray);
      for ($i = 0; $i < $len - 1; $i++) {
        $shortClassArray[$i] = mb_substr($classArray[$i], 0, 1);
      }
      $shortClassArray[$len - 1] = $classArray[$len - 1];
      $shortClass = implode('\\', $shortClassArray);
    }
    else {
      $shortClass = '';
    }

    $message = ($shortClass ? "$shortClass::$function" : $function) . " $message";

    $this->messenger->addMessage($message, $type, FALSE);
  }

}
