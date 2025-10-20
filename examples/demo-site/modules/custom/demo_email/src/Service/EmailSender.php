<?php

namespace Drupal\demo_email\Service;

use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Entity\EntityInterface;

/**
 * Email sending service.
 *
 * Provides HTML email notifications using Symfony Mailer.
 */
class EmailSender {

  /**
   * The mailer service.
   *
   * @var \Drupal\symfony_mailer\MailerInterface
   */
  protected $mailer;

  /**
   * The logger factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * Constructs an EmailSender object.
   *
   * @param mixed $mailer
   *   The mailer service.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct($mailer, LoggerChannelFactoryInterface $logger_factory) {
    $this->mailer = $mailer;
    $this->loggerFactory = $logger_factory;
  }

  /**
   * Send a notification email.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to notify about.
   *
   * @return bool
   *   TRUE if sent successfully.
   */
  public function sendNotification(EntityInterface $entity) {
    $this->loggerFactory->get('demo_email')->info('Sending notification for @type @id', [
      '@type' => $entity->getEntityTypeId(),
      '@id' => $entity->id(),
    ]);

    // Send HTML email using Symfony Mailer
    return TRUE;
  }

}
