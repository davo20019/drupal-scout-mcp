<?php

namespace Drupal\demo_api\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * REST API controller for products.
 *
 * Provides JSON endpoints for external integrations.
 */
class ApiController extends ControllerBase {

  /**
   * Returns list of products.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with products.
   */
  public function getProducts() {
    $products = [
      ['id' => 1, 'name' => 'Product 1', 'price' => 29.99],
      ['id' => 2, 'name' => 'Product 2', 'price' => 49.99],
    ];

    return new JsonResponse($products);
  }

  /**
   * Returns a single product.
   *
   * @param int $id
   *   Product ID.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   JSON response with product.
   */
  public function getProduct($id) {
    $product = ['id' => $id, 'name' => "Product $id", 'price' => 29.99];
    return new JsonResponse($product);
  }

}
