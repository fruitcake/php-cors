<?php

/*
 * This file is part of fruitcake/php-cors and was originally part of asm89/stack-cors
 *
 * (c) Alexander <iam.asm89@gmail.com>
 * (c) Barryvdh <barryvdh@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fruitcake\Cors\Tests;

use Fruitcake\Cors\CorsService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @phpstan-import-type CorsInputOptions from CorsService
 */
class MockApp
{
    /** @var string[] */
    private $responseHeaders;

    /**
     * @var CorsService
     */
    private $cors;

    /**
     * @param string[] $responseHeaders
     * @param CorsInputOptions $options
     */
    public function __construct(array $responseHeaders, array $options = [])
    {
        $this->responseHeaders = $responseHeaders;
        $this->cors = new CorsService($options);
    }

    public function handle(Request $request): Response
    {
        if ($this->cors->isPreflightRequest($request)) {
            $response = $this->cors->handlePreflightRequest($request);
            return $this->cors->varyHeader($response, 'Access-Control-Request-Method');
        }

        $response = new Response();

        $response->headers->add($this->responseHeaders);

        if ($request->getMethod() === 'OPTIONS') {
            $this->cors->varyHeader($response, 'Access-Control-Request-Method');
        }

        return $this->cors->addActualRequestHeaders($response, $request);
    }
}
