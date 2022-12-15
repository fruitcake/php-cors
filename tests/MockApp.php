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
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

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
     * @var ResponseFactoryInterface
     */
    private $responseFactory;

    /**
     * @param string[] $responseHeaders
     * @param ResponseFactoryInterface $responseFactory
     * @param CorsInputOptions $options
     */
    public function __construct(array $responseHeaders, ResponseFactoryInterface $responseFactory, array $options = [])
    {
        $this->responseHeaders = $responseHeaders;
        $this->responseFactory = $responseFactory;
        $this->cors = new CorsService($responseFactory, $options);
    }

    public function handle(RequestInterface $request): ResponseInterface
    {
        if ($this->cors->isPreflightRequest($request)) {
            $response = $this->cors->handlePreflightRequest($request);
            return $this->cors->varyHeader($response, 'Access-Control-Request-Method');
        }

        $response = $this->responseFactory->createResponse();

        foreach ($this->responseHeaders as $name => $value) {
            $response = $response->withAddedHeader($name, $value);
        }

        if ($request->getMethod() === 'OPTIONS') {
            $response = $this->cors->varyHeader($response, 'Access-Control-Request-Method');
        }

        return $this->cors->addActualRequestHeaders($response, $request);
    }
}
